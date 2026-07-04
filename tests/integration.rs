use std::ffi::OsStr;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use stackpulse::{
    is_python_module, AttachMode, FrameKind, PerfRecorder, PerfRecorderOptions, PerfSpoolReader,
    PerfSummary, PerfSymbolizer, ResolvedFrame, SymbolOrigin,
};

const ACCEPT_TIMEOUT: Duration = Duration::from_secs(10);
const READY_TIMEOUT: Duration = Duration::from_secs(10);
const RECORD_TIMEOUT: Duration = Duration::from_secs(5);

static NEXT_TEST_ID: AtomicU64 = AtomicU64::new(0);

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

#[test]
fn records_c_ladder_stack() -> TestResult {
    run_native_stack_case(NativeStackCase {
        name: "c-ladder",
        program: TargetProgram::C {
            source: "c_ladder.c",
            output: "stackpulse-c-ladder",
        },
        include_kernel: false,
        target_samples: 5,
        assertion: StackAssertion::OrderedNames {
            names: &[
                "stackpulse_c_leaf",
                "stackpulse_c_middle",
                "stackpulse_c_entry",
            ],
        },
    })
}

#[test]
fn records_rust_ladder_stack() -> TestResult {
    run_native_stack_case(NativeStackCase {
        name: "rust-ladder",
        program: TargetProgram::Rust {
            source: "rust_ladder.rs",
            output: "stackpulse-rust-ladder",
        },
        include_kernel: false,
        target_samples: 5,
        assertion: StackAssertion::OrderedNames {
            names: &[
                "stackpulse_rust_leaf",
                "stackpulse_rust_middle",
                "stackpulse_rust_entry",
            ],
        },
    })
}

#[test]
fn records_c_recursive_stack() -> TestResult {
    run_native_stack_case(NativeStackCase {
        name: "c-recursion",
        program: TargetProgram::C {
            source: "c_recursion.c",
            output: "stackpulse-c-recursion",
        },
        include_kernel: false,
        target_samples: 5,
        assertion: StackAssertion::RepeatedName {
            name: "stackpulse_c_recursive",
            min_count: 4,
        },
    })
}

#[test]
fn resolves_c_shared_library_stack() -> TestResult {
    run_native_stack_case(NativeStackCase {
        name: "c-shared-library",
        program: TargetProgram::SharedC,
        include_kernel: false,
        target_samples: 5,
        assertion: StackAssertion::SharedLibrary {
            names: &[
                "stackpulse_shared_leaf",
                "stackpulse_shared_middle",
                "stackpulse_shared_entry",
            ],
            module_basename: "libstackpulse_shared_worker.so",
        },
    })
}

#[test]
fn records_kernel_frames_when_enabled() -> TestResult {
    run_native_stack_case(NativeStackCase {
        name: "kernel-frames",
        program: TargetProgram::C {
            source: "c_kernel_syscall.c",
            output: "stackpulse-c-kernel-syscall",
        },
        include_kernel: true,
        target_samples: 10,
        assertion: StackAssertion::KernelFrames,
    })
}

#[test]
fn records_samples_from_real_python_process() -> TestResult {
    let python = match python_for_tests() {
        Some(python) => python,
        None => return skip_or_fail("python3 was not found"),
    };

    let script = PythonScript::new("busy", busy_python_script())?;
    let ReadyPython { _child, process } = spawn_ready_python(&python, script.path(), &[])?;
    let target_pid = process.pid;

    let Some(capture) = record_profile(target_pid as u32, "python-samples", false, 3)? else {
        return Ok(());
    };

    capture.assert_min_samples(1);
    assert!(
        capture
            .reader
            .samples()
            .iter()
            .any(|sample| sample.process_id == target_pid),
        "profile should contain samples for pid {target_pid}; {}",
        capture.diagnostics()
    );
    assert_has_python_module(&capture.reader);
    assert_has_any_named_frame(&capture);
    Ok(())
}

#[test]
fn follows_python_child_processes_when_enabled() -> TestResult {
    let python = match python_for_tests() {
        Some(python) => python,
        None => return skip_or_fail("python3 was not found"),
    };

    let (listener, port) = listener()?;
    let parent_script = child_spawning_python_script(port);
    let parent = python_command(&python)
        .arg("-c")
        .arg(parent_script)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let _parent = ChildGuard::new(parent);
    let mut stream = accept(&listener)?;

    let ready = read_until(&mut stream, b"parent:", READY_TIMEOUT)?;
    let parent_pid = parse_pid_line(&ready, "parent:")?;
    let profile_path = ProfilePath::new("python-children");

    let Some(recorder) = attach_recorder(parent_pid as u32, profile_path.as_ref(), true)? else {
        return Ok(());
    };

    stream.write_all(b"go\n")?;
    let child_ready = read_until(&mut stream, b"child:", READY_TIMEOUT)?;
    let spawned_child_pid = parse_pid_line(&child_ready, "child:")?;
    let _spawned_child = PidGuard::new(spawned_child_pid);

    let capture = finish_recording(profile_path, recorder, 5)?;

    assert!(
        capture
            .reader
            .samples()
            .iter()
            .any(|sample| sample.process_id == spawned_child_pid),
        "expected inherited child pid {spawned_child_pid} in samples; seen pids: {:?}; {}",
        sample_pids(&capture.reader),
        capture.diagnostics()
    );
    Ok(())
}

#[test]
fn resolves_python_perf_map_frames_when_runtime_provides_them() -> TestResult {
    run_python_stack_case(PythonStackCase {
        name: "python-perf-map",
        script_name: "busy",
        script: busy_python_script(),
        expected_perf_map_functions: &[
            "stackpulse_busy_leaf",
            "stackpulse_busy_middle",
            "stackpulse_busy_entry",
        ],
        target_samples: 5,
        assertion: StackAssertion::PythonOrderedNames {
            names: &[
                "stackpulse_busy_leaf",
                "stackpulse_busy_middle",
                "stackpulse_busy_entry",
            ],
        },
    })
}

struct NativeStackCase {
    name: &'static str,
    program: TargetProgram,
    include_kernel: bool,
    target_samples: u64,
    assertion: StackAssertion,
}

struct PythonStackCase {
    name: &'static str,
    script_name: &'static str,
    script: &'static str,
    expected_perf_map_functions: &'static [&'static str],
    target_samples: u64,
    assertion: StackAssertion,
}

enum TargetProgram {
    C {
        source: &'static str,
        output: &'static str,
    },
    Rust {
        source: &'static str,
        output: &'static str,
    },
    SharedC,
}

enum StackAssertion {
    OrderedNames {
        names: &'static [&'static str],
    },
    RepeatedName {
        name: &'static str,
        min_count: usize,
    },
    SharedLibrary {
        names: &'static [&'static str],
        module_basename: &'static str,
    },
    KernelFrames,
    PythonOrderedNames {
        names: &'static [&'static str],
    },
}

fn run_native_stack_case(case: NativeStackCase) -> TestResult {
    let binary = match case.program.compile() {
        Ok(binary) => binary,
        Err(BuildError::Skip(message)) => return skip_or_fail(&message),
        Err(BuildError::Failed(message)) => return Err(message.into()),
    };
    let target = spawn_ready_binary(&binary)?;
    let Some(capture) = record_profile_with_options(
        target.pid as u32,
        case.name,
        false,
        case.include_kernel,
        case.target_samples,
    )?
    else {
        return Ok(());
    };

    capture.assert_min_samples(case.target_samples);
    case.assertion.assert(&capture, target.pid);
    Ok(())
}

fn run_python_stack_case(case: PythonStackCase) -> TestResult {
    let python = match python_for_tests() {
        Some(python) => python,
        None => return skip_or_fail("python3 was not found"),
    };

    let script = PythonScript::new(case.script_name, case.script)?;
    let ReadyPython { _child, process } = spawn_ready_python(&python, script.path(), &[])?;
    let target_pid = process.pid;
    let perf_map_path = PathBuf::from(format!("/tmp/perf-{target_pid}.map"));

    if wait_for_file(&perf_map_path, Duration::from_secs(2)).is_none() {
        if require_python_perf() {
            return Err(format!(
                "Python perf support did not create {}; run with -X perf or PYTHONPERFSUPPORT=1 on a Python runtime that supports perf maps",
                perf_map_path.display()
            )
            .into());
        }
        eprintln!(
            "skipping perf-map assertion: Python runtime did not create {}",
            perf_map_path.display()
        );
        return Ok(());
    }
    assert_perf_map_has_python_symbols(
        &perf_map_path,
        script.path(),
        case.expected_perf_map_functions,
    )?;

    let Some(capture) = record_profile(target_pid as u32, case.name, false, case.target_samples)?
    else {
        return Ok(());
    };

    case.assertion.assert(&capture, target_pid);
    remove_file_if_exists(&perf_map_path);
    Ok(())
}

impl TargetProgram {
    fn compile(&self) -> Result<PathBuf, BuildError> {
        match self {
            Self::C { source, output } => compile_c_binary(source, output),
            Self::Rust { source, output } => compile_rust_binary(source, output),
            Self::SharedC => compile_shared_c_binary(),
        }
    }
}

impl StackAssertion {
    fn assert(&self, capture: &CapturedProfile, pid: i32) {
        match self {
            Self::OrderedNames { names } => {
                assert_stack_contains_ordered_names(capture, pid, names);
            }
            Self::RepeatedName { name, min_count } => {
                assert_stack_contains_repeated_name(capture, pid, name, *min_count);
            }
            Self::SharedLibrary {
                names,
                module_basename,
            } => {
                assert_stack_contains_ordered_names(capture, pid, names);
                assert!(
                    capture.stacks_for_pid(pid).any(|stack| {
                        stack.frames.iter().any(|frame| {
                            frame.name == names[0]
                                && frame.module_basename() == Some(*module_basename)
                        })
                    }),
                    "expected {} to resolve from module {module_basename}; {}",
                    names[0],
                    capture.diagnostics()
                );
            }
            Self::KernelFrames => {
                assert_kernel_capture_enabled(capture);
                assert_has_kernel_frame(capture);
            }
            Self::PythonOrderedNames { names } => {
                assert_python_stack_contains_leaf(capture, pid, names[0]);
                assert_python_stack_contains_ordered_names(capture, pid, names);
            }
        }
    }
}

struct CapturedProfile {
    path: ProfilePath,
    summary: PerfSummary,
    reader: PerfSpoolReader,
    stacks: Vec<ResolvedSampleStack>,
}

impl CapturedProfile {
    fn assert_min_samples(&self, samples: u64) {
        assert!(
            self.summary.samples >= samples,
            "expected at least {samples} samples; {}",
            self.diagnostics()
        );
    }

    fn stacks_for_pid(&self, pid: i32) -> impl Iterator<Item = &ResolvedSampleStack> {
        self.stacks
            .iter()
            .filter(move |stack| stack.process_id == pid)
    }

    fn diagnostics(&self) -> String {
        let mut text = format!(
            "profile: {}\nsummary: {:#?}\nmodules: {:#?}\nresolved stacks:",
            self.path.as_ref().display(),
            self.summary,
            self.reader.modules()
        );
        for stack in self.stacks.iter().take(16) {
            text.push_str(&format!("\n  pid {}:", stack.process_id));
            for frame in &stack.frames {
                text.push_str(&format!(
                    "\n    {:?} {:?} {} [{}] {:?}",
                    frame.kind,
                    frame.origin,
                    frame.name,
                    frame.module.as_deref().unwrap_or("<no module>"),
                    frame.file
                ));
            }
        }
        text
    }
}

#[derive(Debug)]
struct ResolvedSampleStack {
    process_id: i32,
    frames: Vec<ResolvedTestFrame>,
}

#[derive(Debug)]
struct ResolvedTestFrame {
    name: String,
    kind: FrameKind,
    origin: SymbolOrigin,
    module: Option<String>,
    file: Option<String>,
}

impl ResolvedTestFrame {
    fn module_basename(&self) -> Option<&str> {
        self.module.as_deref().map(|module| {
            Path::new(module)
                .file_name()
                .and_then(OsStr::to_str)
                .unwrap_or(module)
        })
    }
}

fn assert_stack_contains_ordered_names(capture: &CapturedProfile, pid: i32, expected: &[&str]) {
    assert!(
        capture.stacks_for_pid(pid).any(|stack| {
            let names = stack.frame_names();
            contains_ordered_or_reverse_subsequence(&names, expected)
        }),
        "expected one stack for pid {pid} to contain {expected:?}; {}",
        capture.diagnostics()
    );
}

fn assert_stack_contains_repeated_name(
    capture: &CapturedProfile,
    pid: i32,
    expected: &str,
    min_count: usize,
) {
    let max_count = capture
        .stacks_for_pid(pid)
        .map(|stack| {
            stack
                .frames
                .iter()
                .filter(|frame| frame.name == expected)
                .count()
        })
        .max()
        .unwrap_or(0);
    assert!(
        max_count >= min_count,
        "expected one stack for pid {pid} to contain {expected:?} at least {min_count} times, max was {max_count}; {}",
        capture.diagnostics()
    );
}

fn assert_kernel_capture_enabled(capture: &CapturedProfile) {
    assert!(
        capture.summary.kernel_enabled,
        "kernel frame capture was not enabled; {}",
        capture.diagnostics()
    );
}

fn assert_has_kernel_frame(capture: &CapturedProfile) {
    assert!(
        capture
            .stacks
            .iter()
            .flat_map(|stack| &stack.frames)
            .any(|frame| frame.kind == FrameKind::Kernel),
        "expected at least one resolved kernel frame; {}",
        capture.diagnostics()
    );
}

fn assert_python_stack_contains_leaf(capture: &CapturedProfile, pid: i32, expected: &str) {
    assert!(
        capture.stacks_for_pid(pid).any(|stack| {
            stack
                .frames
                .iter()
                .any(|frame| frame.kind == FrameKind::Python && frame.name == expected)
        }),
        "expected a Python frame named {expected}; {}",
        capture.diagnostics()
    );
}

fn assert_python_stack_contains_ordered_names(
    capture: &CapturedProfile,
    pid: i32,
    expected: &[&str],
) {
    let python_stacks: Vec<Vec<&str>> = capture
        .stacks_for_pid(pid)
        .map(|stack| {
            stack
                .frames
                .iter()
                .filter(|frame| frame.kind == FrameKind::Python)
                .map(|frame| frame.name.as_str())
                .collect()
        })
        .filter(|stack: &Vec<&str>| !stack.is_empty())
        .collect();

    if python_stacks
        .iter()
        .any(|stack| stack.len() >= expected.len())
    {
        assert!(
            python_stacks
                .iter()
                .any(|stack| contains_ordered_or_reverse_subsequence(stack, expected)),
            "expected one Python stack to contain {expected:?}; {}",
            capture.diagnostics()
        );
    }
}

impl ResolvedSampleStack {
    fn frame_names(&self) -> Vec<&str> {
        self.frames
            .iter()
            .map(|frame| frame.name.as_str())
            .collect()
    }
}

fn contains_ordered_or_reverse_subsequence(stack: &[&str], expected: &[&str]) -> bool {
    if contains_ordered_subsequence(stack, expected) {
        return true;
    }
    let reversed = expected.iter().rev().copied().collect::<Vec<_>>();
    contains_ordered_subsequence(stack, &reversed)
}

fn contains_ordered_subsequence(stack: &[&str], expected: &[&str]) -> bool {
    let mut cursor = 0;
    for frame in stack {
        if cursor < expected.len() && *frame == expected[cursor] {
            cursor += 1;
        }
    }
    cursor == expected.len()
}

fn record_profile(
    pid: u32,
    name: &str,
    inherit_child_processes: bool,
    target_samples: u64,
) -> io::Result<Option<CapturedProfile>> {
    record_profile_with_options(pid, name, inherit_child_processes, false, target_samples)
}

fn record_profile_with_options(
    pid: u32,
    name: &str,
    inherit_child_processes: bool,
    include_kernel: bool,
    target_samples: u64,
) -> io::Result<Option<CapturedProfile>> {
    let profile_path = ProfilePath::new(name);
    let Some(recorder) = attach_recorder_with_options(
        pid,
        profile_path.as_ref(),
        inherit_child_processes,
        include_kernel,
    )?
    else {
        return Ok(None);
    };
    finish_recording(profile_path, recorder, target_samples).map(Some)
}

fn finish_recording(
    profile_path: ProfilePath,
    mut recorder: PerfRecorder,
    target_samples: u64,
) -> io::Result<CapturedProfile> {
    let deadline = Instant::now() + RECORD_TIMEOUT;
    while Instant::now() < deadline && recorder.summary().samples < target_samples {
        recorder.wait()?;
        recorder.consume_available()?;
    }
    let summary = recorder.finish()?;
    let reader = PerfSpoolReader::open(profile_path.as_ref())?;
    let stacks = resolve_stacks(&reader)?;
    Ok(CapturedProfile {
        path: profile_path,
        summary,
        reader,
        stacks,
    })
}

fn resolve_stacks(reader: &PerfSpoolReader) -> io::Result<Vec<ResolvedSampleStack>> {
    let mut symbolizer = PerfSymbolizer::for_spool(reader);
    let mut stacks = Vec::new();
    for sample in reader.samples() {
        let raw_frames = reader.stack_frame_refs(sample.stack_id)?;
        let mut frames = Vec::new();
        symbolizer.for_each_resolved_frame(
            sample.process_id,
            sample.stack_id,
            raw_frames,
            |frame| {
                frames.push(resolve_test_frame(frame));
            },
        );
        stacks.push(ResolvedSampleStack {
            process_id: sample.process_id,
            frames,
        });
    }
    Ok(stacks)
}

fn resolve_test_frame(frame: &ResolvedFrame) -> ResolvedTestFrame {
    match frame {
        ResolvedFrame::Python(frame) => ResolvedTestFrame {
            name: frame.func_name.to_string(),
            kind: FrameKind::Python,
            origin: SymbolOrigin::PerfMap,
            module: None,
            file: Some(frame.file_name.to_string()),
        },
        ResolvedFrame::Native(frame) => ResolvedTestFrame {
            name: frame.func_name(),
            kind: frame.kind,
            origin: frame.origin,
            module: frame
                .symbol
                .as_ref()
                .map(|symbol| symbol.module.to_string()),
            file: frame
                .symbol
                .as_ref()
                .and_then(|symbol| symbol.file.as_ref().map(ToString::to_string)),
        },
    }
}

fn attach_recorder(
    pid: u32,
    profile_path: &Path,
    inherit_child_processes: bool,
) -> io::Result<Option<PerfRecorder>> {
    attach_recorder_with_options(pid, profile_path, inherit_child_processes, false)
}

fn attach_recorder_with_options(
    pid: u32,
    profile_path: &Path,
    inherit_child_processes: bool,
    include_kernel: bool,
) -> io::Result<Option<PerfRecorder>> {
    match PerfRecorder::attach(
        pid,
        profile_path,
        AttachMode::StopAttachEnableResume,
        PerfRecorderOptions {
            frequency: 499,
            stack_size: 60 * 1024,
            include_kernel,
            inherit_child_processes,
            ..PerfRecorderOptions::default()
        },
    ) {
        Ok(recorder) => Ok(Some(recorder)),
        Err(err) if attach_is_not_allowed(&err) => {
            if environment_skips_allowed() {
                eprintln!("skipping integration test: profiling is not allowed here: {err}");
                Ok(None)
            } else {
                Err(io::Error::new(
                    err.kind(),
                    format!("profiling is not available in CI: {err}"),
                ))
            }
        }
        Err(err) => Err(err),
    }
}

fn compile_c_binary(source: &str, output: &str) -> Result<PathBuf, BuildError> {
    let compiler = c_compiler()
        .ok_or_else(|| BuildError::Skip("no C compiler was found for integration tests".into()))?;
    let dir = unique_build_dir(output)?;
    let binary = dir.join(output);
    let mut command = Command::new(compiler);
    command
        .args(common_c_flags())
        .arg("-I")
        .arg(targets_dir())
        .arg(targets_dir().join(source))
        .arg("-o")
        .arg(&binary);
    run_build_command(command, &format!("compile {source}"))?;
    Ok(binary)
}

fn compile_shared_c_binary() -> Result<PathBuf, BuildError> {
    let compiler = c_compiler()
        .ok_or_else(|| BuildError::Skip("no C compiler was found for integration tests".into()))?;
    let dir = unique_build_dir("stackpulse-c-shared")?;
    let library = dir.join("libstackpulse_shared_worker.so");
    let binary = dir.join("stackpulse-c-shared");

    let mut compile_library = Command::new(&compiler);
    compile_library
        .args(common_c_flags())
        .arg("-shared")
        .arg("-fPIC")
        .arg(targets_dir().join("c_shared_worker.c"))
        .arg("-o")
        .arg(&library);
    run_build_command(compile_library, "compile shared C worker")?;

    let mut compile_binary = Command::new(compiler);
    compile_binary
        .args(common_c_flags())
        .arg("-I")
        .arg(targets_dir())
        .arg(targets_dir().join("c_shared_main.c"))
        .arg("-L")
        .arg(&dir)
        .arg("-lstackpulse_shared_worker")
        .arg(format!("-Wl,-rpath,{}", dir.display()))
        .arg("-o")
        .arg(&binary);
    run_build_command(compile_binary, "compile shared C main")?;

    Ok(binary)
}

fn compile_rust_binary(source: &str, output: &str) -> Result<PathBuf, BuildError> {
    let rustc = rustc()
        .ok_or_else(|| BuildError::Skip("rustc was not found for integration tests".into()))?;
    let dir = unique_build_dir(output)?;
    let binary = dir.join(output);
    let mut command = Command::new(rustc);
    command
        .arg("--edition=2021")
        .arg("-g")
        .arg("-C")
        .arg("debuginfo=2")
        .arg("-C")
        .arg("force-frame-pointers=yes")
        .arg("-C")
        .arg("opt-level=0")
        .arg(targets_dir().join(source))
        .arg("-o")
        .arg(&binary);
    run_build_command(command, &format!("compile {source}"))?;
    Ok(binary)
}

fn common_c_flags() -> [&'static str; 4] {
    [
        "-g",
        "-O0",
        "-fno-omit-frame-pointer",
        "-fno-optimize-sibling-calls",
    ]
}

fn run_build_command(mut command: Command, description: &str) -> Result<(), BuildError> {
    let output = command.output().map_err(|err| {
        BuildError::Failed(format!(
            "failed to run {description}: {err}; command: {command:?}"
        ))
    })?;
    if output.status.success() {
        return Ok(());
    }

    Err(BuildError::Failed(format!(
        "{description} failed with status {}\ncommand: {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        command,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )))
}

fn c_compiler() -> Option<PathBuf> {
    if let Some(cc) = std::env::var_os("CC") {
        let path = PathBuf::from(cc);
        if command_is_available(&path) {
            return Some(path);
        }
    }
    ["cc", "clang", "gcc"]
        .into_iter()
        .map(PathBuf::from)
        .find(|path| command_is_available(path))
}

fn rustc() -> Option<PathBuf> {
    if let Some(rustc) = std::env::var_os("RUSTC") {
        let path = PathBuf::from(rustc);
        if command_is_available(&path) {
            return Some(path);
        }
    }
    let path = PathBuf::from("rustc");
    command_is_available(&path).then_some(path)
}

fn command_is_available(command: &Path) -> bool {
    Command::new(command)
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

fn targets_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("targets")
}

fn unique_build_dir(name: &str) -> Result<PathBuf, BuildError> {
    let id = NEXT_TEST_ID.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "stackpulse-integration-build-{name}-{}-{id}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir)
        .map_err(|err| BuildError::Failed(format!("failed to create {}: {err}", dir.display())))?;
    Ok(dir)
}

#[derive(Debug)]
enum BuildError {
    Skip(String),
    Failed(String),
}

impl From<io::Error> for BuildError {
    fn from(err: io::Error) -> Self {
        Self::Failed(err.to_string())
    }
}

#[derive(Debug)]
struct ReadyTarget {
    _child: ChildGuard,
    pid: i32,
}

fn spawn_ready_binary(binary: &Path) -> io::Result<ReadyTarget> {
    let (listener, port) = listener()?;
    let mut child = Command::new(binary)
        .arg(port.to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()?;
    match accept(&listener).and_then(|mut stream| {
        let ready = read_until(&mut stream, b"ready:", READY_TIMEOUT)?;
        parse_pid_line(&ready, "ready:")
    }) {
        Ok(pid) => Ok(ReadyTarget {
            _child: ChildGuard::new(child),
            pid,
        }),
        Err(err) => {
            cleanup_child(&mut child);
            Err(err)
        }
    }
}

#[derive(Debug)]
struct ProfilePath(PathBuf);

impl ProfilePath {
    fn new(name: &str) -> Self {
        let id = NEXT_TEST_ID.fetch_add(1, Ordering::Relaxed);
        Self(std::env::temp_dir().join(format!(
            "stackpulse-{name}-{}-{id}.spool",
            std::process::id()
        )))
    }
}

impl AsRef<Path> for ProfilePath {
    fn as_ref(&self) -> &Path {
        &self.0
    }
}

impl Drop for ProfilePath {
    fn drop(&mut self) {
        remove_file_if_exists(&self.0);
    }
}

fn python_for_tests() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("STACKPULSE_TEST_PYTHON") {
        return Some(PathBuf::from(path));
    }
    Command::new("python3")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .ok()
        .filter(|status| status.success())
        .map(|_| PathBuf::from("python3"))
}

fn python_command(python: &Path) -> Command {
    let mut command = Command::new(python);
    command
        .arg("-X")
        .arg("perf")
        .env("PYTHONPERFSUPPORT", "1")
        .env("PYTHONUNBUFFERED", "1");
    command
}

#[derive(Debug)]
struct ReadyPython {
    _child: ChildGuard,
    process: ReadyProcess,
}

#[derive(Debug)]
struct ReadyProcess {
    pid: i32,
}

fn spawn_ready_python(python: &Path, script: &Path, args: &[&str]) -> io::Result<ReadyPython> {
    let (listener, port) = listener()?;
    let mut child = python_command(python)
        .arg(script)
        .arg(port.to_string())
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    match accept(&listener).and_then(|mut stream| {
        let ready = read_until(&mut stream, b"ready:", READY_TIMEOUT)?;
        parse_pid_line(&ready, "ready:")
    }) {
        Ok(pid) => Ok(ReadyPython {
            _child: ChildGuard::new(child),
            process: ReadyProcess { pid },
        }),
        Err(err) => {
            cleanup_child(&mut child);
            Err(err)
        }
    }
}

fn busy_python_script() -> &'static str {
    r#"
import os
import socket
import sys

sock = socket.create_connection(("127.0.0.1", int(sys.argv[1])))
sock.sendall(f"ready:{os.getpid()}\n".encode())

def stackpulse_busy_leaf():
    value = 0
    while True:
        value = (value * 33 + 17) % 1000003

def stackpulse_busy_middle():
    stackpulse_busy_leaf()

def stackpulse_busy_entry():
    stackpulse_busy_middle()

stackpulse_busy_entry()
"#
}

fn child_spawning_python_script(port: u16) -> String {
    format!(
        r#"
import os
import socket
import subprocess
import sys
import time

sock = socket.create_connection(("127.0.0.1", {port}))
sock.sendall(f"parent:{{os.getpid()}}\n".encode())
sock.recv(16)

child_code = """
def stackpulse_child_leaf():
    value = 0
    while True:
        value = (value + 31) % 1000003
stackpulse_child_leaf()
"""

child = subprocess.Popen(
    [sys.executable, "-X", "perf", "-c", child_code],
    env={{**os.environ, "PYTHONPERFSUPPORT": "1", "PYTHONUNBUFFERED": "1"}},
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
)
sock.sendall(f"child:{{child.pid}}\n".encode())
time.sleep(10_000)
"#
    )
}

fn listener() -> io::Result<(TcpListener, u16)> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    Ok((listener, port))
}

fn accept(listener: &TcpListener) -> io::Result<TcpStream> {
    listener.set_nonblocking(true)?;
    let deadline = Instant::now() + ACCEPT_TIMEOUT;
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                stream.set_read_timeout(Some(READY_TIMEOUT))?;
                return Ok(stream);
            }
            Err(err) if err.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "timed out waiting for test process",
                ));
            }
            Err(err) => return Err(err),
        }
    }
}

fn read_until(stream: &mut TcpStream, needle: &[u8], timeout: Duration) -> io::Result<Vec<u8>> {
    stream.set_read_timeout(Some(Duration::from_millis(100)))?;
    let deadline = Instant::now() + timeout;
    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 256];
    loop {
        if buffer.windows(needle.len()).any(|window| window == needle) && buffer.contains(&b'\n') {
            return Ok(buffer);
        }
        match stream.read(&mut chunk) {
            Ok(0) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    format!("connection closed before {needle:?}; got {buffer:?}"),
                ));
            }
            Ok(n) => buffer.extend_from_slice(&chunk[..n]),
            Err(err)
                if matches!(
                    err.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) && Instant::now() < deadline =>
            {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(err)
                if matches!(
                    err.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("timed out waiting for {needle:?}; got {buffer:?}"),
                ));
            }
            Err(err) => return Err(err),
        }
    }
}

fn parse_pid_line(buffer: &[u8], prefix: &str) -> io::Result<i32> {
    let text = String::from_utf8_lossy(buffer);
    text.lines()
        .find_map(|line| line.strip_prefix(prefix))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, format!("missing {prefix:?}")))?
        .trim()
        .parse::<i32>()
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))
}

fn attach_is_not_allowed(err: &io::Error) -> bool {
    if matches!(
        err.kind(),
        io::ErrorKind::PermissionDenied | io::ErrorKind::Unsupported
    ) {
        return true;
    }
    matches!(err.raw_os_error(), Some(libc::EPERM | libc::EACCES))
        || err.to_string().to_ascii_lowercase().contains("permission")
}

fn environment_skips_allowed() -> bool {
    std::env::var_os("CI").is_none() || std::env::var_os("STACKPULSE_ALLOW_PERF_SKIP").is_some()
}

fn require_python_perf() -> bool {
    matches!(
        std::env::var("STACKPULSE_REQUIRE_PYTHON_PERF").as_deref(),
        Ok("1" | "true" | "yes")
    )
}

fn skip_or_fail(message: &str) -> TestResult {
    if environment_skips_allowed() {
        eprintln!("skipping integration test: {message}");
        Ok(())
    } else {
        Err(message.to_owned().into())
    }
}

fn sample_pids(reader: &PerfSpoolReader) -> Vec<i32> {
    let mut pids: Vec<_> = reader
        .samples()
        .iter()
        .map(|sample| sample.process_id)
        .collect();
    pids.sort_unstable();
    pids.dedup();
    pids
}

fn assert_has_python_module(reader: &PerfSpoolReader) {
    assert!(
        reader.modules().iter().any(|module| {
            Path::new(&module.path)
                .file_name()
                .and_then(OsStr::to_str)
                .is_some_and(is_python_module)
        }),
        "expected at least one Python module, modules: {:?}",
        reader.modules()
    );
}

fn assert_has_any_named_frame(capture: &CapturedProfile) {
    assert!(
        capture
            .stacks
            .iter()
            .flat_map(|stack| &stack.frames)
            .any(|frame| !frame.name.starts_with("<0x")),
        "expected at least one resolved frame; {}",
        capture.diagnostics()
    );
}

fn assert_perf_map_has_python_symbols(
    path: &Path,
    script: &Path,
    funcs: &[&str],
) -> io::Result<()> {
    // Python appends a trampoline entry when a function first executes, so
    // the map exists before the expected functions are in it; poll instead
    // of racing interpreter startup.
    let script = script.to_string_lossy();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let text = std::fs::read_to_string(path)?;
        let missing = funcs.iter().find(|func| {
            let expected = format!("py::{func}:{script}");
            !text.lines().any(|line| line.ends_with(&expected))
        });
        let Some(func) = missing else {
            return Ok(());
        };
        assert!(
            Instant::now() < deadline,
            "expected perf map {} to contain \"py::{func}:{script}\"; map contents:\n{text}",
            path.display()
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn wait_for_file(path: &Path, timeout: Duration) -> Option<()> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if path.exists() {
            return Some(());
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    None
}

fn cleanup_child(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

#[derive(Debug)]
struct ChildGuard {
    child: Child,
}

impl ChildGuard {
    fn new(child: Child) -> Self {
        Self { child }
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        cleanup_child(&mut self.child);
    }
}

struct PidGuard {
    pid: i32,
}

impl PidGuard {
    fn new(pid: i32) -> Self {
        Self { pid }
    }
}

impl Drop for PidGuard {
    fn drop(&mut self) {
        unsafe {
            libc::kill(self.pid, libc::SIGKILL);
        }
        for _ in 0..50 {
            let gone = unsafe { libc::kill(self.pid, 0) } != 0;
            if gone {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

fn remove_file_if_exists(path: &Path) {
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) => eprintln!("failed to remove {}: {err}", path.display()),
    }
}

struct PythonScript {
    path: PathBuf,
}

impl PythonScript {
    fn new(name: &str, contents: &str) -> io::Result<Self> {
        let id = NEXT_TEST_ID.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("stackpulse-{name}-{}-{id}.py", std::process::id()));
        std::fs::write(&path, contents)?;
        Ok(Self { path })
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for PythonScript {
    fn drop(&mut self) {
        remove_file_if_exists(&self.path);
    }
}
