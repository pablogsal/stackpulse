use std::ffi::OsStr;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use stackpulse::{
    is_python_module, AttachMode, PerfRecorder, PerfRecorderOptions, PerfSpoolReader,
    PerfSymbolizer, ResolvedFrame,
};

const ACCEPT_TIMEOUT: Duration = Duration::from_secs(10);
const READY_TIMEOUT: Duration = Duration::from_secs(10);
const RECORD_TIMEOUT: Duration = Duration::from_secs(5);

static NEXT_PROFILE_ID: AtomicU64 = AtomicU64::new(0);

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn records_samples_from_real_python_process() -> TestResult {
    let python = match python_for_tests() {
        Some(python) => python,
        None => return skip_or_fail("python3 was not found"),
    };

    let script = PythonScript::new("busy", busy_python_script())?;
    let ReadyPython { _child, mut stream } = spawn_ready_python(&python, script.path(), &[])?;
    let ready = read_until(&mut stream, b"ready:", READY_TIMEOUT)?;
    let target_pid = parse_pid_line(&ready, "ready:")?;
    let profile_path = profile_path("python-samples");

    let Some(summary) = record_until_samples(target_pid as u32, &profile_path, false, 3)? else {
        return Ok(());
    };

    assert!(
        summary.samples > 0,
        "expected samples to be written, summary: {summary:#?}"
    );

    let reader = PerfSpoolReader::open(&profile_path)?;
    assert!(
        reader
            .samples()
            .iter()
            .any(|sample| sample.process_id == target_pid),
        "profile should contain samples for pid {target_pid}, samples: {:?}",
        reader.samples()
    );
    assert_has_python_module(&reader);
    assert_has_resolved_frame(&reader)?;
    remove_file_if_exists(&profile_path);
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
    let profile_path = profile_path("python-children");

    let mut recorder = match attach_recorder(parent_pid as u32, &profile_path, true)? {
        Some(recorder) => recorder,
        None => return Ok(()),
    };

    stream.write_all(b"go\n")?;
    let child_ready = read_until(&mut stream, b"child:", READY_TIMEOUT)?;
    let spawned_child_pid = parse_pid_line(&child_ready, "child:")?;
    let _spawned_child = PidGuard::new(spawned_child_pid);

    let deadline = Instant::now() + RECORD_TIMEOUT;
    while Instant::now() < deadline && recorder.summary().samples < 5 {
        recorder.wait()?;
        recorder.consume_available()?;
    }

    let summary = recorder.finish()?;

    let reader = PerfSpoolReader::open(&profile_path)?;
    assert!(
        reader
            .samples()
            .iter()
            .any(|sample| sample.process_id == spawned_child_pid),
        "expected inherited child pid {spawned_child_pid} in samples; summary: {summary:#?}; seen pids: {:?}",
        sample_pids(&reader)
    );
    remove_file_if_exists(&profile_path);
    Ok(())
}

#[test]
fn resolves_python_perf_map_frames_when_runtime_provides_them() -> TestResult {
    let python = match python_for_tests() {
        Some(python) => python,
        None => return skip_or_fail("python3 was not found"),
    };

    let script = PythonScript::new("busy", busy_python_script())?;
    let ReadyPython {
        _child: child,
        mut stream,
    } = spawn_ready_python(&python, script.path(), &[])?;
    let ready = read_until(&mut stream, b"ready:", READY_TIMEOUT)?;
    let target_pid = parse_pid_line(&ready, "ready:")?;
    let perf_map_path = PathBuf::from(format!("/tmp/perf-{target_pid}.map"));
    let profile_path = profile_path("python-perf-map");

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
    assert_perf_map_has_python_symbols(&perf_map_path, script.path())?;

    let Some(_summary) = record_until_samples(target_pid as u32, &profile_path, false, 5)? else {
        return Ok(());
    };
    drop(child);

    let reader = PerfSpoolReader::open(&profile_path)?;
    let python_stacks = resolved_python_stack_frames(&reader)?;
    assert!(
        python_stacks
            .iter()
            .any(|stack| stack.iter().any(|frame| {
                frame.func_name == "stackpulse_busy_leaf"
                    && frame.file_name == script.path().to_string_lossy()
            })),
        "expected at least one Python sample in stackpulse_busy_leaf from {}; resolved Python stacks: {python_stacks:?}",
        script.path().display()
    );

    let expected = [
        "stackpulse_busy_leaf",
        "stackpulse_busy_middle",
        "stackpulse_busy_entry",
    ];
    let reverse_expected = [
        "stackpulse_busy_entry",
        "stackpulse_busy_middle",
        "stackpulse_busy_leaf",
    ];

    if python_stacks
        .iter()
        .any(|stack| stack.len() >= expected.len())
    {
        assert!(
            python_stacks.iter().any(|stack| {
                contains_ordered_frame_subsequence(stack, &expected, script.path())
                    || contains_ordered_frame_subsequence(stack, &reverse_expected, script.path())
            }),
            "expected one Python stack to contain {expected:?} in call order from {}; resolved Python stacks: {python_stacks:?}",
            script.path().display()
        );
    }

    remove_file_if_exists(&profile_path);
    remove_file_if_exists(&perf_map_path);
    Ok(())
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

struct ReadyPython {
    _child: ChildGuard,
    stream: TcpStream,
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
    match accept(&listener) {
        Ok(stream) => Ok(ReadyPython {
            _child: ChildGuard::new(child),
            stream,
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
                    "timed out waiting for Python test process",
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

fn attach_recorder(
    pid: u32,
    profile_path: &Path,
    inherit_child_processes: bool,
) -> io::Result<Option<PerfRecorder>> {
    match PerfRecorder::attach(
        pid,
        profile_path,
        AttachMode::StopAttachEnableResume,
        PerfRecorderOptions {
            frequency: 499,
            stack_size: 60 * 1024,
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

fn record_until_samples(
    pid: u32,
    profile_path: &Path,
    inherit_child_processes: bool,
    target_samples: u64,
) -> io::Result<Option<stackpulse::PerfSummary>> {
    let Some(mut recorder) = attach_recorder(pid, profile_path, inherit_child_processes)? else {
        return Ok(None);
    };
    let deadline = Instant::now() + RECORD_TIMEOUT;
    while Instant::now() < deadline && recorder.summary().samples < target_samples {
        recorder.wait()?;
        recorder.consume_available()?;
    }
    Ok(Some(recorder.finish()?))
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

fn profile_path(name: &str) -> PathBuf {
    let id = NEXT_PROFILE_ID.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "stackpulse-{name}-{}-{id}.spool",
        std::process::id()
    ))
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

fn assert_has_resolved_frame(reader: &PerfSpoolReader) -> io::Result<()> {
    let mut symbolizer = PerfSymbolizer::new(reader.modules());
    for sample in reader.samples() {
        let raw_frames = reader.stack_frame_refs(sample.stack_id)?;
        let frames =
            symbolizer.stack_refs_to_cached_frames(sample.process_id, sample.stack_id, raw_frames);
        if frames.iter().any(|frame| !frame.func_name().is_empty()) {
            return Ok(());
        }
    }
    panic!("expected at least one resolved frame");
}

#[derive(Debug)]
struct ResolvedPythonFrame {
    file_name: String,
    func_name: String,
}

fn resolved_python_stack_frames(
    reader: &PerfSpoolReader,
) -> io::Result<Vec<Vec<ResolvedPythonFrame>>> {
    let mut symbolizer = PerfSymbolizer::new(reader.modules());
    let mut stacks = Vec::new();
    for sample in reader.samples() {
        let raw_frames = reader.stack_frame_refs(sample.stack_id)?;
        let frames =
            symbolizer.stack_refs_to_cached_frames(sample.process_id, sample.stack_id, raw_frames);
        let names: Vec<_> = frames
            .iter()
            .filter_map(|frame| match frame {
                ResolvedFrame::Python(frame) => Some(ResolvedPythonFrame {
                    file_name: frame.file_name.to_string(),
                    func_name: frame.func_name.to_string(),
                }),
                ResolvedFrame::Native(_) => None,
            })
            .collect();
        if !names.is_empty() {
            stacks.push(names);
        }
    }
    Ok(stacks)
}

fn contains_ordered_frame_subsequence(
    stack: &[ResolvedPythonFrame],
    expected: &[&str],
    expected_file: &Path,
) -> bool {
    let expected_file = expected_file.to_string_lossy();
    let mut cursor = 0;
    for frame in stack {
        if cursor < expected.len()
            && frame.func_name == expected[cursor]
            && frame.file_name == expected_file
        {
            cursor += 1;
        }
    }
    cursor == expected.len()
}

fn assert_perf_map_has_python_symbols(path: &Path, script: &Path) -> io::Result<()> {
    let text = std::fs::read_to_string(path)?;
    let script = script.to_string_lossy();
    for func in [
        "stackpulse_busy_leaf",
        "stackpulse_busy_middle",
        "stackpulse_busy_entry",
    ] {
        let expected = format!("py::{func}:{script}");
        assert!(
            text.lines().any(|line| line.ends_with(&expected)),
            "expected perf map {} to contain {expected:?}; map contents:\n{text}",
            path.display()
        );
    }
    Ok(())
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
        let id = NEXT_PROFILE_ID.fetch_add(1, Ordering::Relaxed);
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
