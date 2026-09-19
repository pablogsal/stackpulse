//! Exercise generated stacks and code removal through LLVM's actual MCJIT engine.
#![cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]

mod common;

use common::{attach_is_not_allowed, environment_skips_allowed};
use stackpulse::profile::{Frame, FrameFlags, SymbolOrigin};
use stackpulse::{Pid, Recorder, SampleRate, Snapshot, Spool};
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant};

/// Own the compiler output and child, including cleanup after a failed assertion.
struct LlvmTarget {
    child: Child,
    responses: Receiver<String>,
    directory: PathBuf,
}

impl LlvmTarget {
    /// Link the fixture to the installed LLVM; CI requires this dependency.
    fn spawn() -> Option<Self> {
        let llvm_config = std::env::var_os("LLVM_CONFIG").unwrap_or_else(|| "llvm-config".into());
        let flags = match Command::new(&llvm_config)
            .args([
                "--cxxflags",
                "--ldflags",
                "--system-libs",
                "--libs",
                "core",
                "executionengine",
                "mcjit",
                "native",
                "irreader",
            ])
            .output()
        {
            Ok(output) => output,
            Err(error)
                if error.kind() == std::io::ErrorKind::NotFound && environment_skips_allowed() =>
            {
                eprintln!("skipping LLVM JIT test: install llvm-dev or set LLVM_CONFIG");
                return None;
            }
            Err(error) => panic!("could not run {llvm_config:?}: {error}"),
        };
        assert!(flags.status.success(), "llvm-config failed: {flags:?}");
        let directory =
            std::env::temp_dir().join(format!("stackpulse-llvm-jit-test-{}", std::process::id()));
        std::fs::create_dir(&directory).unwrap();
        let sources = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/llvm_jit");
        let binary = directory.join("target");
        let compiler = std::env::var_os("CXX").unwrap_or_else(|| "c++".into());
        let output = Command::new(compiler)
            .arg(sources.join("host.cpp"))
            .args(String::from_utf8(flags.stdout).unwrap().split_whitespace())
            .args(["-pthread", "-rdynamic", "-o"])
            .arg(&binary)
            .output()
            .expect("could not run LLVM fixture compiler");
        assert!(
            output.status.success(),
            "could not compile LLVM fixture: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let mut child = Command::new(binary)
            .arg(sources.join("program.ll"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let stdout = child.stdout.take().unwrap();
        let (sender, responses) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                if sender.send(line.expect("LLVM fixture output")).is_err() {
                    break;
                }
            }
        });
        Some(Self {
            child,
            responses,
            directory,
        })
    }

    /// Bound protocol waits so a broken target fails instead of hanging CI.
    fn response(&self) -> String {
        self.responses
            .recv_timeout(Duration::from_secs(20))
            .expect("LLVM fixture did not respond")
    }

    fn command(&mut self, command: &str) {
        writeln!(self.child.stdin.as_mut().unwrap(), "{command}").unwrap();
    }

    fn leaf_address(&self) -> u64 {
        let ready = self.response();
        u64::from_str_radix(
            ready.strip_prefix("ready ").expect("LLVM ready response"),
            16,
        )
        .expect("generated leaf address")
    }
}

impl Drop for LlvmTarget {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

/// Count complete generated call chains, requiring recorded GDB symbols on every frame.
fn generated_stacks(snapshot: &Snapshot, start: usize, leaf: u64, generation: &str) -> usize {
    let expected = ["leaf", "caller", "entry"].map(|name| format!("llvm_{name}_{generation}"));
    let mut symbolizer = snapshot.symbolizer().disable_perf_maps().build().unwrap();
    snapshot
        .samples()
        .skip(start)
        .filter(|sample| {
            let Some(stackpulse::spool::RawFrame::Native {
                mapping: Some(mapping),
                ..
            }) = sample.stack().frames().next()
            else {
                return false;
            };
            if !mapping.address_range().contains(&leaf) {
                return false;
            }
            let stack = symbolizer.resolve(sample.stack()).unwrap();
            let mut frames = stack.frames();
            expected.iter().all(|name| {
                matches!(frames.next(), Some(Frame::Native(frame))
            if frame.name() == Some(name.as_str())
                && frame.origin == SymbolOrigin::GdbJit
                && frame.flags.contains(FrameFlags::JIT))
            })
        })
        .count()
}

/// Wait for sampled behavior rather than assuming a fixed JIT discovery delay.
fn observe_generation<W: Write>(
    recorder: &mut Recorder<W>,
    path: &Path,
    start: usize,
    leaf: u64,
    generation: &str,
) -> usize {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        recorder.poll(Duration::from_millis(50)).unwrap();
        recorder.flush().unwrap();
        let snapshot = Snapshot::open(path).unwrap();
        if generated_stacks(&snapshot, start, leaf, generation) >= 5 {
            return snapshot.samples().count();
        }
        assert!(
            Instant::now() < deadline,
            "missing LLVM {generation} call chain"
        );
    }
}

#[test]
fn llvm_engine_removal_and_replacement_preserve_recorded_stacks() {
    let Some(mut target) = LlvmTarget::spawn() else {
        return;
    };
    let first_leaf = target.leaf_address();
    let path = target.directory.join("recording.spool");
    let mut recorder = match Recorder::builder(SampleRate::hz(100).unwrap())
        .include_kernel(false)
        .attach(
            Pid::try_from(target.child.id()).unwrap(),
            Spool::retained(File::create(&path).unwrap()).unwrap(),
        ) {
        Ok(recorder) => recorder,
        Err(error) if attach_is_not_allowed(&error) && environment_skips_allowed() => {
            eprintln!("skipping LLVM JIT test: profiling is not allowed here: {error}");
            return;
        }
        Err(error) => panic!("could not attach LLVM JIT recorder: {error}"),
    };
    let first_end = observe_generation(&mut recorder, &path, 0, first_leaf, "first");
    target.command("remove");
    // The host checks that LLVM itself unlinked the destroyed engine's registration.
    assert_eq!(target.response(), "removed");
    target.command("replace");
    let second_leaf = target.leaf_address();
    observe_generation(&mut recorder, &path, first_end, second_leaf, "second");
    target.command("exit");
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if let Some(status) = target.child.try_wait().unwrap() {
            assert!(status.success(), "LLVM fixture exited with {status}");
            break;
        }
        assert!(Instant::now() < deadline, "LLVM fixture did not exit");
        std::thread::sleep(Duration::from_millis(10));
    }
    recorder.finish().unwrap();

    let snapshot = Snapshot::open(path).unwrap();
    assert!(generated_stacks(&snapshot, 0, first_leaf, "first") >= 5);
    assert!(generated_stacks(&snapshot, first_end, second_leaf, "second") >= 5);
}
