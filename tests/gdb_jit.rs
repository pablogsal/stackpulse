//! Record assembler-generated JIT programs through the GDB registration ABI.
#![cfg(target_arch = "x86_64")]

mod common;

use common::{attach_is_not_allowed, environment_skips_allowed};
use stackpulse::record::SamplingEvent;
use stackpulse::{Pid, Recorder, SampleRate, Snapshot, Spool};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

static NEXT_FIXTURE: AtomicUsize = AtomicUsize::new(0);

/// Registration changes exercised while the generated leaf keeps running.
#[derive(Clone, Copy, Default)]
enum Scenario {
    #[default]
    Steady,
    UnregisterAndReuse,
    SilentReuse,
    RecoverCfi,
}

/// Choose a registration scenario and independent mapping, discovery, and layout options.
#[derive(Default)]
struct FixtureOptions {
    named: bool,
    executable_registry: bool,
    scenario: Scenario,
    multiple_sections: bool,
}

/// Keep the host process and all compiled artifacts alive for one recording.
struct JitTarget {
    child: Child,
    directory: PathBuf,
}

impl JitTarget {
    /// Compile the generated program and its registry host, then start the host.
    fn spawn(options: &FixtureOptions) -> Self {
        let directory = std::env::temp_dir().join(format!(
            "stackpulse-jit-test-{}-{}",
            std::process::id(),
            NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&directory).unwrap();
        let sources = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/gdb_jit");
        let source = sources.join("registry.c");
        let library = directory.join("libLLVM_fixture.so");
        let mut registry_compiler = Command::new("cc");
        registry_compiler
            .args(["-shared", "-fPIC", "-DREGISTRY_LIBRARY"])
            .arg(&source)
            .arg("-o")
            .arg(&library);
        compile_fixture(registry_compiler, "registry library");
        let assembly = sources.join("leaf.S");
        let object = directory.join("leaf.so");
        let mut assembler = Command::new("cc");
        assembler.args(["-shared", "-nostdlib", "-Wl,--no-eh-frame-hdr"]);
        if options.multiple_sections {
            assembler.arg("-DMULTI_SECTION");
        }
        assembler.arg(&assembly).arg("-o").arg(&object);
        compile_fixture(assembler, "generated leaf and unwind metadata");

        let binary = directory.join("target");
        let mut compiler = Command::new("cc");
        compiler
            .args(["-g", "-O0", "-fno-omit-frame-pointer", "-rdynamic"])
            .arg(format!("-DJIT_LIBRARY=\"{}\"", library.display()))
            .arg(format!("-DJIT_OBJECT=\"{}\"", object.display()));
        match options.scenario {
            Scenario::Steady => {}
            Scenario::UnregisterAndReuse | Scenario::SilentReuse => {
                compiler.arg("-DLIFECYCLE");
            }
            Scenario::RecoverCfi => {
                compiler.arg("-DRECOVER_CFI");
            }
        }
        if options.named {
            compiler.arg("-DNAMED_MAPPING");
        }
        if options.executable_registry {
            compiler.arg("-DEXECUTABLE_REGISTRY");
        }
        compiler.arg(&source).args(["-ldl", "-o"]).arg(&binary);
        compile_fixture(compiler, "JIT registry host");
        let child = Command::new(&binary)
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        Self { child, directory }
    }
}

impl Drop for JitTarget {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

/// Include compiler diagnostics when a fixture cannot be built.
fn compile_fixture(mut compiler: Command, description: &str) {
    let output = compiler.output().expect("could not run C compiler");
    assert!(
        output.status.success(),
        "could not compile {description}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Capture registration phases, terminate the target, and resolve the retained spool.
fn record_and_replay(options: FixtureOptions) {
    let mut target = JitTarget::spawn(&options);
    let mut ready = String::new();
    let mut output = BufReader::new(target.child.stdout.take().unwrap());
    output.read_line(&mut ready).unwrap();
    let busy_pc = u64::from_str_radix(ready.trim().strip_prefix("ready ").unwrap(), 16)
        .expect("fixture busy-loop address");
    let path = target.directory.join("recording.spool");
    let mut recorder = match Recorder::builder(SampleRate::hz(100).unwrap())
        .include_kernel(false)
        .attach(
            Pid::try_from(target.child.id()).unwrap(),
            Spool::retained(File::create(&path).unwrap()).unwrap(),
        ) {
        Ok(recorder) => recorder,
        Err(error) if attach_is_not_allowed(&error) && environment_skips_allowed() => {
            eprintln!("skipping GDB JIT test: profiling is not allowed here: {error}");
            return;
        }
        Err(error) => panic!("could not attach GDB JIT recorder: {error}"),
    };
    let original = observe_phase(
        &mut recorder,
        &path,
        busy_pc,
        0,
        Some("registered_leaf"),
        !matches!(options.scenario, Scenario::RecoverCfi),
    );
    let mut phases = vec![original];
    if matches!(options.scenario, Scenario::UnregisterAndReuse) {
        change_phase(&target, &mut output, libc::SIGUSR1);
        phases.push(observe_phase(
            &mut recorder,
            &path,
            busy_pc,
            phases.last().unwrap().end,
            None,
            false,
        ));
    }
    let final_name = match options.scenario {
        Scenario::Steady => None,
        Scenario::UnregisterAndReuse | Scenario::SilentReuse => Some("replacement_jit"),
        Scenario::RecoverCfi => Some("registered_leaf"),
    };
    if let Some(name) = final_name {
        change_phase(&target, &mut output, libc::SIGUSR2);
        phases.push(observe_phase(
            &mut recorder,
            &path,
            busy_pc,
            phases.last().unwrap().end,
            Some(name),
            true,
        ));
    }
    recorder.finish().unwrap();
    target.child.kill().unwrap();
    target.child.wait().unwrap();

    // Recheck every phase after exit, including the recorded registration identity.
    let snapshot = Snapshot::open(&path).unwrap();
    let mut first_mapping = None;
    for (index, phase) in phases.iter().enumerate() {
        let matches = matching_samples(&snapshot, busy_pc, phase);
        assert!(
            matches.len() >= 5,
            "phase lost its historical samples: {phase:?}"
        );
        for mapping in matches {
            if index == 0 {
                if let Some(original) = first_mapping {
                    assert_eq!(mapping, original, "initial registration identity changed");
                } else {
                    first_mapping = Some(mapping);
                }
            } else if phase.name.is_some() {
                match options.scenario {
                    Scenario::RecoverCfi => assert_eq!(
                        mapping,
                        first_mapping.unwrap(),
                        "CFI retry replaced symbol identity"
                    ),
                    Scenario::UnregisterAndReuse | Scenario::SilentReuse => assert_ne!(
                        mapping,
                        first_mapping.unwrap(),
                        "replacement reused historical identity"
                    ),
                    Scenario::Steady => unreachable!("steady registration has only one phase"),
                }
            }
        }
    }
}

fn change_phase(target: &JitTarget, output: &mut impl BufRead, signal: i32) {
    // SAFETY: This PID belongs to the child retained by JitTarget.
    assert_eq!(unsafe { libc::kill(target.child.id() as i32, signal) }, 0);
    let mut changed = String::new();
    output.read_line(&mut changed).unwrap();
    assert_eq!(changed, "changed\n");
}

#[derive(Debug)]
struct Phase {
    start: usize,
    end: usize,
    name: Option<&'static str>,
    has_caller: bool,
}

/// Wait for observed behavior, allowing slow machines and one-second CFI retries.
fn observe_phase<W: std::io::Write>(
    recorder: &mut Recorder<W>,
    path: &std::path::Path,
    busy_pc: u64,
    start: usize,
    name: Option<&'static str>,
    has_caller: bool,
) -> Phase {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        recorder.poll(Duration::from_millis(50)).unwrap();
        recorder.flush().unwrap();
        // Drop the snapshot before the recorder appends more records.
        let snapshot = Snapshot::open(path).unwrap();
        let phase = Phase {
            start,
            end: snapshot.samples().count(),
            name,
            has_caller,
        };
        let count = matching_samples(&snapshot, busy_pc, &phase).len();
        if count >= 5 {
            return phase;
        }
        assert!(
            Instant::now() < deadline,
            "only {count} matching leaf samples: {phase:?}"
        );
    }
}

/// Match only the generated loop, excluding startup and signal-handler samples.
fn matching_samples<'a>(
    snapshot: &'a Snapshot,
    busy_pc: u64,
    phase: &Phase,
) -> Vec<Option<stackpulse::spool::Mapping<'a>>> {
    let mut symbolizer = snapshot.symbolizer().build().unwrap();
    let mut matches = Vec::new();
    for sample in snapshot
        .samples()
        .skip(phase.start)
        .take(phase.end - phase.start)
    {
        let Some(stackpulse::spool::RawFrame::Native {
            address, mapping, ..
        }) = sample.stack().frames().next()
        else {
            continue;
        };
        if address != busy_pc {
            continue;
        }
        let stack = symbolizer.resolve(sample.stack()).unwrap();
        let mut frames = stack.frames();
        let Some(stackpulse::profile::Frame::Native(leaf)) = frames.next() else {
            continue;
        };
        let registered = leaf.origin == stackpulse::profile::SymbolOrigin::GdbJit;
        if let Some(name) = phase.name {
            if !registered || leaf.name() != Some(name) {
                continue;
            }
            assert!(leaf.flags.contains(stackpulse::profile::FrameFlags::JIT));
        } else if registered {
            continue;
        }
        let has_caller = frames.next().and_then(|frame| frame.name()) == Some("jit_caller");
        if has_caller == phase.has_caller {
            matches.push(mapping);
        }
    }
    matches
}

#[test]
fn anonymous_jit_unwinds_and_replays_after_exit() {
    record_and_replay(FixtureOptions::default());
}

#[test]
fn selected_events_preserve_registered_callers() {
    let rate = stackpulse::record::max_sample_rate().unwrap().min(5_000) as u32;
    for (event, kernel) in [
        (SamplingEvent::CpuCycles, false),
        (SamplingEvent::CpuClock, false),
        (SamplingEvent::CpuClock, true),
    ] {
        let mut target = JitTarget::spawn(&FixtureOptions::default());
        let mut ready = String::new();
        BufReader::new(target.child.stdout.take().unwrap())
            .read_line(&mut ready)
            .unwrap();
        assert!(ready.starts_with("ready "));
        let path = target.directory.join("events.spool");
        let mut recorder = match Recorder::builder(SampleRate::hz(rate).unwrap())
            .sampling_event(event)
            .include_kernel(kernel)
            .attach(
                Pid::try_from(target.child.id()).unwrap(),
                Spool::retained(File::create(&path).unwrap()).unwrap(),
            ) {
            Ok(recorder) => recorder,
            Err(error) if attach_is_not_allowed(&error) && environment_skips_allowed() => {
                eprintln!("skipping event-source test: profiling is not allowed here: {error}");
                return;
            }
            Err(error) => panic!("could not attach {event:?} recorder: {error}"),
        };
        let end = Instant::now() + Duration::from_secs(3);
        while Instant::now() < end {
            recorder.poll(Duration::from_millis(20)).unwrap();
        }
        let summary = recorder.finish().unwrap();
        let snapshot = Snapshot::open(&path).unwrap();
        let mut symbolizer = snapshot.symbolizer().build().unwrap();
        let mut jit = 0;
        let mut wrong = 0;
        for sample in snapshot.samples() {
            let stack = symbolizer.resolve(sample.stack()).unwrap();
            let mut frames = stack.frames();
            if frames.any(|frame| {
                matches!(frame, stackpulse::profile::Frame::Native(native)
                if native.origin == stackpulse::profile::SymbolOrigin::GdbJit
                    && native.name() == Some("registered_leaf"))
            }) {
                jit += 1;
                wrong +=
                    usize::from(frames.next().and_then(|frame| frame.name()) != Some("jit_caller"));
            }
        }
        eprintln!("event={event:?} requested_kernel={kernel} rate={rate} jit={jit} wrong={wrong} summary={summary:?}");
        assert!(
            jit >= 5,
            "recording did not recover enough registered frames"
        );
        assert_eq!(wrong, 0, "{event:?}, kernel={kernel}");
    }
}
#[test]
fn named_jit_with_interposed_registry_unwinds_and_replays_after_exit() {
    record_and_replay(FixtureOptions {
        named: true,
        executable_registry: true,
        ..FixtureOptions::default()
    });
}

#[test]
fn unregister_and_reuse_preserve_historical_symbols() {
    record_and_replay(FixtureOptions {
        named: true,
        executable_registry: true,
        scenario: Scenario::UnregisterAndReuse,
        ..FixtureOptions::default()
    });
}

#[test]
fn later_jit_section_uses_shared_unwind_table() {
    record_and_replay(FixtureOptions {
        multiple_sections: true,
        ..FixtureOptions::default()
    });
}

#[test]
fn silent_registration_reuse_gets_new_historical_identity() {
    record_and_replay(FixtureOptions {
        scenario: Scenario::SilentReuse,
        ..FixtureOptions::default()
    });
}

#[test]
fn unreadable_cfi_recovers_without_replacing_symbols() {
    record_and_replay(FixtureOptions {
        scenario: Scenario::RecoverCfi,
        ..FixtureOptions::default()
    });
}
