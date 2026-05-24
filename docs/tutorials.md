# Tutorials

## Attach to an existing process

Pick a CPU-bound target. Python emits perf-map entries for Python frames when
run with perf support, which makes the resolved output more interesting:

```sh
PYTHONPERFSUPPORT=1 python3 -X perf - <<'PY'
import os
print(os.getpid(), flush=True)
v = 0
while True:
    v = (v * 33 + 17) % 1000003
PY
```

Attach to that PID, drain for ten seconds, then read the spool file back:

```rust,ignore
use std::time::{Duration, Instant};
use stackpulse::{AttachMode, PerfRecorder, PerfRecorderOptions, PerfSpoolReader, PerfSymbolizer};

fn record(pid: u32) -> stackpulse::Result<()> {
    let mut recorder = PerfRecorder::attach(
        pid,
        "profile.spool",
        AttachMode::StopAttachEnableResume,
        PerfRecorderOptions { frequency: 99, stack_size: 60 * 1024, ..Default::default() },
    )?;

    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline && recorder.process_is_active(pid as i32) {
        recorder.wait()?;
        recorder.consume_available()?;
    }
    recorder.finish()?;

    let reader = PerfSpoolReader::open("profile.spool")?;
    let mut symbolizer = PerfSymbolizer::new(reader.modules());

    for sample in reader.samples().iter().take(10) {
        let raw = reader.stack_frame_refs(sample.stack_id)?;
        let frames = symbolizer.stack_refs_to_cached_frames(
            sample.process_id, sample.stack_id, raw,
        );
        println!("pid={} tid={}", sample.process_id, sample.thread_id);
        for f in frames.iter() {
            println!("  {}", f.func_name());
        }
    }
    Ok(())
}
```

The `wait`/`consume_available` pair is the recording loop: `wait` blocks until
a ring buffer is readable, `consume_available` drains queued records, unwinds
samples, and writes them. Skipping this pair lets the kernel buffers fill and
samples are dropped as `lost_events`.

Samples reference stack IDs, not inline frames. That is why profiles stay
small when hot code produces the same stacks repeatedly, and why you reuse a
single [`PerfSymbolizer`], which caches resolved frames by
`(process_id, stack_id)`.

## Capture process startup

Attaching to a running process misses early startup. To profile from the
first instruction, launch the child suspended, attach with
`AttachWithEnableOnExec`, and let it run:

```rust,ignore
use std::ffi::{OsStr, OsString};
use std::time::{Duration, Instant};
use stackpulse::{process::SuspendedLaunchedProcess, AttachMode, PerfRecorder, PerfRecorderOptions};

let args = [OsString::from("-X"), OsString::from("perf"), OsString::from("-c"),
    OsString::from("v = 0\nfor _ in range(50_000_000):\n    v = (v + 1) % 1009\n")];
let env = [(OsString::from("PYTHONPERFSUPPORT"), OsString::from("1"))];

let launched = SuspendedLaunchedProcess::launch_in_suspended_state(
    OsStr::new("python3"), &args, &env,
)?;

let mut recorder = PerfRecorder::attach(
    launched.pid(),
    "startup.spool",
    AttachMode::AttachWithEnableOnExec,
    PerfRecorderOptions { frequency: 199, stack_size: 60 * 1024, ..Default::default() },
)?;

let running = launched.unsuspend_and_run()?;
let timeout = Instant::now() + Duration::from_secs(30);

let status = loop {
    if let Some(status) = running.try_wait()? { break status; }
    if Instant::now() >= timeout {
        recorder.disable();
        return Err("child did not exit before timeout".into());
    }
    recorder.wait()?;
    recorder.consume_available()?;
};

recorder.consume_available()?;
let summary = recorder.finish()?;
println!("status={status:?} samples={}", summary.samples);
# Ok::<_, Box<dyn std::error::Error>>(())
```

The kernel enables the perf events on `execve`, so nothing is recorded before
the child has loaded its binary, and nothing is missed after.

## Aggregate into a stack histogram

Real consumers count repeated stacks rather than printing them. This is the
seed of a flame graph exporter:

```rust,ignore
use std::collections::BTreeMap;
use stackpulse::{PerfSpoolReader, PerfSymbolizer};

let reader = PerfSpoolReader::open("profile.spool")?;
let mut symbolizer = PerfSymbolizer::new(reader.modules());
let mut counts = BTreeMap::<String, u64>::new();

for sample in reader.samples() {
    let raw = reader.stack_frame_refs(sample.stack_id)?;
    let frames = symbolizer.stack_refs_to_cached_frames(sample.process_id, sample.stack_id, raw);
    let key = frames.iter().map(|f| f.func_name()).collect::<Vec<_>>().join(";");
    *counts.entry(key).or_default() += 1;
}

let mut rows: Vec<_> = counts.into_iter().collect();
rows.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
for (stack, count) in rows.iter().take(20) {
    println!("{count:>8} {stack}");
}
# Ok::<_, Box<dyn std::error::Error>>(())
```

A production exporter preserves more metadata: process and thread IDs,
timestamps, [`FrameKind`], [`SymbolOrigin`], file names, line numbers, and
typically respects [`FrameFlags::HIDDEN_DEFAULT`] when rendering.
