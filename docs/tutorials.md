# Tutorials

## Attach to an existing process

Pick a CPU-bound target. Python emits perf-map entries for its own frames
when run with perf support, so the resolved output shows function names
instead of bare addresses:

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

```rust,no_run
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
    let mut symbolizer = PerfSymbolizer::for_spool(&reader);

    for stack in reader.sample_stacks().take(10) {
        println!("pid={} tid={}", stack.sample.process_id, stack.sample.thread_id);
        symbolizer.for_each_sample_stack(stack, |f| {
            println!("  {}", f.func_name());
        });
    }
    Ok(())
}
```

The `wait`/`consume_available` pair is the recording loop. `wait` blocks
until a ring buffer is readable; `consume_available` drains the queued
records, unwinds the samples it finds, and writes them to the spool. If you
skip the pair the kernel buffers fill up and subsequent samples are dropped,
showing up as `lost_events` in the summary.

Samples reference stack IDs, not inline frame data, which is why profiles
stay small when hot code keeps producing the same stacks. It is also why you
should reuse a single [`PerfSymbolizer`]: it caches resolved frames keyed by
`(process_id, stack_id)`.

## Capture process startup

Attaching to a running process misses early startup. To profile from the
first instruction, launch the child suspended, attach with
`AttachWithEnableOnExec`, and let it run:

```rust,no_run
use std::ffi::{OsStr, OsString};
use std::time::{Duration, Instant};
use stackpulse::{process::SuspendedLaunchedProcess, AttachMode, PerfRecorder, PerfRecorderOptions};
# fn run() -> Result<(), Box<dyn std::error::Error>> {
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
# Ok(())
# }
```

The kernel enables the perf events on `execve`, so nothing is recorded before
the child has loaded its binary, and nothing is missed once it starts running.

## Aggregate into a stack histogram

Printing each frame is a debugging mode. A real exporter counts how often
each stack appears. This snippet is the kernel of any flame-graph or
top-functions report:

```rust,no_run
use std::collections::BTreeMap;
use stackpulse::{PerfSpoolReader, PerfSymbolizer};
# fn run() -> Result<(), Box<dyn std::error::Error>> {
let reader = PerfSpoolReader::open("profile.spool")?;
let mut symbolizer = PerfSymbolizer::for_spool(&reader);
let mut counts = BTreeMap::<String, u64>::new();

for stack in reader.sample_stacks() {
    let mut names = Vec::new();
    symbolizer.for_each_sample_stack(stack, |f| {
        names.push(f.func_name());
    });
    let key = names.join(";");
    *counts.entry(key).or_default() += 1;
}

let mut rows: Vec<_> = counts.into_iter().collect();
rows.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
for (stack, count) in rows.iter().take(20) {
    println!("{count:>8} {stack}");
}
# Ok(())
# }
```

A production exporter keeps more metadata around: process and thread IDs,
timestamps, [`FrameKind`], [`SymbolOrigin`], file names, and line numbers.
Most exporters also hide frames flagged with [`FrameFlags::HIDDEN_DEFAULT`]
in their default view.
