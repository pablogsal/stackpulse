# Tutorial

This tutorial walks through a minimal profiler in three steps: attach to a
running process, capture a second process from its first instruction, and
aggregate the recorded stacks into a histogram.

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
use stackpulse::{AttachMode, Pid, Recorder, RecorderOptions, SampleRate, Snapshot};

fn record(pid: u32) -> Result<(), Box<dyn std::error::Error>> {
    let pid = Pid::try_from(pid)?;
    let mut recorder = Recorder::attach(
        pid,
        "profile.spool",
        AttachMode::StopWhileAttaching,
        RecorderOptions::new(SampleRate::hz(99)?).stack_size(60 * 1024),
    )?;

    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline && recorder.process_is_active(pid)? {
        recorder.poll(Duration::from_millis(100))?;
    }
    recorder.finish()?;

    let reader = Snapshot::open("profile.spool")?;
    let mut symbolizer = reader.symbolizer().build()?;

    for stack in reader.stacks().take(10) {
        println!("pid={} tid={}", stack.pid(), stack.tid());
        for frame in symbolizer.resolve(stack)? {
            println!("  {}", frame.display_name());
        }
    }
    Ok(())
}
```

`poll` is the recording loop. It waits for at most the supplied timeout, then
drains queued records, unwinds their samples, and writes them to the spool. If
you stop polling, the kernel buffers fill and subsequent samples appear as
`lost_events` in the summary.

Samples reference stack IDs, not inline frame data, which is why profiles
stay small when hot code keeps producing the same stacks. It is also why you
should reuse a single [`Symbolizer`](crate::Symbolizer): it caches resolved frames keyed by
the opaque [`StackKey`](crate::spool::StackKey).

## Capture process startup

Attaching to a running process misses early startup. To profile from the
first instruction, launch the child suspended, attach with
`OnExec`, and let it run:

```rust,no_run
use std::ffi::{OsStr, OsString};
use std::time::{Duration, Instant};
use stackpulse::{
    process::SuspendedLaunchedProcess, AttachMode, Recorder, RecorderOptions,
    SampleRate,
};
# fn run() -> Result<(), Box<dyn std::error::Error>> {
let args = [OsString::from("-X"), OsString::from("perf"), OsString::from("-c"),
    OsString::from("v = 0\nfor _ in range(50_000_000):\n    v = (v + 1) % 1009\n")];
let env = [(OsString::from("PYTHONPERFSUPPORT"), OsString::from("1"))];

let launched = SuspendedLaunchedProcess::launch_in_suspended_state(
    OsStr::new("python3"), &args, &env,
)?;

let mut recorder = Recorder::attach(
    launched.pid(),
    "startup.spool",
    AttachMode::OnExec,
    RecorderOptions::new(SampleRate::hz(199)?).stack_size(60 * 1024),
)?;

let mut running = launched.unsuspend_and_run()?;
let timeout = Instant::now() + Duration::from_secs(30);

let status = loop {
    if let Some(status) = running.try_wait()? { break status; }
    if Instant::now() >= timeout {
        recorder.disable()?;
        return Err("child did not exit before timeout".into());
    }
    recorder.poll(Duration::from_millis(100))?;
};

let summary = recorder.finish()?;
println!("status={status:?} samples={}", summary.samples);
# Ok(())
# }
```

The kernel enables the perf events on `execve`, so nothing is recorded before
the child has loaded its binary, and nothing is missed once it starts running.

## Aggregate into a stack histogram

To build a flame graph or top-functions report, count how often each stack
appears:

```rust,no_run
use std::collections::BTreeMap;
use stackpulse::Snapshot;
# fn run() -> Result<(), Box<dyn std::error::Error>> {
let reader = Snapshot::open("profile.spool")?;
let mut symbolizer = reader.symbolizer().build()?;
let mut counts = BTreeMap::<String, u64>::new();

for stack in reader.stacks() {
    let mut names = Vec::new();
    for frame in symbolizer.resolve(stack)? {
        names.push(frame.display_name().to_owned());
    }
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

Keep process and thread IDs when the output needs per-process or per-thread
views. [`FrameKind`](crate::profile::FrameKind), [`SymbolOrigin`](crate::profile::SymbolOrigin),
file names, and line numbers are available on resolved frames. Frames marked
with [`FrameFlags::HIDDEN_DEFAULT`](crate::profile::FrameFlags::HIDDEN_DEFAULT) identify
interpreter internals that a profiler may hide by default.
