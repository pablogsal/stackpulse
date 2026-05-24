# Tutorials

These tutorials teach the API by building complete recording flows. They assume
you are on Linux and have permission to profile the target process.

## Tutorial 1: record an existing process

In this tutorial you will attach to a running process, record samples for a few
seconds, read the resulting spool file, and print resolved stack frames.

### 1. Start a target process

Use any CPU-bound process you own. Python is convenient because it can also emit
perf-map symbols for Python frames:

```sh
PYTHONPERFSUPPORT=1 python3 -X perf - <<'PY'
import os
print(os.getpid(), flush=True)

def leaf():
    value = 0
    while True:
        value = (value * 33 + 17) % 1000003

def middle():
    leaf()

middle()
PY
```

Copy the printed PID for the next step.

### 2. Attach and drain perf events

Add `stackpulse` to a Rust program, then record the PID:

```rust
use std::time::{Duration, Instant};

use stackpulse::{AttachMode, PerfRecorder, PerfRecorderOptions};

fn record_for_ten_seconds(pid: u32) -> Result<(), Box<dyn std::error::Error>> {
    let mut recorder = PerfRecorder::attach(
        pid,
        "profile.spool",
        AttachMode::StopAttachEnableResume,
        PerfRecorderOptions {
            frequency: 99,
            stack_size: 60 * 1024,
            ..PerfRecorderOptions::default()
        },
    )?;

    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline && recorder.process_is_active(pid as i32) {
        recorder.wait()?;
        recorder.consume_available()?;
    }

    let summary = recorder.finish()?;
    println!("{summary:#?}");
    Ok(())
}
```

The important part is the `wait` and `consume_available` loop. `wait` blocks
briefly until a perf ring buffer is readable. `consume_available` drains queued
records, updates module state, unwinds samples, and writes compact records to
the spool file. `finish` flushes the file and returns final counters.

### 3. Read raw samples

Open the spool file and inspect its samples:

```rust
use stackpulse::PerfSpoolReader;

fn print_sample_index() -> Result<(), Box<dyn std::error::Error>> {
    let reader = PerfSpoolReader::open("profile.spool")?;

    println!("modules: {}", reader.modules().len());
    println!("samples: {}", reader.samples().len());
    println!("process exec markers: {}", reader.process_execs().len());

    for sample in reader.samples().iter().take(10) {
        println!(
            "{} us pid={} tid={} stack={}",
            reader.timestamp_us(sample),
            sample.process_id,
            sample.thread_id,
            sample.stack_id
        );
    }

    Ok(())
}
```

Samples store stack IDs rather than repeating every frame inline. This is why
large profiles stay small when hot code produces the same stacks repeatedly.

### 4. Resolve frames

Use one `PerfSymbolizer` per profile and reuse it across samples. It caches both
individual frames and whole stacks:

```rust
use stackpulse::{PerfSpoolReader, PerfSymbolizer};

fn print_resolved_stacks() -> Result<(), Box<dyn std::error::Error>> {
    let reader = PerfSpoolReader::open("profile.spool")?;
    let mut symbolizer = PerfSymbolizer::new(reader.modules());
    let mut raw_frames = Vec::new();

    for sample in reader.samples().iter().take(10) {
        reader.stack_frames(sample.stack_id, &mut raw_frames)?;
        let frames = symbolizer.stack_to_cached_frames(
            sample.process_id,
            sample.stack_id,
            &raw_frames,
        );

        println!("sample pid={} tid={}", sample.process_id, sample.thread_id);
        for frame in frames.iter() {
            println!("  {}", frame.func_name());
        }
    }

    Ok(())
}
```

For the Python target above, frames may include native interpreter frames,
Python `py::` perf-map frames, shared library frames, and address-only fallbacks
when debug or symbol data is unavailable.

## Tutorial 2: launch a process without missing startup work

Attaching to a running process is simple, but it can miss short-lived startup
work. To capture from the beginning, launch the child in a suspended state,
attach with `AttachWithEnableOnExec`, then let the child execute.

```rust
use std::ffi::{OsStr, OsString};
use std::time::{Duration, Instant};

use stackpulse::{
    process::SuspendedLaunchedProcess, AttachMode, PerfRecorder, PerfRecorderOptions,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = [
        OsString::from("-X"),
        OsString::from("perf"),
        OsString::from("-c"),
        OsString::from(
            "value = 0\nfor _ in range(50_000_000):\n    value = (value + 1) % 1009\n",
        ),
    ];
    let env = [(OsString::from("PYTHONPERFSUPPORT"), OsString::from("1"))];

    let launched = SuspendedLaunchedProcess::launch_in_suspended_state(
        OsStr::new("python3"),
        &args,
        &env,
    )?;

    let mut recorder = PerfRecorder::attach(
        launched.pid(),
        "startup.spool",
        AttachMode::AttachWithEnableOnExec,
        PerfRecorderOptions {
            frequency: 199,
            stack_size: 60 * 1024,
            ..PerfRecorderOptions::default()
        },
    )?;

    let running = launched.unsuspend_and_run()?;
    let timeout = Instant::now() + Duration::from_secs(30);

    let status = loop {
        if let Some(status) = running.try_wait()? {
            break status;
        }
        if Instant::now() >= timeout {
            recorder.disable();
            return Err("child did not exit before timeout".into());
        }
        recorder.wait()?;
        recorder.consume_available()?;
    };

    recorder.consume_available()?;
    let summary = recorder.finish()?;

    println!("child status: {status:?}");
    println!("samples written: {}", summary.samples);
    Ok(())
}
```

Use this pattern for profilers that launch the workload themselves, benchmarks
where startup matters, and short-lived commands.

## Tutorial 3: build a tiny stack counter

Most applications do not print raw samples directly. They aggregate repeated
stacks first:

```rust
use std::collections::BTreeMap;

use stackpulse::{PerfSpoolReader, PerfSymbolizer};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let reader = PerfSpoolReader::open("profile.spool")?;
    let mut symbolizer = PerfSymbolizer::new(reader.modules());
    let mut raw_frames = Vec::new();
    let mut counts = BTreeMap::<String, u64>::new();

    for sample in reader.samples() {
        reader.stack_frames(sample.stack_id, &mut raw_frames)?;
        let frames = symbolizer.stack_to_cached_frames(
            sample.process_id,
            sample.stack_id,
            &raw_frames,
        );

        let key = frames
            .iter()
            .map(|frame| frame.func_name())
            .collect::<Vec<_>>()
            .join(";");
        *counts.entry(key).or_default() += 1;
    }

    let mut rows = counts.into_iter().collect::<Vec<_>>();
    rows.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));

    for (stack, count) in rows.iter().take(20) {
        println!("{count:>8} {stack}");
    }

    Ok(())
}
```

This is the starting point for flame graph exporters and profile UIs. Production
exporters usually preserve more metadata than the example above: process ID,
thread ID, timestamp range, frame kind, symbol origin, file names, and line
numbers when available.
