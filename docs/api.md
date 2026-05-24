# stackpulse API documentation

This directory is the user documentation for `stackpulse`. It is separate from
the crate README on purpose: the README gives a short project overview, while
these pages explain how to build reliable profilers and analysis tools on top
of the Rust API.

The docs follow the Diataxis shape:

| Need | Document |
| --- | --- |
| Learn the end-to-end workflow | [Tutorials](tutorials.md) |
| Solve an operational problem | [How-to guides](how-to.md) |
| Look up public types and fields | [Reference](reference.md) |
| Understand how Linux perf sampling works here | [Explanation](explanation.md) |

## The core workflow

`stackpulse` has four main concepts:

1. `PerfRecorder` attaches to one or more Linux processes and drains
   `perf_event_open` records into a compact spool file.
2. `PerfSpoolReader` reads that file back into samples, modules, process
   execution markers, and interned stack frames.
3. `PerfSymbolizer` turns raw frame addresses into displayable frames using ELF
   symbols, Python perf maps, kernel symbols, and address-only fallbacks.
4. The `profile` data types describe the resolved frames that a UI, exporter,
   flame graph builder, or report generator can consume.

The normal recording loop is:

```rust
use std::time::{Duration, Instant};

use stackpulse::{
    AttachMode, PerfRecorder, PerfRecorderOptions, PerfSpoolReader, PerfSymbolizer,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let pid = std::env::args().nth(1).expect("pid").parse::<u32>()?;

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
    eprintln!("wrote {} samples", summary.samples);

    let reader = PerfSpoolReader::open("profile.spool")?;
    let mut symbolizer = PerfSymbolizer::new(reader.modules());
    let mut raw_frames = Vec::new();

    for sample in reader.samples().iter().take(5) {
        reader.stack_frames(sample.stack_id, &mut raw_frames)?;
        let frames = symbolizer.stack_to_cached_frames(
            sample.process_id,
            sample.stack_id,
            &raw_frames,
        );

        println!(
            "{} us pid={} tid={}",
            reader.timestamp_us(sample),
            sample.process_id,
            sample.thread_id
        );
        for frame in frames.iter() {
            println!("  {}", frame.func_name());
        }
    }

    Ok(())
}
```

## What the library is good at

Use `stackpulse` when you need to embed Linux CPU stack sampling in another Rust
program. It is designed for profilers, CI performance capture, local developer
tools, and service-side capture agents that want to store a profile first and
render or export it later.

It is not a command-line profiler by itself. It does not choose a report format
for you, and it intentionally leaves aggregation, flame graph construction,
storage policy, and UI decisions to the application using the crate.

## Runtime requirements

`stackpulse` is Linux-only. The crate uses `perf_event_open`, `/proc`, ELF
metadata, optional `/proc/kallsyms`, and optional Python perf maps in `/tmp`.

Most user-space recordings work as the same user that owns the target process.
Kernel frames, restricted systems, containerized environments, and high sample
rates can require extra permissions or sysctl changes. See
[How Linux perf sampling works in stackpulse](explanation.md) for the model and
[How-to guides](how-to.md) for practical recipes.

## Documentation quality contract

The API docs use the same vocabulary across pages:

- A **sample** is one timestamped observation of one thread.
- A **module** is an executable memory range such as a binary, shared object,
  anonymous JIT mapping, or kernel range.
- A **raw frame** is an address stored in the spool file.
- A **resolved frame** is a displayable `ResolvedFrame` produced by
  `PerfSymbolizer`.
- A **spool file** is the compact on-disk profile written by `PerfRecorder`.

When adding new public APIs, update [Reference](reference.md). When adding new
recording behaviors or operational constraints, update [How-to guides](how-to.md)
and [Explanation](explanation.md).
