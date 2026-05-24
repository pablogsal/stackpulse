A library for recording Linux CPU stack samples and resolving them into
displayable frames. Designed to be embedded in profilers, capture agents,
benchmark harnesses, and developer tooling.

`stackpulse` does the recording and symbolization. It does not aggregate,
render flame graphs, or choose an output format. That is left to the calling
application.

# Quick example

```rust,ignore
use std::time::{Duration, Instant};
use stackpulse::{AttachMode, PerfRecorder, PerfRecorderOptions, PerfSpoolReader, PerfSymbolizer};

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

for sample in reader.samples() {
    let raw = reader.stack_frame_refs(sample.stack_id)?;
    let frames = symbolizer.stack_refs_to_cached_frames(sample.process_id, sample.stack_id, raw);
    for frame in frames.iter() {
        println!("{}", frame.func_name());
    }
}
# Ok::<_, Box<dyn std::error::Error>>(())
```

# Core types

| Type | Role |
| --- | --- |
| [`PerfRecorder`] | Attaches to one or more processes, drains `perf_event_open` ring buffers, writes a spool file. |
| [`PerfSpoolReader`] | Reads a spool file back into samples, modules, exec markers, and interned stack frames. |
| [`PerfSymbolizer`] | Resolves raw frame addresses using ELF symbols, kernel symbols, Python perf maps, and address fallbacks. |
| [`profile`] types | Resolved frame data types: what an aggregator, UI, or exporter consumes. |

Recording and symbolization are deliberately separate. The recorder writes a
self-contained spool file; symbolization happens later, off the hot path, and
can run on a different host as long as the binaries and perf maps are
preserved.

# Vocabulary

- A sample is one timestamped observation of one thread.
- A module is an executable memory range: a binary, shared object,
  anonymous JIT mapping, or kernel range.
- A raw frame is an address recorded in the spool file.
- A resolved frame is a displayable [`ResolvedFrame`] produced by
  [`PerfSymbolizer`].
- A spool file is the compact on-disk profile written by [`PerfRecorder`].

# Runtime requirements

Linux only. Uses `perf_event_open`, `/proc`, ELF metadata, optional
`/proc/kallsyms`, and optional Python perf maps under `/tmp`.

User-space recording works as the same user that owns the target. Kernel
frames, containers, hardened systems, and aggressive sample rates may need
extra capabilities (typically `CAP_PERFMON`) or `perf_event_paranoid`
adjustments. See [Permissions](#permissions-and-system-configuration).
