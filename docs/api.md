StackPulse is a Rust library for building Linux profilers with `perf_event`.
[`Recorder`] captures CPU stack samples from running processes and writes
them to a compact spool file. [`Snapshot`] loads that file back, and
[`Symbolizer`] resolves the recorded addresses into frames with names and
source locations, ready for whatever aggregation or output your profiler does
with them.

# Quick example

```rust,no_run
use std::time::{Duration, Instant};
use stackpulse::{AttachMode, Pid, Recorder, RecorderOptions, SampleRate, Snapshot};
# fn run(pid: u32) -> Result<(), Box<dyn std::error::Error>> {
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

for stack in reader.stacks() {
    for frame in symbolizer.resolve(stack)? {
        println!("{}", frame.display_name());
    }
}
# Ok(())
# }
```

# Core types

| Type | Role |
| --- | --- |
| [`Recorder`] | Attaches to one or more processes, drains `perf_event_open` ring buffers, writes a spool file. |
| [`Snapshot`] | Reads a completed spool into memory for random access. |
| [`Replay`] | Validates a spool, retains its definitions, and decodes samples sequentially to reduce memory use for large profiles. |
| [`Tail`] | Decodes bounded batches from a growing spool for live processing. |
| [`Symbolizer`] | Resolves raw frame addresses using ELF symbols, kernel symbols, Python perf maps, and address fallbacks. The native ELF backend is pluggable via [`symbolize::NativeSymbolizer`]. |
| [`symbolize::NativeSymbolizer`] | Trait for swapping in your own native symbolizer (custom debuginfod, debug-dir, or source-info policy). [`Symbolizer`] still handles kernel and perf-map frames. |
| [`profile`] types | Resolved frame data types: what an aggregator, UI, or exporter consumes. |

The recorder writes a self-contained spool file. Symbolization reads it later
and can run on another host if the same binaries and perf maps are available.

# Vocabulary

- A sample is one timestamped observation of one thread.
- A module is an executable memory range: a binary, shared object,
  anonymous JIT mapping, or kernel range.
- A raw frame is an address recorded in the spool file.
- A resolved frame is a displayable [`profile::ResolvedFrame`] produced by
  [`Symbolizer`].
- A spool file is the compact on-disk profile written by [`Recorder`].

# Raw replay

Recording never depends on symbolization: the spool stores raw instruction
pointers together with the module mappings observed at capture time. An
application that already has its own symbol pipeline can skip
[`Symbolizer`] and consume those raw frames directly:

```rust,no_run
# fn run() -> Result<(), Box<dyn std::error::Error>> {
let reader = stackpulse::Snapshot::open("profile.spool")?;

for stack in reader.stacks() {
    for context in stack.contexts() {
        let ip = context.frame.abs_ip;
        if let Some(module) = context.module {
            // Pass `ip`, `module.module`, and `module.file_relative_ip` to your symbolizer.
        }
    }
}
# Ok(())
# }
```

`SampleStack::contexts` does not symbolize anything. It binds each borrowed raw
frame to the module mapping StackPulse recorded at capture time, which is what
an external symbolizer needs to translate the address, even across remaps.

# Sequential replay

For large profiles, use [`Replay`] to avoid retaining every
[`spool::SampleRecord`] in memory:

```rust,no_run
use stackpulse::Replay;
# fn run() -> Result<(), Box<dyn std::error::Error>> {
let reader = Replay::open("profile.spool")?;
let mut symbolizer = reader.symbolizer().build()?;

for stack in reader.stacks() {
    for frame in symbolizer.resolve(stack)? {
        println!("{}", frame.display_name());
    }
}
# Ok(())
# }
```

Opening still validates the complete spool and retains modules, frames,
interned stacks, threads, and runtime markers; only the samples themselves are
decoded on the fly as the iterator advances. The file must remain unchanged
while the reader is alive. Use [`Snapshot`] instead when you need
random access to `samples()`.

# Live tailing

Use [`Tail`] when recording and processing run concurrently. Apply each batch
to its symbolizer before resolving the batch's stacks. With
[`StackCache::External`], discard prepared stacks selected by the returned
[`symbolize::Invalidation`] before resolving more samples.

Prefer [`Recorder::tail`] when the recorder and tail live in one process. It
shares handles still held by the recorder's bounded image cache, so deleted or
replaced files can still be symbolized exactly while their images remain in
that cache. `Tail::open` has only the paths stored in the spool.

```rust,no_run
use stackpulse::{StackCache, Tail};
# fn run() -> Result<(), Box<dyn std::error::Error>> {
let mut tail = Tail::open("profile.spool")?;
let mut symbolizer = tail.symbolizer().stack_cache(StackCache::External).build()?;

// Call this function after each writer flush and once after the writer finishes.
fn process_visible(
    tail: &mut Tail,
    symbolizer: &mut stackpulse::Symbolizer,
) -> stackpulse::Result<()> {
  loop {
    let batch = tail.poll()?;
    let invalidation = symbolizer.update(&batch)?;
    invalidate_prepared_stacks(|pid| invalidation.affects_process(pid));

    for stack in batch.stacks() {
        for frame in symbolizer.resolve(stack)? {
            aggregate(frame);
        }
    }

    if !batch.has_more() {
        break;
    }
  }
  Ok(())
}
# Ok(())
# }
# fn invalidate_prepared_stacks(_: impl Fn(stackpulse::Pid) -> bool) {}
# fn aggregate(_: &stackpulse::profile::ResolvedFrame) {}
```

`TailBatch` borrows the tail's reusable sample storage. Finish processing and
drop the batch before polling again. `has_more()` means another complete batch
may already be visible, not that the writer is still running. Poll again
promptly when it is true. When it is false, wait for the writer to flush or
finish before polling again. A final incomplete record is retried after the
writer appends the remainder.

`Symbolizer::update` verifies that the batch and symbolizer came from the same
tail. It installs new definitions, refreshes live perf maps and kernel symbols,
and retires resources only after the last batch that can reference them has
been processed. An invalidation can target individual processes or every
prepared stack. Callers using `StackCache::Internal` do not maintain that
external state, but must still call `update` before `resolve`.

External caches can use [`symbolize::ResolvedFrameId`] to reuse converted
frames across different stacks. IDs are unique for one symbolizer and are
never reused. Cache a whole resolved stack only when
[`symbolize::ResolvedStack::is_cacheable`] is true; otherwise a temporary
native-image failure would preserve an address-only result permanently.

# Plugging in an external native symbolizer

The default constructors install the bundled `wholesym` backend for native
ELF symbol lookup. To replace it, implement [`symbolize::NativeSymbolizer`] and pass a
factory to [`SymbolizerBuilder::native`]. StackPulse groups native lookups by
process and passes them to the backend in batches. Each [`symbolize::NativeLookup`]
contains the selected module and the absolute, relative, and image addresses:

```rust,no_run
use stackpulse::symbolize::{NativeLookup, NativeSymbolizer, NativeSymbols};
use stackpulse::Snapshot;

struct MySymbolizer { /* your wholesym / debuginfod / dwarf state */ }

impl NativeSymbolizer for MySymbolizer {
    type Error = std::convert::Infallible;

    fn symbolize(
        &mut self,
        requests: &[NativeLookup],
        output: &mut Vec<NativeSymbols>,
    ) -> Result<(), Self::Error> {
        for request in requests {
            let _ = (request.module().path(), request.image_address());
            output.push(NativeSymbols::unresolved());
        }
        Ok(())
    }
}

# fn run() -> Result<(), Box<dyn std::error::Error>> {
let reader = Snapshot::open("profile.spool")?;
let mut symbolizer = reader.symbolizer()
    .native(|_pid| MySymbolizer { /* ... */ })
    .build()?;
# Ok(())
# }
```

Kernel frames (`/proc/kallsyms`) and Python or JIT perf maps
(`/tmp/perf-<pid>.map`) stay inside [`Symbolizer`]; the plug-in only sees
native module addresses. Consumers that always supply a native symbolizer can
disable StackPulse's default features to omit `wholesym` and Tokio. In that
configuration [`Symbolizer::has_native_backend`] is `false` until `native(...)`
installs one; native frames otherwise resolve to address-only values.

Backend tests can construct requests directly with
[`symbolize::NativeModule::new`] and [`symbolize::NativeLookup::new`]. Each
synthetic module gets a distinct opaque image identity. Its `image_path()` is
`None`; recorded modules expose that path only when StackPulse retained the
exact validated file backing the Linux mapping.

During live tailing, [`symbolize::NativeSymbolizer::retire_module`] reports
when a mapping is no longer active. Backends should use it to discard
mapping-specific indexes. State shared by `NativeModule::image_id()` can stay
cached until the last mapping for that image is retired.

Symbol results can be provisional when a retryable error prevents StackPulse
from opening a validated native image. A later resolution attempt can replace
that address-only fallback with more specific symbols. External stack caches
should avoid permanently caching those temporary fallbacks.

# Runtime requirements

StackPulse runs on Linux and uses `perf_event_open`, `/proc`, ELF metadata,
optional `/proc/kallsyms`, and optional Python perf maps under `/tmp`.

User-space recording works as the same user that owns the target. Kernel
frames, containers, hardened systems, and aggressive sample rates may need
extra capabilities (typically `CAP_PERFMON`) or a relaxed
`perf_event_paranoid` setting. See the Permissions section in the
explanation chapter for the full breakdown.

# Guide

The [guide](crate::docs) walks through process attachment, startup capture,
configuration, symbolization, diagnostics, and the SPULSE file format.
