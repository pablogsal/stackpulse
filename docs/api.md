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
| [`Snapshot`] | Reads a spool file back into samples, modules, Python-runtime records, interned stack frames, and borrowed frame contexts. |
| [`Replay`] | Validates a spool, retains its definitions, and decodes samples sequentially to reduce memory use for large profiles. |
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
