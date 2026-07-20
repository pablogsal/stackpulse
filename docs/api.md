A library for recording Linux CPU stack samples into a compact spool file and,
when you want them, resolving the recorded addresses into displayable frames.
Built to drop into profilers, capture agents, benchmark harnesses, and
developer tooling.

The crate covers two phases: capture and replay. Recording always runs;
symbolization is opt-in. Embedders that already have their own symbol
pipeline can read raw instruction pointers straight from the spool and never
touch [`PerfSymbolizer`]. stackpulse does not aggregate stacks, render flame
graphs, or pick an output format. Those decisions stay with the caller.

# Quick example

```rust,no_run
use std::time::{Duration, Instant};
use stackpulse::{AttachMode, PerfRecorder, PerfRecorderOptions, PerfSpoolReader, PerfSymbolizer};
# fn run(pid: u32) -> Result<(), Box<dyn std::error::Error>> {
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

for stack in reader.sample_stacks() {
    symbolizer.for_each_sample_stack(stack, |frame| {
        println!("{}", frame.func_name());
    });
}
# Ok(())
# }
```

# Core types

| Type | Role |
| --- | --- |
| [`PerfRecorder`] | Attaches to one or more processes, drains `perf_event_open` ring buffers, writes a spool file. |
| [`PerfSpoolReader`] | Reads a spool file back into samples, modules, Python-runtime records, interned stack frames, and borrowed frame contexts. |
| [`PerfSymbolizer`] | Resolves raw frame addresses using ELF symbols, kernel symbols, Python perf maps, and address fallbacks. The native ELF backend is pluggable via [`NativeSymbolizer`]. |
| [`NativeSymbolizer`] | Trait for swapping in your own native symbolizer (custom debuginfod, debug-dir, or source-info policy). [`PerfSymbolizer`] still handles kernel and perf-map frames. |
| [`profile`] types | Resolved frame data types: what an aggregator, UI, or exporter consumes. |

Recording and symbolization are deliberately separate. The recorder writes a
self-contained spool file; symbolization happens later, off the hot path, and
can run on a different host as long as the binaries and perf maps are
preserved.

# Raw replay

For integrations with an existing symbolizer, consume raw frames directly:

```rust,no_run
# fn run() -> Result<(), Box<dyn std::error::Error>> {
let reader = stackpulse::PerfSpoolReader::open("profile.spool")?;

for sample in reader.samples() {
    for context in reader.stack_frame_contexts(sample.process_id, sample.stack_id)? {
        let ip = context.frame.abs_ip;
        if let Some(module) = context.module {
            // Pass `ip`, `module.module`, and `module.file_relative_ip` to your symbolizer.
        }
    }
}
# Ok(())
# }
```

`stack_frame_contexts` does not symbolize. It only binds borrowed raw frames to
the module mapping stackpulse recorded at capture time.

# Plugging in an external native symbolizer

Callers with their own debuginfod, debug-dir, or source-info pipeline can keep
using [`PerfSymbolizer`] for kernel and perf-map frames while substituting a
different backend for native ELF modules. Implement [`NativeSymbolizer`] and
hand a factory to [`PerfSymbolizerBuilder::native_symbolizer_factory`]. stackpulse parses each
module's ELF, computes its image base, and calls `set_modules` whenever the
module set for a process group changes; you then receive `symbolize_one(addr)`
for every native frame:

```rust,no_run
use std::rc::Rc;
use stackpulse::{
    NativeSymbolizer, PerfSpoolReader, PerfSymbolizerBuilder, SymModule, SymbolsRc,
};

struct MySymbolizer { /* your wholesym / debuginfod / dwarf state */ }

impl NativeSymbolizer for MySymbolizer {
    fn set_modules(&mut self, modules: Vec<SymModule>) {
        // modules carries path, avma_range, and ModuleImageBase already
        // resolved from ELF. No /proc or /maps work needed here.
    }
    fn symbolize_one(&mut self, addr: u64) -> SymbolsRc {
        // Convert addr -> SVMA via the SymModule's image_base, then look up.
        Rc::from([])
    }
}

# fn run() -> Result<(), Box<dyn std::error::Error>> {
let reader = PerfSpoolReader::open("profile.spool")?;
let factory = |_pid: i32| -> Box<dyn NativeSymbolizer> {
    Box::new(MySymbolizer { /* ... */ })
};
let mut symbolizer = PerfSymbolizerBuilder::for_spool(&reader)
    .native_symbolizer_factory(factory)
    .build();
# Ok(())
# }
```

Kernel frames (`/proc/kallsyms`) and Python or JIT perf maps
(`/tmp/perf-PID.map`) stay inside `PerfSymbolizer`; the plug-in only sees
native module addresses. The default constructors install the bundled
wholesym backend.

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
extra capabilities (typically `CAP_PERFMON`) or a relaxed
`perf_event_paranoid` setting. See the Permissions section in the
explanation chapter for the full breakdown.
