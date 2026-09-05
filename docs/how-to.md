# Recipes

This chapter collects short, self-contained recipes: configuring capture,
adding processes, selecting symbol sources, and diagnosing lost samples.

## Pick recording options

A recorder needs a positive sample rate. The stack snapshot defaults to 32 KiB:

```rust,no_run
use stackpulse::{RecorderOptions, SampleRate};

let options = RecorderOptions::new(SampleRate::hz(99).expect("positive rate"))
    .stack_size(60 * 1024)
    .include_kernel(false)
    .inherit_children(false);
```

| Setting | When to change it | What it costs |
| --- | --- | --- |
| `SampleRate` | Need a fixed rate or the current kernel maximum. | Higher rates raise CPU overhead and increase the chance of lost events under load. |
| `stack_size(bytes)` | Stacks are getting truncated. | More memory copied per sample. Capped at [`MAX_SAMPLE_USER_STACK`](crate::record::MAX_SAMPLE_USER_STACK). |
| `include_kernel(bool)` | Want syscall, scheduler, or kernel-lock attribution. | Usually needs extra privileges. If only kernel sampling is denied, [`Recorder::attach`](crate::Recorder::attach) retries user-only and reports `summary.kernel_enabled = false`. |
| `inherit_children(bool)` | Forked children are part of the workload. | Opens more perf events and adds bookkeeping per child. |
| `start_timestamp_us(value)` | Aligning the profile to an external clock or trace. | Metadata only; read back through [`Snapshot::timestamp_us`](crate::Snapshot::timestamp_us). |
| `sample_interval_us(value)` | UI or export format wants an interval hint. | Metadata only; does not drive kernel sampling. |

Check the kernel cap before asking for an aggressive rate:

```rust,no_run
if let Some(limit) = stackpulse::record::max_sample_rate() {
    println!("kernel cap: {limit}");
}
```

## Poll without dropping samples

Call `poll` regularly while the target runs:

```rust,no_run
# use std::time::Duration;
# use stackpulse::{Pid, Recorder};
# fn run(pid: Pid, mut recorder: Recorder) -> stackpulse::Result<()> {
while recorder.process_is_active(pid)? {
    recorder.poll(Duration::from_millis(100))?;
}
let summary = recorder.finish()?;
# Ok(())
# }
```

The recorder does not drain in the background: if nothing calls
`poll`, the kernel buffers fill and samples are dropped. `poll` waits for at
most the supplied timeout, then drains every ready perf buffer and writes the
resulting spool records. `finish` disables sampling and performs one final
drain before flushing.

An existing event loop can check
[`Recorder::has_pending_events`](crate::Recorder::has_pending_events), then
call `poll(Duration::ZERO)` to drain without blocking.

## Process a profile while recording

Create a tail from a file-backed recorder, then process every complete batch
after flushing the writer:

```rust,no_run
# use std::time::Duration;
# use stackpulse::{Pid, Recorder, Symbolizer, Tail};
# fn run(pid: Pid, mut recorder: Recorder) -> stackpulse::Result<()> {
fn process_visible(tail: &mut Tail, symbolizer: &mut Symbolizer) -> stackpulse::Result<()> {
    loop {
        let batch = tail.poll()?;
        symbolizer.update(&batch)?;
        for stack in batch.stacks() {
            for frame in symbolizer.resolve(stack)? {
                consume(frame);
            }
        }
        if !batch.has_more() {
            return Ok(());
        }
    }
}

let mut tail = recorder.tail()?;
let mut symbolizer = tail.symbolizer().build()?;

while recorder.process_is_active(pid)? {
    recorder.poll(Duration::from_millis(100))?;
    recorder.flush()?;
    process_visible(&mut tail, &mut symbolizer)?;
}

recorder.finish()?;
process_visible(&mut tail, &mut symbolizer)?;
# Ok(())
# }
# fn consume(_: &stackpulse::profile::ResolvedFrame) {}
```

`Recorder::tail` can be called once. It transfers the recorder's retained
exact-image handles to the reader so deleted or replaced mappings can still be
symbolized from the file that was actually sampled. `Tail::open` is available
when the writer lives elsewhere, but then only paths recorded in the spool are
available.

After a batch is dropped, `tail.discard_consumed()` can release the filesystem
blocks occupied by records that will not be read again. This makes the spool
disposable: the active tail can continue, but the file can no longer be opened
or replayed from the beginning. If the filesystem does not support hole
punching, the method returns an unsupported-operation error.

The example uses StackPulse's internal stack cache. If the application keeps
prepared stacks itself, configure `StackCache::External`, consume the
`Invalidation` returned by every `update`, and do not cache a resolved stack
when `ResolvedStack::is_cacheable()` is false.

## Profile more than one process

After attaching the first PID, add the others:

```rust,no_run
use stackpulse::AttachMode;
# fn run(mut recorder: stackpulse::Recorder, other_pid: u32) -> Result<(), Box<dyn std::error::Error>> {
let other_pid = stackpulse::Pid::try_from(other_pid)?;
recorder.attach_process(other_pid, AttachMode::StopWhileAttaching)?;
# Ok(())
# }
```

To pick up everything under a known root:

```rust,no_run
# use stackpulse::AttachMode;
# fn run(mut recorder: stackpulse::Recorder, root_pid: stackpulse::Pid) -> Result<(), Box<dyn std::error::Error>> {
for child in stackpulse::children::discover_all_descendants(root_pid) {
    recorder.attach_process(child, AttachMode::StopWhileAttaching)?;
}
# Ok(())
# }
```

## Follow children created after recording starts

Turn on child inheritance:

```rust,no_run
let options = stackpulse::RecorderOptions::default().inherit_children(true);
```

The recorder watches for forks, clones the parent's module state, and opens
the new process. Children that existed before recording started aren't picked
up automatically; attach them yourself.

## Catch threads created later

Perf inheritance usually catches new threads. When it doesn't (or you've
deliberately turned it off to limit fan-out), refresh periodically:

```rust,no_run
# fn run(mut recorder: stackpulse::Recorder, pid: stackpulse::Pid) -> std::io::Result<()> {
recorder.refresh_threads(pid)?;
# Ok(())
# }
```

This scans `/proc/<pid>/task` and opens events for threads it hasn't seen.
Run it from a slow maintenance tick, not the hot loop.

## Resolve symbols

One symbolizer per profile, reused for every sample:

```rust,no_run
# fn run() -> Result<(), Box<dyn std::error::Error>> {
let reader = stackpulse::Snapshot::open("profile.spool")?;
let mut symbolizer = reader.symbolizer().build()?;

for stack in reader.stacks() {
    for frame in symbolizer.resolve(stack)? {
        // render or aggregate
        let _ = frame.display_name();
    }
}
# Ok(())
# }
```

`resolve` returns borrowed frames from the symbolizer's cache. With the
default [`StackCache::Internal`](crate::StackCache::Internal), repeated stacks
reuse compact frame IDs instead of allocating another frame vector.

[`FrameFlags::HIDDEN_DEFAULT`](crate::profile::FrameFlags::HIDDEN_DEFAULT) marks frames
that a profiler may hide in its default view. [`SymbolOrigin`](crate::profile::SymbolOrigin)
distinguishes resolved symbols from address-only fallbacks.

## Use your own symbolizer

If your application already owns symbolization, skip [`Symbolizer`](crate::Symbolizer)
entirely. [`SampleStack::contexts`](crate::spool::SampleStack::contexts) yields each raw frame together with the
module mapping recorded at capture time, which is everything an external
symbolizer needs:

```rust,no_run
# fn run() -> Result<(), Box<dyn std::error::Error>> {
let reader = stackpulse::Snapshot::open("profile.spool")?;

for stack in reader.stacks() {
    for context in stack.contexts() {
        let frame = context.frame;
        let module = context.module;
        // Resolve `frame.abs_ip` using your own native, JIT, or kernel symbolizer.
        // `module` is only the recorded mapping context.
    }
}
# Ok(())
# }
```

When raw addresses and sample metadata are enough, `frames()` is lighter
because it skips the module lookup:

```rust,no_run
# fn run(reader: &stackpulse::Snapshot) {
for sample_stack in reader.stacks() {
    for frame in sample_stack.frames() {
        let _ = frame.abs_ip;
    }
}
# }
```

## Python frames

`Symbolizer` reads Python perf maps when the runtime emits them. For
modern CPython:

```sh
PYTHONPERFSUPPORT=1 python3 -X perf app.py
```

The default symbolizer allows perf-map lookup for any PID, so nothing extra
is needed beyond running the target with perf support enabled.

The spool file only stores Python runtime markers, not the perf-map content.
For later or remote symbolization, copy the `perf-<pid>.map` files into a
directory and pass that directory to `SymbolizerBuilder::perf_map_dir`.

To avoid stale perf maps from PID reuse, restrict lookup to processes the
recorder last saw as Python runtimes:

```rust,no_run
# fn run(reader: &stackpulse::Snapshot) -> stackpulse::Result<()> {
let mut python_pids = std::collections::BTreeSet::new();
for runtime in reader.python_runtime_records() {
    if runtime.is_python_runtime {
        python_pids.insert(runtime.process_id);
    } else {
        python_pids.remove(&runtime.process_id);
    }
}

let mut symbolizer = reader.symbolizer()
    .perf_maps_for(python_pids)
    .build()?;
# Ok(())
# }
```

The loop retains only processes whose latest recorded status is Python. This
avoids accepting an older Python status after a PID is reused.

Or skip perf maps entirely:

```rust,no_run
# fn run(reader: &stackpulse::Snapshot) -> stackpulse::Result<()> {
let mut symbolizer = reader.symbolizer()
    .disable_perf_maps()
    .build()?;
# Ok(())
# }
```

## Kernel frames

Set `include_kernel`:

```rust,no_run
let options = stackpulse::RecorderOptions::default().include_kernel(true);
```

Kernel frames come from perf callchains. User frames go through the native
DWARF unwinder, and the event excludes user callchains. If the kernel
unexpectedly supplies user callchain frames anyway, the recorder discards
and counts them in `ignored_user_callchain_frames`.

After attach, check whether kernel sampling actually stuck:

```rust,no_run
# fn run(recorder: &stackpulse::Recorder) {
let summary = recorder.summary();
if !summary.kernel_enabled {
    eprintln!("fell back to user-only frames");
}
# }
```

Kernel names come from `/proc/kallsyms` when readable; otherwise kernel
frames render as addresses.

For cross-host analysis, preserve the recording host's address-bearing
`kallsyms` data and select it explicitly:

```rust,no_run
use stackpulse::symbolize::KernelSymbolSource;
# fn run(reader: &stackpulse::Replay) -> stackpulse::Result<()> {
let symbolizer = reader
    .symbolizer()
    .kernel_symbols(KernelSymbolSource::File("recording.kallsyms".into()))
    .build()?;
# let _ = symbolizer;
# Ok(())
# }
```

Use `KernelSymbolSource::Disabled` when resolving against the analysis host's
kernel would be misleading.

## Diagnose bad profiles

Call `finish` and inspect its [`RecordingSummary`](crate::RecordingSummary):

```rust,no_run
# fn run(recorder: stackpulse::Recorder) -> std::io::Result<()> {
let summary = recorder.finish()?;
println!("events: {}",   summary.sample_events);
println!("written: {}",  summary.samples);
println!("lost: {}",     summary.lost_events);
println!("empty: {}",    summary.empty_stack_samples);
println!("truncated: {}", summary.truncated_frame_markers);
println!("errors: {}",   summary.error_stats.total());
println!("frame-pointer fallbacks: {}", summary.unwind_fallbacks.total());
# Ok(())
# }
```

Reading the numbers:

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| `sample_events > samples` | Samples lacked PIDs, TIDs, timestamps, or frames. | Look at the specific skip counters. |
| High `lost_events` | Ring buffers overran. | Lower the sample rate, poll more often, reduce fan-out. |
| High `empty_stack_samples` | Register/stack capture failed, or unwind produced nothing. | Check `summary.error_stats`. |
| Lots of truncation | `stack_size` too small. | Bump it, up to [`MAX_SAMPLE_USER_STACK`](crate::record::MAX_SAMPLE_USER_STACK). |
| Mostly address-only frames | No symbols or mappings available. | Keep the binaries; symbolize on a host that has them. |

For a breakdown:

```rust,no_run
# fn run(summary: &stackpulse::RecordingSummary) {
for (kind, count) in summary.error_stats.nonzero_counts() {
    println!("{}: {count}", kind.description());
}
for (kind, count) in summary.unwind_fallbacks.nonzero_counts() {
    println!("fallback {kind:?}: {count}");
}
# }
```

## Permission failures

Permission errors can come from perf events, `/proc`, kernel-frame capture, or
`/proc/kallsyms`. Try the least invasive changes first:

- Profile a process you own.
- Drop `include_kernel`.
- Cap your request at or below `stackpulse::record::max_sample_rate()`.
- Grant `CAP_PERFMON` (or whatever your kernel requires) to the profiler binary.
- Relax `perf_event_paranoid` in test environments.

If only kernel sampling is denied,
[`Recorder::attach`](crate::Recorder::attach) retries in user-only mode
and sets `summary.kernel_enabled` to `false`.
