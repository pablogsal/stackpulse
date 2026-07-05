# Recipes

Self-contained snippets for the recurring tweaks you make once the basic
record-then-symbolize loop is up: choosing recording options, attaching to
a running process, replaying a spool you saved earlier, swapping in a
custom symbolizer, and handling errors that come back from the recorder.

## Pick recording options

Start conservative:

```rust,no_run
use stackpulse::PerfRecorderOptions;

let options = PerfRecorderOptions {
    frequency: 99,
    stack_size: 60 * 1024,
    include_kernel: false,
    inherit_child_processes: false,
    ..Default::default()
};
```

Knobs:

| Field | When to change it | What it costs |
| --- | --- | --- |
| `frequency` | Need more or fewer samples per second. | Higher rates raise CPU overhead and increase the chance of lost events under load. |
| `stack_size` | Stacks are getting truncated. | More memory copied per sample. Capped at [`MAX_SAMPLE_USER_STACK`]. |
| `include_kernel` | Want syscall, scheduler, or kernel-lock attribution. | Usually needs extra privileges. If only kernel sampling is denied, [`PerfRecorder::attach`] retries user-only and reports `summary.kernel_enabled = false`. |
| `inherit_child_processes` | Forked children are part of the workload. | Opens more perf events and adds bookkeeping per child. |
| `start_timestamp_us` | Aligning the profile to an external clock or trace. | Metadata only; read back through [`PerfSpoolReader::timestamp_us`]. |
| `sample_interval_us` | UI or export format wants an interval hint. | Metadata only; does not drive kernel sampling. |

Check the kernel cap before asking for an aggressive rate:

```rust,no_run
if let Some(limit) = stackpulse::max_sample_rate() {
    println!("kernel cap: {limit}");
}
```

## Drain without dropping samples

Call `consume_available` inside the loop and once more before `finish`:

```rust,no_run
# use stackpulse::PerfRecorder;
# fn run(pid: u32, mut recorder: PerfRecorder) -> std::io::Result<()> {
while recorder.process_is_active(pid as i32) {
    recorder.wait()?;
    recorder.consume_available()?;
}
recorder.consume_available()?;
let summary = recorder.finish()?;
# Ok(())
# }
```

Draining is mandatory. A recorder that you only hold onto will not write
anything to the spool: `wait` parks the thread until perf data arrives, and
`consume_available` is what turns that data into spool records. If you
already have an event loop, run `wait` from a worker thread or poll
[`PerfRecorder::has_pending_events`] from the main loop and drain when it
returns `true`.

## Profile more than one process

After attaching the first PID, add the others:

```rust,no_run
use stackpulse::AttachMode;
# fn run(mut recorder: stackpulse::PerfRecorder, other_pid: u32) -> std::io::Result<()> {
recorder.open_process(other_pid, AttachMode::StopAttachEnableResume)?;
# Ok(())
# }
```

To pick up everything under a known root:

```rust,no_run
# use stackpulse::AttachMode;
# fn run(mut recorder: stackpulse::PerfRecorder, root_pid: i32) -> std::io::Result<()> {
for child in stackpulse::children::discover_all_descendants(root_pid) {
    recorder.open_process(child as u32, AttachMode::StopAttachEnableResume)?;
}
# Ok(())
# }
```

## Follow children created after recording starts

Turn on `inherit_child_processes`:

```rust,no_run
let options = stackpulse::PerfRecorderOptions {
    inherit_child_processes: true,
    ..Default::default()
};
```

The recorder watches for forks, clones the parent's module state, and opens
the new process. Children that existed before recording started aren't picked
up automatically; attach them yourself.

## Catch threads created later

Perf inheritance usually catches new threads. When it doesn't (or you've
deliberately turned it off to limit fan-out), refresh periodically:

```rust,no_run
# fn run(mut recorder: stackpulse::PerfRecorder, pid: u32) -> std::io::Result<()> {
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
let reader = stackpulse::PerfSpoolReader::open("profile.spool")?;
let mut symbolizer = stackpulse::PerfSymbolizer::for_spool(&reader);

for stack in reader.sample_stacks() {
    symbolizer.for_each_sample_stack(stack, |frame| {
        // render or aggregate
        let _ = frame.func_name();
    });
}
# Ok(())
# }
```

`for_each_sample_stack` streams borrowed frames straight out of the
symbolizer's cache. It only stores compact frame ids per repeated
`(process_id, stack_id)`, so callers that render or aggregate inline never
pay for materializing a full resolved-stack `Vec`.

Display policy is your call. Most UIs hide [`FrameFlags::HIDDEN_DEFAULT`] by
default, group frames by [`FrameKind`], and surface [`SymbolOrigin`] in
detail views so users can tell ELF symbols from address-only fallbacks.

## Use your own symbolizer

If your application already owns symbolization, skip [`PerfSymbolizer`] and
read raw frames plus their recorded module context directly:

```rust,no_run
# fn run() -> Result<(), Box<dyn std::error::Error>> {
let reader = stackpulse::PerfSpoolReader::open("profile.spool")?;

for sample in reader.samples() {
    for context in reader.stack_frame_contexts(sample.process_id, sample.stack_id)? {
        let frame = context.frame;
        let module = context.module;
        // Resolve `frame.abs_ip` using your own native, JIT, or kernel symbolizer.
        // `module` is only the recorded mapping context.
    }
}
# Ok(())
# }
```

Use `sample_stacks()` when you only need raw frames and sample metadata:

```rust,no_run
# fn run(reader: &stackpulse::PerfSpoolReader) {
for sample_stack in reader.sample_stacks() {
    for frame in sample_stack.frames {
        let _ = frame.abs_ip;
    }
}
# }
```

This is the path to use when you have your own debug-dir, debuginfod,
Python perf-map, JIT, or kernel-symbol pipeline and want stackpulse to stay
out of the way.

## Python frames

`PerfSymbolizer` reads Python perf maps when the runtime emits them. For
modern CPython:

```sh
PYTHONPERFSUPPORT=1 python3 -X perf app.py
```

The default symbolizer allows perf-map lookup for any PID:

```rust,no_run
# fn run(reader: &stackpulse::PerfSpoolReader) {
let mut symbolizer = stackpulse::PerfSymbolizer::new(reader.modules());
# }
```

The spool file only stores Python runtime markers, not the perf-map content
itself. If you want to symbolize later (on another machine, or after the
runtime has cleaned up `/tmp/perf-<pid>.map`), copy those maps next to the
spool.

To avoid stale perf maps from PID reuse, restrict lookup to processes the
recorder last saw as Python runtimes:

```rust,no_run
# fn run(reader: &stackpulse::PerfSpoolReader) {
let mut python_pids = std::collections::BTreeSet::new();
for exec in reader.process_execs() {
    if exec.is_python_runtime {
        python_pids.insert(exec.process_id);
    } else {
        python_pids.remove(&exec.process_id);
    }
}

let mut symbolizer = stackpulse::PerfSymbolizer::with_perf_map_processes(
    reader.modules(), python_pids,
);
# }
```

`PerfSymbolizer::for_spool_with_recorded_python_perf_maps(reader)` is a
broader convenience helper: it allows any PID that was ever marked as a Python
runtime in the spool.

Or skip perf maps entirely:

```rust,no_run
# fn run(reader: &stackpulse::PerfSpoolReader) {
let mut symbolizer = stackpulse::PerfSymbolizer::with_perf_maps(reader.modules(), false);
# }
```

## Kernel frames

Set `include_kernel`:

```rust,no_run
let options = stackpulse::PerfRecorderOptions {
    include_kernel: true,
    ..Default::default()
};
```

Kernel frames come from perf callchains. User frames still go through the
native DWARF unwinder; the user side of the perf callchain is only consulted
when DWARF unwinding stops early or returns nothing. Anything from the user
callchain that the DWARF result already covered is counted as
`ignored_user_callchain_frames` in the summary.

After attach, check whether kernel sampling actually stuck:

```rust,no_run
# fn run(recorder: &stackpulse::PerfRecorder) {
let summary = recorder.summary();
if !summary.kernel_enabled {
    eprintln!("fell back to user-only frames");
}
# }
```

Kernel names come from `/proc/kallsyms` when readable; otherwise kernel
frames render as addresses.

## Diagnose bad profiles

`PerfSummary` is the first place to look:

```rust,no_run
# fn run(recorder: stackpulse::PerfRecorder) -> std::io::Result<()> {
let summary = recorder.finish()?;
println!("events: {}",   summary.sample_events);
println!("written: {}",  summary.samples);
println!("lost: {}",     summary.lost_events);
println!("empty: {}",    summary.empty_stack_samples);
println!("truncated: {}",summary.truncated_frame_markers);
println!("errors: {}",   summary.error_stats.total());
# Ok(())
# }
```

Reading the numbers:

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| `sample_events > samples` | Samples lacked PIDs, TIDs, timestamps, or frames. | Look at the specific skip counters. |
| High `lost_events` | Ring buffers overran. | Lower `frequency`, drain more often, reduce fan-out. |
| High `empty_stack_samples` | Register/stack capture failed, or unwind produced nothing. | Check `summary.error_stats`. |
| Lots of truncation | `stack_size` too small. | Bump it, up to [`MAX_SAMPLE_USER_STACK`]. |
| Mostly address-only frames | No symbols or mappings available. | Keep the binaries; symbolize on a host that has them. |

For a formatted breakdown:

```rust,no_run
# fn run(summary: &stackpulse::PerfSummary) -> std::fmt::Result {
let mut report = String::new();
stackpulse::ErrorStatsFormatter::new(
    &summary.error_stats, summary.sample_events, summary.samples,
).write_to(&mut report)?;
println!("{report}");
# Ok(())
# }
```

## Permission failures

Permission errors surface when opening perf events, reading `/proc`, asking
for kernel frames, or reading `/proc/kallsyms`. Work down the list:

- Profile a process you own.
- Drop `include_kernel`.
- Cap your request at or below `stackpulse::max_sample_rate()`.
- Grant `CAP_PERFMON` (or whatever your kernel requires) to the profiler binary.
- Relax `perf_event_paranoid` in test environments.

Don't fail the whole recording on the first permission error. If kernel
sampling alone was denied, [`PerfRecorder::attach`] has already retried in
user-only mode and surfaced that through `summary.kernel_enabled`.
