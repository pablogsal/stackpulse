# Recipes

Short snippets for things you usually want to do once you've got the basic
recording loop working.

## Pick recording options

Start conservative:

```rust,ignore
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
| `frequency` | Need more or fewer samples per second. | Higher = more overhead and more lost events under load. |
| `stack_size` | Stacks are getting truncated. | More memory copied per sample. Cap is [`MAX_SAMPLE_USER_STACK`]. |
| `include_kernel` | Want syscall, scheduler, or kernel-lock attribution. | Often needs extra perms. If only kernel sampling is denied, [`PerfRecorder::attach`] retries user-only and reports `summary.kernel_enabled = false`. |
| `inherit_child_processes` | Forked children are part of the workload. | Opens more perf events; more bookkeeping. |
| `start_timestamp_us` | Aligning the profile to an external clock or trace. | Just metadata, used by [`PerfSpoolReader::timestamp_us`]. |
| `sample_interval_us` | UI or export format wants an interval hint. | Metadata only; doesn't drive kernel sampling. |

Check the kernel cap before asking for an aggressive rate:

```rust,ignore
if let Some(limit) = stackpulse::max_sample_rate() {
    println!("kernel cap: {limit}");
}
```

## Drain without dropping samples

Call `consume_available` inside the loop and once more before `finish`:

```rust,ignore
while recorder.process_is_active(pid as i32) {
    recorder.wait()?;
    recorder.consume_available()?;
}
recorder.consume_available()?;
let summary = recorder.finish()?;
```

A recorder is not just a handle. If you don't drain it, samples don't make
it to the spool file. If you have your own event loop, run `wait` from a
worker thread or poll with [`PerfRecorder::has_pending_events`] before
draining.

## Profile more than one process

After attaching the first PID, add the others:

```rust,ignore
use stackpulse::AttachMode;

recorder.open_process(other_pid, AttachMode::StopAttachEnableResume)?;
```

To pick up everything under a known root:

```rust,ignore
for child in stackpulse::children::discover_all_descendants(root_pid) {
    recorder.open_process(child as u32, AttachMode::StopAttachEnableResume)?;
}
```

## Follow children created after recording starts

Turn on `inherit_child_processes`:

```rust,ignore
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

```rust,ignore
recorder.refresh_threads(pid)?;
```

This scans `/proc/<pid>/task` and opens events for threads it hasn't seen.
Run it from a slow maintenance tick, not the hot loop.

## Resolve symbols

One symbolizer per profile, reused for every sample:

```rust,ignore
let reader = stackpulse::PerfSpoolReader::open("profile.spool")?;
let mut symbolizer = stackpulse::PerfSymbolizer::new(reader.modules());

for sample in reader.samples() {
    let raw = reader.stack_frame_refs(sample.stack_id)?;
    let frames = symbolizer.stack_refs_to_cached_frames(
        sample.process_id, sample.stack_id, raw,
    );
    // render or aggregate
}
```

`stack_refs_to_cached_frames` caches by `(process_id, stack_id)`, which matters
because profiles tend to contain the same stacks over and over.

Display policy is up to you. A UI typically hides
[`FrameFlags::HIDDEN_DEFAULT`], groups by [`FrameKind`], and shows
[`SymbolOrigin`] in detail views so users can tell ELF symbols from
address-only fallbacks.

## Python frames

`PerfSymbolizer` reads Python perf maps when the runtime emits them. For
modern CPython:

```sh
PYTHONPERFSUPPORT=1 python3 -X perf app.py
```

The default symbolizer allows perf-map lookup for any PID:

```rust,ignore
let mut symbolizer = stackpulse::PerfSymbolizer::new(reader.modules());
```

The spool file only stores Python runtime markers, not the perf-map content
itself. If you want to symbolize later (on another machine, or after the
runtime has cleaned up `/tmp/perf-<pid>.map`), copy those maps next to the
spool.

To avoid stale perf maps from PID reuse, restrict lookup to processes the
recorder last saw as Python runtimes:

```rust,ignore
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
```

Or skip perf maps entirely:

```rust,ignore
let mut symbolizer = stackpulse::PerfSymbolizer::with_perf_maps(reader.modules(), false);
```

## Kernel frames

```rust,ignore
let options = stackpulse::PerfRecorderOptions {
    include_kernel: true,
    ..Default::default()
};
```

Kernel frames come from perf callchains; user frames still come from the
native unwinder. When kernel sampling is on, user callchain frames from perf
are dropped to avoid duplicating the unwinder's work. They show up as
`ignored_user_callchain_frames` in the summary.

After attach, check whether kernel sampling actually stuck:

```rust,ignore
let summary = recorder.summary();
if !summary.kernel_enabled {
    eprintln!("fell back to user-only frames");
}
```

Kernel names come from `/proc/kallsyms` when readable; otherwise kernel
frames render as addresses.

## Diagnose bad profiles

`PerfSummary` is the first place to look:

```rust,ignore
let summary = recorder.finish()?;
println!("events: {}",   summary.sample_events);
println!("written: {}",  summary.samples);
println!("lost: {}",     summary.lost_events);
println!("empty: {}",    summary.empty_stack_samples);
println!("truncated: {}",summary.truncated_frame_markers);
println!("errors: {}",   summary.error_stats.total());
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

```rust,ignore
let mut report = String::new();
stackpulse::ErrorStatsFormatter::new(
    &summary.error_stats, summary.sample_events, summary.samples,
).write_to(&mut report)?;
println!("{report}");
```

## Permission failures

Most permission errors show up when opening perf events, reading `/proc`,
asking for kernel frames, or reading `/proc/kallsyms`. Things to try:

- Profile a process you own.
- Drop `include_kernel`.
- Request a rate at or below `stackpulse::max_sample_rate()`.
- Grant `CAP_PERFMON` (or whatever your kernel wants) to the profiler binary.
- Loosen `perf_event_paranoid` in test environments.

Don't bail out on every permission error. If only kernel sampling was denied,
[`PerfRecorder::attach`] has already retried in user-only mode.
