# How-to guides

Use these guides when you already understand the basic recording flow and need
to make a profiler behave correctly in a specific situation.

## Choose recording options

Start with conservative options:

```rust
use stackpulse::PerfRecorderOptions;

let options = PerfRecorderOptions {
    frequency: 99,
    stack_size: 60 * 1024,
    include_kernel: false,
    inherit_child_processes: false,
    ..PerfRecorderOptions::default()
};
```

Tune from there:

| Option | Use it when | Tradeoff |
| --- | --- | --- |
| `frequency` | You need more or fewer samples per second. | Higher values improve temporal detail but increase overhead and lost-event risk. |
| `stack_size` | Native stacks are truncated or unwind errors show stack reads are too small. | Larger stacks increase per-sample memory copied by the kernel. Must not exceed `MAX_SAMPLE_USER_STACK`. |
| `include_kernel` | You need syscall, scheduler, driver, or kernel lock attribution. | May require extra permissions. If the attach only fails because kernel sampling is denied, `PerfRecorder::attach` retries user-only and sets `summary.kernel_enabled` to `false`. |
| `inherit_child_processes` | Forked child processes are part of the workload. | Opens more perf events and increases bookkeeping. |
| `start_timestamp_us` | You need profile timestamps aligned to an external clock or trace. | Stored as profile metadata and used by `PerfSpoolReader::timestamp_us`. |
| `sample_interval_us` | Your UI or export format expects an interval hint. | Stored as metadata; it does not drive kernel sampling. |

Check the kernel frequency limit before requesting aggressive sample rates:

```rust
if let Some(limit) = stackpulse::max_sample_rate() {
    println!("kernel max sample rate: {limit}");
}
```

## Drain a recorder without losing queued data

Always call `consume_available` in the recording loop and once more before
`finish`:

```rust
while recorder.process_is_active(pid as i32) {
    recorder.wait()?;
    recorder.consume_available()?;
}

recorder.consume_available()?;
let summary = recorder.finish()?;
```

If your application has its own event loop, call `wait` from a blocking worker
or poll periodically and use `has_pending_events` to decide whether a drain is
already useful. The important invariant is that a recorder is not just a handle:
it must be drained for samples to reach the spool file.

## Attach to more than one process

Create the recorder for the first process, then add more processes:

```rust
use stackpulse::AttachMode;

recorder.open_process(other_pid, AttachMode::StopAttachEnableResume)?;
```

`open_process` registers the process, discovers existing executable mappings,
and enables sampling when `StopAttachEnableResume` is used. This is useful for
profilers that discover a process tree themselves or attach to several service
workers.

To discover descendants of a known root:

```rust
for child in stackpulse::children::discover_all_descendants(root_pid) {
    recorder.open_process(child as u32, AttachMode::StopAttachEnableResume)?;
}
```

## Follow child processes created after recording starts

Set `inherit_child_processes`:

```rust
let options = stackpulse::PerfRecorderOptions {
    inherit_child_processes: true,
    ..stackpulse::PerfRecorderOptions::default()
};
```

When enabled, `stackpulse` listens for fork events, clones module state from the
parent, opens the new process, and records future samples for it. Existing
descendants are not retroactively added; attach them explicitly if they were
created before the recording started.

## Capture newly-created threads

`stackpulse` normally asks perf to inherit thread events. On systems or workloads
where inheritance is unavailable or the event fan-out would be excessive, use
periodic refresh:

```rust
recorder.refresh_threads(pid)?;
```

Call this from a low-frequency maintenance tick, not a hot path. The method
scans `/proc/<pid>/task` and opens perf events for threads that were not already
tracked.

## Resolve symbols efficiently

Create one symbolizer per profile and reuse it:

```rust
let reader = stackpulse::PerfSpoolReader::open("profile.spool")?;
let mut symbolizer = stackpulse::PerfSymbolizer::new(reader.modules());
let mut raw_frames = Vec::new();

for sample in reader.samples() {
    reader.stack_frames(sample.stack_id, &mut raw_frames)?;
    let frames = symbolizer.stack_to_cached_frames(
        sample.process_id,
        sample.stack_id,
        &raw_frames,
    );
    // Render or aggregate frames here.
}
```

`stack_to_cached_frames` caches by `(process_id, stack_id)`. That matters because
profiles often contain many samples with the same stack ID.

Frame display policy is application-specific. A UI will commonly hide frames
with `FrameFlags::HIDDEN_DEFAULT` by default, group by `FrameKind`, and expose
`SymbolOrigin` so users can distinguish debug symbols from address fallbacks.

## Get Python frames

`PerfSymbolizer` can use Python perf maps when the Python runtime emits them.
Launch Python with either `-X perf` or `PYTHONPERFSUPPORT=1`; using both is fine:

```sh
PYTHONPERFSUPPORT=1 python3 -X perf app.py
```

At read time, the default symbolizer permits perf-map lookups for all processes:

```rust
let mut symbolizer = stackpulse::PerfSymbolizer::new(reader.modules());
```

The spool file stores Python-runtime process markers, not the contents of the
perf-map file. If you need to symbolize later on another machine or after the
runtime deletes `/tmp/perf-<pid>.map`, copy those perf-map files as profiling
artifacts alongside the spool file.

If stale `/tmp/perf-<pid>.map` files are a concern, restrict lookup to processes
that your recorder most recently marked as Python runtimes:

```rust
let mut python_pids = std::collections::BTreeSet::new();
for exec in reader.process_execs() {
    if exec.is_python_runtime {
        python_pids.insert(exec.process_id);
    } else {
        python_pids.remove(&exec.process_id);
    }
}

let mut symbolizer = stackpulse::PerfSymbolizer::with_perf_map_processes(
    reader.modules(),
    python_pids,
);
```

Disable perf maps entirely when you need purely native symbolization:

```rust
let mut symbolizer = stackpulse::PerfSymbolizer::with_perf_maps(reader.modules(), false);
```

## Include kernel frames

Set `include_kernel`:

```rust
let options = stackpulse::PerfRecorderOptions {
    include_kernel: true,
    ..stackpulse::PerfRecorderOptions::default()
};
```

Kernel frames are captured through perf callchains, while user frames are
captured through copied registers and stack bytes. When kernel sampling is
enabled, user callchain frames from perf are ignored so the native unwinder is
still the source of user-space frames.

After attach, inspect:

```rust
let summary = recorder.summary();
if !summary.kernel_enabled {
    eprintln!("recording fell back to user-space frames only");
}
```

Resolved kernel names come from `/proc/kallsyms` when readable. Otherwise
kernel frames fall back to address-like names.

## Diagnose missing or low-quality samples

Use `PerfSummary` first:

```rust
let summary = recorder.finish()?;
println!("events seen: {}", summary.sample_events);
println!("samples written: {}", summary.samples);
println!("lost events: {}", summary.lost_events);
println!("empty stacks: {}", summary.empty_stack_samples);
println!("truncated markers: {}", summary.truncated_frame_markers);
println!("errors: {}", summary.error_stats.total());
```

Common interpretations:

| Symptom | Likely cause | Next step |
| --- | --- | --- |
| `sample_events > samples` | Samples were skipped because they lacked task IDs, timestamps, or frames. | Inspect the specific summary counters. |
| High `lost_events` | Ring buffers were overrun. | Lower frequency, drain more often, or reduce target fan-out. |
| High `empty_stack_samples` | Register or stack capture failed, or frames could not be resolved into usable records. | Check `summary.error_stats`. |
| High native stack truncation | `stack_size` is too small for the workload's call depth. | Increase `stack_size` up to `MAX_SAMPLE_USER_STACK`. |
| Address-only frames | Symbol files or mappings were unavailable. | Preserve binaries/debug files and resolve on the same host when possible. |

For formatted error statistics:

```rust
let mut report = String::new();
stackpulse::ErrorStatsFormatter::new(
    &summary.error_stats,
    summary.sample_events,
    summary.samples,
)
.write_to(&mut report)?;
println!("{report}");
```

## Handle permission failures

Permission failures usually appear when opening perf events, reading target
metadata from `/proc`, including kernel frames, or reading kernel symbols.
Practical responses are:

- Profile a process owned by the same user.
- Lower `include_kernel` to `false`.
- Request a sample rate at or below `stackpulse::max_sample_rate()`.
- Run in an environment where `perf_event_open` is allowed.
- Grant the profiler process the capabilities your system requires for perf
  capture, such as `CAP_PERFMON` on newer Linux systems.

Do not treat all permission failures as fatal for user-space profiling. If the
only denied operation was kernel frame capture, `PerfRecorder::attach` may have
already retried without kernel frames.
