# Reference

This page documents the public `stackpulse` API. For exact trait bounds and
crate-level examples, build rustdoc with:

```sh
make doc
```

## Module map

The crate root re-exports the main profiling types:

```rust
use stackpulse::{
    AttachMode, PerfRecorder, PerfRecorderOptions, PerfSpoolReader, PerfSymbolizer,
};
```

Public modules:

| Module | Purpose |
| --- | --- |
| `stackpulse::process` | Launch a process suspended before `execve` so profiling starts at process birth. |
| `stackpulse::children` | Discover descendant PIDs through `/proc`. |
| `stackpulse::profile` | Resolved frame and symbol data types. |
| `stackpulse::state` | Process existence, exit watching, and signal helpers. |

## Recording

### `PerfRecorder`

`PerfRecorder` records stack samples for one or more Linux processes and writes a
spool file.

| Method | Purpose |
| --- | --- |
| `PerfRecorder::attach(pid, output, attach_mode, options)` | Open perf events for `pid`, create the spool writer, register known mappings, and start recording when appropriate. |
| `consume_available()` | Drain readable perf events, update module/process state, unwind samples, and write spool records. |
| `wait()` | Wait briefly for perf data to become readable. |
| `open_process(pid, attach_mode)` | Add another process to the same recording. |
| `refresh_threads(pid)` | Discover and open new threads when perf inheritance is unavailable or intentionally avoided. |
| `disable()` | Disable sampling for all attached perf events. |
| `has_pending_events()` | Return whether perf data is already queued for consumption. |
| `summary()` | Return a snapshot of recording counters. |
| `active_processes()` | Return PIDs still believed to be alive. |
| `process_is_active(pid)` | Return whether one PID is still believed to be alive. |
| `has_active_processes_except(pid)` | Return whether any active process other than `pid` remains. |
| `active_processes_except(pid)` | Return active PIDs excluding `pid`. |
| `finish()` | Flush the spool file and return final counters. Consumes the recorder. |

The recorder must be drained. Opening a recorder and sleeping without
`consume_available` lets kernel buffers fill and prevents samples from reaching
the spool file.

### `AttachMode`

| Variant | Use case |
| --- | --- |
| `StopAttachEnableResume` | Attach to an already-running process. The process is briefly stopped while perf events are opened, then resumed. |
| `AttachWithEnableOnExec` | Attach to a process that has been forked but not yet executed. Use with `process::SuspendedLaunchedProcess`. |

### `PerfRecorderOptions`

| Field | Type | Meaning |
| --- | --- | --- |
| `frequency` | `u32` | Requested samples per second. Must not exceed `/proc/sys/kernel/perf_event_max_sample_rate` when that limit is readable. |
| `stack_size` | `u32` | Number of user stack bytes copied per sample. Must not exceed `MAX_SAMPLE_USER_STACK`. |
| `include_kernel` | `bool` | Include kernel frames when permissions allow it. |
| `inherit_child_processes` | `bool` | Follow child processes created after recording starts. |
| `start_timestamp_us` | `u64` | Timeline anchor stored in the spool file. |
| `sample_interval_us` | `u64` | Optional interval metadata stored in the spool file. |

`Default` sets numeric fields to `0` and boolean fields to `false`. For real
recordings, set at least `frequency` and `stack_size`.

### `PerfSummary`

`PerfSummary` is a counter snapshot for recording quality and diagnostics.

| Field | Meaning |
| --- | --- |
| `sample_events` | Raw perf sample records seen. |
| `samples` | Samples successfully written to the spool file. |
| `lost_events` | Records the kernel reported as lost. |
| `kernel_enabled` | Whether kernel frame capture remained enabled after attach. |
| `missing_pid_samples` | Samples skipped because the process ID was missing or invalid. |
| `missing_tid_samples` | Samples skipped because the thread ID was missing or invalid. |
| `idle_tid_samples` | Samples skipped because they were attributed to idle thread ID `0`. |
| `missing_timestamp_samples` | Samples skipped because perf did not provide a timestamp. |
| `empty_stack_samples` | Samples skipped because no usable frames were produced. |
| `truncated_frame_markers` | Internal truncation markers observed while unwinding. |
| `ignored_user_callchain_frames` | User callchain frames ignored when kernel callchains were enabled. |
| `error_stats` | Per-kind sample error counters. |

## Reading spool files

### `PerfSpoolReader`

`PerfSpoolReader::open(path)` reads the entire spool file into memory and
validates record references.

| Method | Purpose |
| --- | --- |
| `modules()` | Return recorded executable memory ranges. |
| `samples()` | Return timestamped samples. |
| `process_execs()` | Return process execution markers, including Python runtime on/off markers. |
| `stack_frames(stack_id, out)` | Expand an interned stack ID into raw `FrameRecord` values. Clears `out` first. |
| `timestamp_us(sample)` | Convert a sample timestamp to the profile timeline in microseconds. |

### `ModuleRecord`

| Field | Meaning |
| --- | --- |
| `id` | Stable module ID within the profile. |
| `process_id` | Owning process ID, or a kernel marker for kernel code. |
| `start`, `end` | Runtime address range. |
| `file_offset` | File offset corresponding to `start`. |
| `inode` | Backing file inode when available. |
| `path` | Path or display name. |
| `is_kernel` | Whether the record represents kernel code. |

### `FrameRecord`

| Field | Meaning |
| --- | --- |
| `module_id` | Matched module ID, when known. |
| `rel_ip` | Address relative to the matched module. |
| `abs_ip` | Absolute instruction pointer. |
| `mode` | `FrameMode::User` or `FrameMode::Kernel`. |

### `OwnedSampleRecord`

| Field | Meaning |
| --- | --- |
| `timestamp_ns` | Monotonic perf timestamp in nanoseconds. |
| `process_id` | Process ID for the sampled thread. |
| `thread_id` | Thread ID for the sample. |
| `stack_id` | Interned stack identifier for `PerfSpoolReader::stack_frames`. |

### `ProcessExecRecord`

| Field | Meaning |
| --- | --- |
| `timestamp_ns` | Monotonic timestamp in nanoseconds. |
| `process_id` | Process ID. |
| `is_python_runtime` | Whether the process most recently looked like a Python runtime with perf-map support. A later marker with `false` means the PID should no longer be treated as Python for perf-map lookup. |

## Symbolization

### `PerfSymbolizer`

`PerfSymbolizer` resolves raw frames into displayable frames. Construct one
symbolizer per profile and reuse it.

| Constructor or method | Purpose |
| --- | --- |
| `PerfSymbolizer::new(modules)` | Resolve using ELF/native symbols, kernel symbols, and currently available Python perf maps. |
| `PerfSymbolizer::with_perf_maps(modules, allow_perf_maps)` | Enable or disable Python perf-map lookup globally. |
| `PerfSymbolizer::with_perf_map_processes(modules, processes)` | Allow perf-map lookup only for listed PIDs. |
| `stack_to_cached_frames(process_id, stack_id, frames)` | Resolve a raw stack and cache the result by `(process_id, stack_id)`. |

Resolution order:

1. Python perf map or native JIT perf map from `/tmp/perf-<pid>.map`, when
   allowed and appropriate for the frame.
2. Native ELF symbolization for file-backed user modules.
3. Kernel symbol lookup for kernel frames.
4. Address-only fallback.

### `ResolvedFrame`

`ResolvedFrame` is either:

| Variant | Meaning |
| --- | --- |
| `ResolvedFrame::Python(PythonFrame)` | A Python frame parsed from a perf-map symbol. |
| `ResolvedFrame::Native(NativeFrame)` | A native, kernel, JIT, or address-only frame. |

`ResolvedFrame::func_name()` returns a displayable function name for both
variants.

### `PythonFrame`

| Field or method | Meaning |
| --- | --- |
| `file_name` | Python source filename. |
| `location` | Line and column metadata when available. |
| `func_name` | Python function name. |
| `opcode` | Optional Python opcode. |
| `is_entry` | Whether the frame is an entry marker. |
| `basename()` | Filename without leading directories. |

### `NativeFrame` and `NativeSymbol`

`NativeFrame` carries the resolved symbol plus frame classification:

| Field | Meaning |
| --- | --- |
| `pc` | Program counter. |
| `sp` | Stack pointer when available. Currently `0` for frames produced by the public symbolizer. |
| `symbol` | Optional `NativeSymbol`. Missing means address-only fallback. |
| `is_python_runtime` | Whether this frame belongs to Python runtime machinery. |
| `kind` | `FrameKind::Native`, `Kernel`, or `Unknown`. |
| `origin` | `SymbolOrigin` that explains where the name came from. |
| `flags` | `FrameFlags` for UI policy. |

`NativeSymbol` includes the symbol name, optional source file and line, module
name, module/file basename offsets, module-relative offset, and Python-runtime
helpers such as `is_eval_frame` and `should_ignore`.

### `FrameKind`, `SymbolOrigin`, and `FrameFlags`

| Type | Values |
| --- | --- |
| `FrameKind` | `Python`, `Native`, `Kernel`, `Unknown` |
| `SymbolOrigin` | `Elf`, `PerfMap`, `KernelSymbols`, `AddressOnly` |
| `FrameFlags` | `PYTHON_RUNTIME`, `PYTHON_EVAL`, `HIDDEN_DEFAULT`, `JIT`, `ANONYMOUS` |

UI code commonly hides `HIDDEN_DEFAULT`, labels `JIT`, groups by `FrameKind`,
and exposes `SymbolOrigin` in debug or detail views.

## Process launch and state helpers

### `process::SuspendedLaunchedProcess`

| Method | Purpose |
| --- | --- |
| `launch_in_suspended_state(command_name, command_args, env_vars)` | Fork a child that waits before `execve`. |
| `pid()` | Return the child PID before it has executed. |
| `unsuspend_and_run()` | Allow the child to execute and return `RunningProcess`. |

### `process::RunningProcess`

| Method | Purpose |
| --- | --- |
| `try_wait()` | Non-blocking wait. |
| `wait()` | Blocking wait until process exit. |

### `children`

| Function | Purpose |
| --- | --- |
| `discover_all_descendants(root)` | Discover descendant PIDs using `/proc/<pid>/task/*/children` with a `/proc/*/stat` fallback. |

### `state`

| Function or type | Purpose |
| --- | --- |
| `ProcessExitWatcher::try_new(pid)` | Create a pidfd-based exit watcher. |
| `ProcessExitWatcher::poll()` | Poll for exit without blocking. |
| `process_exists(pid)` | Check whether a process appears alive. |
| `interrupt_process(pid)` | Send `SIGINT`. |
| `kill_process(pid)` | Send `SIGKILL`. |

## Error statistics

`SampleErrorStats` records per-kind sample failures. It is cloneable, resettable,
and can be formatted with `ErrorStatsFormatter`.

| Type or method | Purpose |
| --- | --- |
| `SampleErrorKind` | Enumerates stack, frame parsing, native unwind, merge, and thread-list failures. |
| `SampleErrorStats::record(kind)` | Increment a counter. |
| `SampleErrorStats::record_with_log(kind, context)` | Increment and emit a throttled debug log. |
| `get(kind)` | Read one counter. |
| `total()` | Sum all counters. |
| `has_errors()` | Check if any counter is non-zero. |
| `iter_nonzero()` | Iterate non-zero counters. |
| `reset()` | Clear counters. |
| `ErrorStatsFormatter::new(stats, total_samples, successful_samples)` | Build a display formatter. |
| `write_to(writer)` | Write a grouped report. |

## Constants and helpers

| Item | Meaning |
| --- | --- |
| `MAX_SAMPLE_USER_STACK` | Maximum user stack bytes accepted by the perf sampling configuration. |
| `max_sample_rate()` | Read `/proc/sys/kernel/perf_event_max_sample_rate`, returning `None` if unavailable. |
| `is_python_module(name)` | Return whether a basename looks like a Python executable or libpython name. |
| `path_to_name(path)` | Return a display name from a path. |
| `ModuleImageBase` | Helper for translating runtime AVMA addresses to static VMAs. |
| `PerfFrequencyLimit` | Error payload used when requested frequency exceeds the kernel max sample rate. |

## Spool file invariants

The spool format is append-only and compact:

- Modules, frames, stack nodes, threads, samples, and process exec markers are
  separate record kinds.
- Frames are interned. Repeated frames are stored once.
- Stacks are represented as prefix nodes. Repeated stack suffixes are shared.
- Threads are interned by `(process_id, thread_id)`.
- Sample timestamps are stored as deltas in nanoseconds.
- `timestamp_us` maps sample time to the profile timeline using the stored start
  timestamp and the first sample timestamp.

The on-disk format is an implementation detail. Use `PerfSpoolReader` rather
than parsing spool files directly.
