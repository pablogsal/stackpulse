# Reference

A condensed map of the public surface. Each item links to its full rustdoc
page.

## Module map

The crate root re-exports the recording, reading, and symbolization types:

```rust,no_run
use stackpulse::{
    AttachMode, PerfRecorder, PerfRecorderOptions, PerfSpoolReader, PerfSymbolizer,
};
```

Public modules:

| Module | What it's for |
| --- | --- |
| [`process`] | Launch a process suspended before `execve` so sampling starts at birth. |
| [`children`] | Walk descendant PIDs through `/proc`. |
| [`profile`] | Resolved frames and symbol data types. |
| [`state`] | Process liveness, exit watching, and signal helpers. |

## Recording

### [`PerfRecorder`]

Records stack samples for one or more processes and writes a spool file.

| Method | What it does |
| --- | --- |
| `attach(pid, output, mode, options)` | Open perf events, create the spool, register known mappings, start sampling. |
| `consume_available()` | Drain perf data, update module/process state, unwind, write records. |
| `wait()` | Block briefly for new perf data. |
| `open_process(pid, mode)` | Add another process to the same recording. |
| `refresh_threads(pid)` | Discover new threads when perf inheritance isn't doing it. |
| `disable()` | Stop sampling for all attached events. |
| `has_pending_events()` | Is there perf data ready to drain? |
| `summary()` | Snapshot of recording counters. |
| `process_is_active(pid)` | Is a given PID still alive? |
| `has_active_processes_except(pid)` | Is any PID other than the given one still alive? |
| `finish()` | Flush, return final counters, consume the recorder. |

The recorder is not just a handle. Opening one and never calling
`consume_available` will fill kernel buffers and lose samples.

### [`AttachMode`]

| Variant | Use |
| --- | --- |
| `StopAttachEnableResume` | Attaching to a running process. The target is briefly stopped while events open, then resumed. |
| `AttachWithEnableOnExec` | Attaching to a forked-but-not-yet-exec'd child. Pair with [`process::SuspendedLaunchedProcess`]. |

### [`PerfRecorderOptions`]

| Field | Type | Meaning |
| --- | --- | --- |
| `frequency` | `u32` | Samples per second. Must be ≤ `/proc/sys/kernel/perf_event_max_sample_rate` when readable. |
| `stack_size` | `u32` | User stack bytes copied per sample. Capped at [`MAX_SAMPLE_USER_STACK`]. |
| `include_kernel` | `bool` | Capture kernel frames when allowed. |
| `inherit_child_processes` | `bool` | Follow children forked after recording starts. |
| `start_timestamp_us` | `u64` | Timeline anchor stored in the spool. |
| `sample_interval_us` | `u64` | Optional interval hint stored in the spool. |

`Default` zero-fills everything. For a real recording, set `frequency` and
`stack_size` at minimum.

### [`PerfSummary`]

Counter snapshot for quality checks.

| Field | Meaning |
| --- | --- |
| `sample_events` | Raw perf sample records seen. |
| `samples` | Samples written to the spool. |
| `lost_events` | Kernel-reported losses. |
| `kernel_enabled` | Whether kernel capture stayed on after attach. |
| `missing_pid_samples` / `missing_tid_samples` | Samples dropped for missing IDs. |
| `idle_tid_samples` | Samples attributed to idle TID 0. |
| `missing_timestamp_samples` | Samples without a perf timestamp. |
| `empty_stack_samples` | Samples that produced no usable frames. |
| `truncated_frame_markers` | Unwind truncation markers observed. |
| `ignored_user_callchain_frames` | Unexpected user callchain frames discarded because user stacks are unwound from DWARF. |
| `error_stats` | Per-kind sample error counters. |

## Reading spool files

### [`PerfSpoolReader`]

`PerfSpoolReader::open(path)` reads the whole spool into memory and validates
record references.

| Method | What it returns |
| --- | --- |
| `start_timestamp_us()` | Profile timeline anchor stored in the spool header. |
| `sample_interval_us()` | Optional sample interval metadata stored in the spool header. |
| `modules()` | Recorded executable memory ranges. |
| `frames()` | Interned raw frame records. Useful for precomputing symbolization caches. |
| `samples()` | Timestamped samples. |
| `process_execs()` | Process exec markers, including Python runtime on/off. |
| `recovered_from_truncated_tail()` | Whether the spool ended mid-record and the reader kept only the intact prefix. |
| `kernel_frame_addresses()` | Iterator over absolute kernel IPs in interned frames. Used by [`PerfSymbolizer::for_spool`] for sparse `kallsyms` loading. |
| `stack_frame_refs(stack_id)` | Borrow raw [`FrameRecord`]s for an interned stack without copying. |
| `stack_frame_contexts(pid, stack_id)` | Borrow raw frames with recorded module context for an interned stack. |
| `sample_stacks()` | Iterate samples with borrowed raw stacks. |
| `stack_frames(stack_id, out)` | Expand an interned stack into [`FrameRecord`]s. Clears `out` first. |
| `timestamp_us(sample)` | Sample timestamp in profile-timeline microseconds. |

Frame iteration order is leaf to root. `FrameModuleRef::rel_ip` uses the same
file-offset coordinate space as `FrameRecord::rel_ip`; external symbolizers can
combine it with the recorded module mapping however their own lookup API
requires.

### [`ModuleRecord`]

| Field | Meaning |
| --- | --- |
| `id` | Stable module ID within this profile. |
| `process_id` | Owning PID (or a kernel marker for kernel code). |
| `start`, `end` | Runtime address range. |
| `file_offset` | File offset matching `start`. |
| `inode` | Backing file inode, when known. |
| `path` | Path or display name as [`ModulePath`]. Spool-read paths can borrow from the mmap-backed profile. |
| `is_kernel` | Kernel range? |

### [`FrameRecord`]

| Field | Meaning |
| --- | --- |
| `module_id` | Matched module, when known. |
| `rel_ip` | Module-relative address. |
| `abs_ip` | Absolute IP. |
| `mode` | [`FrameMode::User`], [`FrameMode::Kernel`], or [`FrameMode::TruncatedStackMarker`]. |

`FrameRecord::truncated_stack_marker()` creates the sentinel written when
native unwinding stopped before the stack root. Use
`FrameRecord::is_truncated_stack_marker()` to detect it in raw-frame workflows.

### [`OwnedSampleRecord`]

| Field | Meaning |
| --- | --- |
| `timestamp_ns` | Monotonic perf timestamp (ns). |
| `process_id` | PID. |
| `thread_id` | TID. |
| `stack_id` | Pass to [`PerfSpoolReader::stack_frames`]. |

### [`ProcessExecRecord`]

| Field | Meaning |
| --- | --- |
| `timestamp_ns` | Monotonic timestamp (ns). |
| `process_id` | PID. |
| `is_python_runtime` | Latest observation: does this PID look like a Python runtime with perf-map support? A later marker with `false` means stop treating it as Python. |

## Symbolization

### [`PerfSymbolizer`]

Resolves raw frames into displayable ones. One per profile, reused.

| Constructor or method | Use |
| --- | --- |
| `new(modules)` | Default: ELF, kernel symbols, plus Python perf maps for any PID. |
| `for_spool(reader)` | Create a symbolizer for a loaded spool, including sparse kernel-symbol loading. |
| `for_spool_with_perf_maps(reader, allow)` | Same as `for_spool`, but explicitly enable or disable Python perf maps. |
| `for_spool_with_recorded_python_perf_maps(reader)` | Allow perf maps for PIDs ever recorded as Python runtimes in the spool. |
| `with_perf_maps(modules, allow)` | Globally enable or disable perf-map lookup. |
| `with_perf_map_processes(modules, pids)` | Allow perf maps only for the listed PIDs. |
| `for_each_sample_stack(stack, visit)` | Resolve a [`SampleStack`] from `sample_stacks()` and stream borrowed resolved frames to `visit`. |
| `for_each_resolved_frame_slice(pid, frames, visit)` | Resolve a caller-supplied raw-frame slice and stream borrowed resolved frames to `visit`. |

`for_spool_with_recorded_python_perf_maps` is intentionally broader than a
"last observed as Python" filter: a PID remains allowed if it was ever marked
as a Python runtime in the spool. Use `with_perf_map_processes` for stricter
PID-reuse handling.

Resolution order, top to bottom:

1. Python or JIT perf map at `/tmp/perf-<pid>.map`, if allowed and the frame
   matches.
2. ELF symbols for file-backed user modules.
3. Kernel symbol lookup for kernel frames.
4. Address-only fallback.

### [`ResolvedFrame`]

| Variant | Meaning |
| --- | --- |
| `Python(PythonFrame)` | Python frame from a perf-map symbol. |
| `Native(NativeFrame)` | Native, kernel, JIT, or address-only frame. |

`ResolvedFrame::func_name()` gives you a displayable name for either.

### [`PythonFrame`]

| Field / method | Meaning |
| --- | --- |
| `file_name` | Python source filename. |
| `location` | Line + column when available. |
| `func_name` | Python function name. |
| `opcode` | Optional opcode. |
| `is_entry` | Entry marker? |
| `basename()` | Filename without leading dirs. |

### [`NativeFrame`] and [`NativeSymbol`]

`NativeFrame`:

| Field | Meaning |
| --- | --- |
| `pc` | Program counter. |
| `sp` | Stack pointer when available (currently `0` from the public symbolizer). |
| `symbol` | `Option<NativeSymbol>`. `None` means address-only. |
| `is_python_runtime` | Belongs to Python runtime machinery. |
| `kind` | [`FrameKind::Native`], `Kernel`, or `Unknown`. |
| `origin` | [`SymbolOrigin`]. Where the name came from. |
| `flags` | [`FrameFlags`] for UI policy. |

`NativeSymbol` carries the symbol name, optional source file / line, module
name, basename offsets, module-relative offset, and Python-runtime helpers
like `is_eval_frame` and `should_ignore`.

### Kinds, origins, flags

| Type | Values |
| --- | --- |
| [`FrameKind`] | `Python`, `Native`, `Kernel`, `Unknown` |
| [`SymbolOrigin`] | `Elf`, `PerfMap`, `KernelSymbols`, `AddressOnly` |
| [`FrameFlags`] | `PYTHON_RUNTIME`, `HIDDEN_DEFAULT`, `JIT`, `TRUNCATED_STACK` |

UIs typically hide `HIDDEN_DEFAULT`, badge `JIT`, group by [`FrameKind`], and
expose [`SymbolOrigin`] in a details view.

## Feature flags

| Feature | Effect |
| --- | --- |
| `debuginfod` | Enables the default native symbolizer to query debuginfod when `DEBUGINFOD_URLS` is set. |

`STACKPULSE_DEBUG_DIRS` overrides local debug-file search roots. With
`debuginfod`, `STACKPULSE_DEBUGINFOD_CACHE_DIR` overrides the debuginfod cache
directory.

## Process launch and liveness

### [`process::SuspendedLaunchedProcess`]

| Method | What it does |
| --- | --- |
| `launch_in_suspended_state(cmd, args, env)` | Fork a child that waits before `execve`. |
| `pid()` | The child's PID before it has executed. |
| `unsuspend_and_run()` | Let it `execve`, returns [`process::RunningProcess`]. |

### [`process::RunningProcess`]

| Method | What it does |
| --- | --- |
| `try_wait()` | Non-blocking wait. |
| `wait()` | Blocking wait until exit. |

### [`children`]

| Function | What it does |
| --- | --- |
| `discover_all_descendants(root)` | Descendant PIDs via `/proc/<pid>/task/*/children`, falling back to `/proc/*/stat`. |

### [`state`]

| Function or type | What it does |
| --- | --- |
| `ProcessExitWatcher::try_new(pid)` | pidfd-based exit watcher. |
| `ProcessExitWatcher::poll()` | Non-blocking exit check. |
| `process_exists(pid)` | Does this PID look alive? |
| `interrupt_process(pid)` | `SIGINT`. |
| `kill_process(pid)` | `SIGKILL`. |

## Error statistics

[`SampleErrorStats`] records per-kind failures. Cloneable, resettable,
printable via [`ErrorStatsFormatter`].

| Item | What it does |
| --- | --- |
| [`SampleErrorKind`] | Native-unwinding failure kinds (register capture, missing user registers, stack read, framehop errors). |
| `record(kind)` | Bump a counter. |
| `record_with_log(kind, ctx)` | Bump and emit a throttled debug log. |
| `get(kind)` | Read one counter. |
| `total()` | Sum across kinds. |
| `has_errors()` | Any non-zero? |
| `iter_nonzero()` | Iterate the non-zero counters. |
| `reset()` | Zero everything. |
| `ErrorStatsFormatter::new(stats, total_samples, successful_samples)` | Build a display formatter. |
| `write_to(writer)` | Write a grouped report. |

## Constants and helpers

| Item | Meaning |
| --- | --- |
| [`MAX_SAMPLE_USER_STACK`] | Maximum user stack bytes perf will accept. |
| [`max_sample_rate`] | Reads `/proc/sys/kernel/perf_event_max_sample_rate`, `None` if unavailable. |
| [`is_python_module`] | Does this basename look like a Python executable or `libpython`? |
| [`path_to_name`] | Display name from a path. |
| [`ModuleImageBase`] | Translates runtime AVMA addresses to static VMAs. |
| [`PerfFrequencyLimit`] | Error payload when requested frequency exceeds the kernel cap. |

## Spool format invariants

Append-only and compact:

- Modules, frames, stack nodes, threads, samples, and process exec markers
  are separate record kinds.
- Frames are interned. Repeated frames stored once.
- Stacks are prefix nodes. Common suffixes shared.
- Threads are interned by `(process_id, thread_id)`.
- Sample timestamps stored as deltas (ns).
- `timestamp_us` maps perf time to profile time using the stored start
  timestamp and the first sample.

The on-disk layout is an implementation detail. Read spool files through
[`PerfSpoolReader`].
