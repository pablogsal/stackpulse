# Reference

This chapter links every public type and method a profiler integration uses,
grouped by task: recording, reading spool files, symbolization, process
management, and diagnostics.

## Module map

The crate root re-exports the recording, reading, and symbolization types:

```rust,no_run
use stackpulse::{
    AttachMode, Recorder, RecorderOptions, Replay, Snapshot, Tail,
};
```

Public modules:

| Module | What it's for |
| --- | --- |
| [`process`](crate::process) | Launch a process suspended before `execve` so sampling starts at birth. |
| [`children`](crate::children) | Walk descendant PIDs through `/proc`. |
| [`error`](crate::error) | Stable error categories and the crate result type. |
| [`identity`](crate::identity) | Validated Linux process and thread IDs. |
| [`profile`](crate::profile) | Resolved frames and symbol data types. |
| [`record`](crate::record) | Recording types and statistics. |
| [`spool`](crate::spool) | Spool readers and raw profile data. |
| [`state`](crate::state) | Process liveness, exit watching, and signal helpers. |
| [`symbolize`](crate::symbolize) | Stack resolution and native-symbolizer integration. |

## Recording

### [`Recorder`](crate::Recorder)

Records stack samples for one or more processes and writes a spool file.

| Method | What it does |
| --- | --- |
| `attach(pid, output, mode, options)` | Open perf events, create the spool, register known mappings, start sampling. |
| `attach_with_writer(pid, writer, mode, options)` | Record to a caller-owned writer. |
| `poll(timeout)` | Wait up to `timeout`, then drain ready perf data, unwind samples, and write records. |
| `tail()` | Flush the spool and create its one in-process incremental reader. |
| `attach_process(pid, mode)` | Add another process to the same recording. |
| `refresh_threads(pid)` | Discover new threads when perf inheritance isn't doing it. |
| `disable()` | Stop sampling for all attached events. |
| `enable()` | Resume sampling for all attached events. |
| `flush()` | Drain events and flush the writer. After observed loss it can also scan `/proc`, rebuild mappings, discover descendants, and reopen perf events. |
| `has_pending_events()` | Report whether perf data is ready to drain. |
| `summary()` | Snapshot of recording counters. |
| `process_is_active(pid)` | Report whether the given PID is still alive. |
| `has_active_processes_except(pid)` | Fallibly report whether any attached PID other than the given one is alive. |
| `active_process_count()` | Fallibly count attached processes that are still alive. |
| `finish()` | Flush, return final counters, consume the recorder. |

The recorder does not drain itself. Call `poll` while the target runs or the
kernel buffers will fill and drop samples.

### [`AttachMode`](crate::AttachMode)

| Variant | Use |
| --- | --- |
| `Running` | Attach without stopping. Initial mapping discovery can race with concurrent mmap, munmap, and exec activity. |
| `StopWhileAttaching` | Attaching to a running process. The target is briefly stopped while events open, then resumed. |
| `OnExec` | Attaching to a forked-but-not-yet-exec'd child. Pair with [`process::SuspendedLaunchedProcess`](crate::process::SuspendedLaunchedProcess). |

### [`SampleRate`](crate::SampleRate) and [`RecorderOptions`](crate::RecorderOptions)

`SampleRate::hz(value)` validates a fixed rate. `SampleRate::Maximum` reads the
current kernel maximum when recording starts.

| Builder method | Meaning |
| --- | --- |
| `new(sample_rate)` | Start with a 32 KiB stack snapshot and optional features disabled. |
| `stack_size(bytes)` | Set user stack bytes copied per sample. Capped at [`MAX_SAMPLE_USER_STACK`](crate::record::MAX_SAMPLE_USER_STACK). |
| `ring_buffer_stacks(count)` | Target capacity in stack-sized records. Capacity is `max(stack_size, system_page_size) * count`, with a floor for one maximum-size perf record and power-of-two page rounding. On 4 KiB-page hosts, the default count of 32 gives 1 MiB at 32 KiB stacks and 2 MiB at 64 KiB stacks. Rings are capped at 256 MiB per CPU and share a 1 GiB recorder data-ring budget. `EPERM` or `ENOMEM` while mapping causes progressive fallback to the minimum valid ring. |
| `include_kernel(bool)` | Capture kernel frames when allowed. |
| `inherit_children(bool)` | Follow children forked after recording starts. |
| `start_timestamp_us(value)` | Set the timeline anchor stored in the spool. |
| `sample_interval_us(value)` | Set optional interval metadata stored in the spool. |

`Default` records at 1,000 Hz with a 32 KiB stack snapshot.

### [`Pid`](crate::Pid) and [`Tid`](crate::Tid)

These types reject zero, negative values, and values outside Linux's signed
PID range. Construct them with `Pid::try_from` and `Tid::try_from`; use `get()`
when an external API requires the raw `i32`.

### [`RecordingSummary`](crate::RecordingSummary)

Counter snapshot for quality checks.

| Field | Meaning |
| --- | --- |
| `sample_events` | Raw perf sample records seen. |
| `samples` | Samples written to the spool. |
| `lost_events` | Kernel-reported losses. |
| `lifecycle_gaps` | Nonzero loss batches that made lifecycle state potentially incomplete. Several batches can share one recovery sweep. |
| `kernel_enabled` | Whether kernel capture stayed on after attach. |
| `minimum_ring_buffer_bytes` / `maximum_ring_buffer_bytes` | Effective per-CPU perf data-ring capacity range. The metadata page is excluded. |
| `missing_pid_samples` / `missing_tid_samples` | Samples dropped for missing IDs. |
| `idle_tid_samples` | Samples attributed to idle TID 0. |
| `missing_timestamp_samples` | Samples without a perf timestamp. |
| `empty_stack_samples` | Samples that produced no usable frames. |
| `truncated_frame_markers` | Unwind truncation markers observed. |
| `ignored_user_callchain_frames` | Unexpected user callchain frames discarded because user stacks are unwound from DWARF. |
| `error_stats` | Per-kind sample error counters. |

## Reading spool files

### [`Snapshot`](crate::Snapshot)

`Snapshot::open(path)` reads the whole spool into memory and validates
record references.

| Method | What it returns |
| --- | --- |
| `start_timestamp_us()` | Optional profile timeline anchor stored in the spool header. |
| `sample_interval_us()` | Optional sample interval metadata stored in the spool header. |
| `modules()` | Recorded executable memory ranges. |
| `frames()` | Interned raw frame records. Useful for precomputing symbolization caches. |
| `samples()` | Timestamped samples. |
| `python_runtime_records()` | Python-runtime status changes. |
| `recovered_from_truncated_tail()` | Whether the spool ended mid-record and the reader kept only the intact prefix. |
| `kernel_frame_addresses()` | Iterator over absolute kernel IPs in interned frames. |
| `stacks()` | Iterate samples with borrowed raw stacks. |
| `stack(index)` | Borrow one indexed sample with its raw stack. |
| `timestamp_us(sample)` | Sample timestamp in profile-timeline microseconds, or `None` without an anchor. |

Frame iteration order is leaf to root. `FrameModuleRef::file_relative_ip` and
`FrameRecord::file_relative_ip` share the same file-offset coordinate space,
so an external symbolizer can pair either one with the recorded module
mapping.

### [`Replay`](crate::Replay)

`Replay::open(path)` validates the complete spool and retains
definitions but not sample metadata. Samples are decoded sequentially during
iteration. A bounded range index accelerates replay; if it fills, the reader
scans validated records with constant additional memory.

| Method | What it returns |
| --- | --- |
| `start_timestamp_us()` | Optional profile timeline anchor stored in the spool header. |
| `sample_interval_us()` | Optional sample interval metadata stored in the spool header. |
| `modules()` | Recorded executable memory ranges. |
| `frames()` | Interned raw frame records. |
| `sample_count()` | Number of samples in the validated spool prefix. |
| `samples()` | Sequential iterator of owned [`SampleRecord`](crate::spool::SampleRecord) values. |
| `stacks()` | Sequential iterator of [`SampleStack`](crate::spool::SampleStack) values with borrowed raw frames. |
| `python_runtime_records()` | Python-runtime status changes. |
| `recovered_from_truncated_tail()` | Whether the spool ended mid-record and only the intact prefix is available. |
| `timestamp_us(sample)` | Sample timestamp in profile-timeline microseconds, or `None` without an anchor. |

The spool file must not be truncated or modified while either reader is alive.
Use [`Snapshot`](crate::Snapshot) when sample random access is required.

### [`Tail`](crate::Tail)

`Tail` reads complete records from an append-only spool while its writer is
still active. [`Recorder::tail`](crate::Recorder::tail) is preferred for an
in-process reader because it also shares the recorder's retained exact-image
handles. `Tail::open(path)` works for a separate reader after the writer has
flushed the spool header.

| Method | What it returns |
| --- | --- |
| `symbolizer()` | A symbolizer bound to this tail's growing definitions. |
| `poll()` | A borrowed [`TailBatch`](crate::spool::TailBatch) containing the next bounded group of visible samples and definition changes. |
| `start_timestamp_us()` | Optional profile timeline anchor stored in the spool header. |
| `sample_interval_us()` | Optional sample interval metadata stored in the spool header. |

`TailBatch::stacks()` yields borrowed raw stacks. Call
`Symbolizer::update(&batch)` before resolving them. `TailBatch::has_more()` is
true when another batch may already be decoded without waiting for the writer;
it is not a writer-completion signal. The batch borrows reusable storage from
the tail, so it must be dropped before the next poll.

For external prepared-stack caches, apply every returned
[`Invalidation`](crate::symbolize::Invalidation). `all()` requests a full
reset; otherwise `processes()` lists the affected process IDs and
`affects_process(pid)` performs either check. A resolved stack with
`is_cacheable() == false` is provisional and must not be retained.

### [`ModuleRecord`](crate::spool::ModuleRecord)

| Accessor | Meaning |
| --- | --- |
| `id()` | Stable module ID within this profile. |
| `pid()` | Owning PID, or `None` for kernel code. |
| `address_range()` | Runtime address range. |
| `file_offset()` | File offset matching the mapping start. |
| `inode()` and device accessors | Recorded file identity, when known. |
| `path()` | Owned, shared path or display name as [`ModulePath`](crate::spool::ModulePath). |
| `is_kernel()` | Whether this mapping is a kernel range. |

### [`FrameRecord`](crate::spool::FrameRecord)

| Field | Meaning |
| --- | --- |
| `module_id` | Matched module, when known. |
| `file_relative_ip` | Address in the mapped file's offset coordinate space. |
| `abs_ip` | Absolute IP. |
| `mode` | [`FrameMode::User`](crate::spool::FrameMode::User), [`FrameMode::Kernel`](crate::spool::FrameMode::Kernel), or [`FrameMode::TruncatedStackMarker`](crate::spool::FrameMode::TruncatedStackMarker). |

`FrameRecord::truncated_stack_marker()` creates the sentinel written when
native unwinding stopped before the stack root. Use
`FrameRecord::is_truncated_stack_marker()` to detect it in raw-frame workflows.

### [`SampleRecord`](crate::spool::SampleRecord)

| Field | Meaning |
| --- | --- |
| `timestamp_ns` | Monotonic perf timestamp (ns). |
| `process_id` | PID. |
| `thread_id` | TID. |

### [`PythonRuntimeRecord`](crate::spool::PythonRuntimeRecord)

| Field | Meaning |
| --- | --- |
| `timestamp_ns` | Monotonic timestamp (ns). |
| `process_id` | PID. |
| `is_python_runtime` | Latest observation: does this PID look like a Python runtime with perf-map support? A later marker with `false` means stop treating it as Python. |

## Symbolization

### [`Symbolizer`](crate::Symbolizer)

Resolves raw frames into displayable frames. Reuse one symbolizer per profile.

| Constructor or method | Use |
| --- | --- |
| `source.symbolizer()` | Configure a symbolizer associated with a [`Replay`](crate::Replay), [`Snapshot`](crate::Snapshot), or [`Tail`](crate::Tail). |
| `SymbolizerBuilder::for_modules(modules)` | Configure symbolization for module records. |
| `SymbolizerBuilder::from_modules(modules)` | Transfer an owned module table without copying it. |
| `disable_perf_maps()` | Disable Python perf-map lookup. |
| `perf_maps_for(pids)` | Allow perf maps only for the listed PIDs. |
| `perf_map_dir(path)` | Read preserved `perf-<pid>.map` files from `path` instead of `/tmp`. |
| `native(factory)` | Replace the bundled native symbolizer with a [`NativeSymbolizer`](crate::symbolize::NativeSymbolizer). |
| `try_native(factory)` | Replace it with a lazily constructed backend whose factory may fail. |
| `kernel_symbols(source)` | Use host symbols, a preserved `kallsyms` file, or no kernel symbols. |
| `stack_cache(mode)` | Choose whether StackPulse or the caller caches resolved stacks. |
| `build()` | Validate the configuration and construct the symbolizer. |
| `update(batch)` | Apply a live tail batch's definitions and symbol-source changes before resolving its stacks. |
| `has_native_backend()` | Report whether native ELF symbolization is configured. |
| `resolve(stack)` | Resolve a [`SampleStack`](crate::spool::SampleStack) and return borrowed frames as a [`ResolvedStack`](crate::symbolize::ResolvedStack). |
| `resolve_raw(pid, frames)` | Resolve a caller-owned raw-frame slice without retaining a stack entry. |

Use `perf_maps_for` with IDs from `python_runtime_records()` when perf-map
lookup should follow the runtime metadata captured in the spool.

For a live tail, call `update` once for every polled batch, including an empty
batch. With `StackCache::Internal`, the symbolizer invalidates its own cached
stacks. With `StackCache::External`, the caller applies the returned
`Invalidation` to its prepared-stack cache. `ResolvedStack::next_with_id`
provides stable, symbolizer-local frame IDs for a separate converted-frame
cache.

[`NativeSymbolizer`](crate::symbolize::NativeSymbolizer) receives a batch of
[`NativeLookup`](crate::symbolize::NativeLookup) values and appends one
[`NativeSymbols`](crate::symbolize::NativeSymbols) result per lookup, in the same order.
Each lookup provides the selected module plus its absolute, relative, and
image addresses. `NativeModule::new` and `NativeLookup::new` construct
realistic requests for backend tests without recording a process. Synthetic
modules receive distinct opaque image identities and never have an
`image_path()`.

An `image_path()` is available only when StackPulse reopened and retained the
exact file backing a Linux mapping. It is absent for synthetic modules,
anonymous mappings, files that could not be reopened, and modules without a
validated file descriptor. An address-only result caused by a retryable native
image open failure is provisional; a later resolution attempt can return more
specific symbols.

Resolution order, top to bottom:

1. Python or JIT perf map at `/tmp/perf-<pid>.map`, if allowed and the frame
   matches.
2. ELF symbols for file-backed user modules.
3. Kernel symbol lookup for kernel frames.
4. Address-only fallback.

### [`ResolvedFrame`](crate::profile::ResolvedFrame)

| Variant | Meaning |
| --- | --- |
| `Python(PythonFrame)` | Python frame from a perf-map symbol. |
| `Native(NativeFrame)` | Native, kernel, JIT, or address-only frame. |

`ResolvedFrame::name()` borrows a resolved name without allocation.
`ResolvedFrame::display_name()` is the explicit allocating convenience for
address-only frames that need hexadecimal formatting.

### [`PythonFrame`](crate::profile::PythonFrame)

| Field / method | Meaning |
| --- | --- |
| `file_name()` | Python source filename. |
| `location` | Line + column when available. |
| `func_name` | Python function name. |
| `opcode` | Optional opcode. |
| `is_entry` | Whether this frame is a Python entry frame. |
| `basename()` | Filename without leading dirs. |

### [`NativeFrame`](crate::profile::NativeFrame) and [`NativeSymbol`](crate::profile::NativeSymbol)

`NativeFrame`:

| Field | Meaning |
| --- | --- |
| `pc` | Program counter. |
| `symbol` | `Option<NativeSymbol>`. `None` means address-only. |
| `is_python_runtime()` | Whether the owning module is Python runtime machinery. |
| `kind` | [`FrameKind::Native`](crate::profile::FrameKind::Native), `Kernel`, or `Unknown`. |
| `origin` | [`SymbolOrigin`](crate::profile::SymbolOrigin). Where the name came from. |
| `flags` | [`FrameFlags`](crate::profile::FrameFlags) for UI policy. |

`NativeSymbol` carries the symbol name, optional source file / line, module
name, basename access, function-relative offset, and Python-runtime helpers
like `is_eval_frame()` and `should_ignore()`.

### Kinds, origins, and flags

| Type | Values |
| --- | --- |
| [`FrameKind`](crate::profile::FrameKind) | `Python`, `Native`, `Kernel`, `Unknown` |
| [`SymbolOrigin`](crate::profile::SymbolOrigin) | `Elf`, `PerfMap`, `KernelSymbols`, `AddressOnly` |
| [`FrameFlags`](crate::profile::FrameFlags) | `PYTHON_RUNTIME`, `HIDDEN_DEFAULT`, `JIT`, `TRUNCATED_STACK` |

[`FrameFlags`](crate::profile::FrameFlags) and [`SymbolOrigin`](crate::profile::SymbolOrigin)
provide display hints. StackPulse does not apply a UI policy.

## Feature flags

| Feature | Effect |
| --- | --- |
| `builtin-wholesym` (default) | Includes the `wholesym` native symbolizer and its Tokio runtime. |
| `debuginfod` | Enables the default native symbolizer to query debuginfod when `DEBUGINFOD_URLS` is set. |

`STACKPULSE_DEBUG_DIRS` overrides local debug-file search roots. With
`debuginfod`, `STACKPULSE_DEBUGINFOD_CACHE_DIR` overrides the debuginfod cache
directory.

## Process launch and liveness

### [`process::SuspendedLaunchedProcess`](crate::process::SuspendedLaunchedProcess)

| Method | What it does |
| --- | --- |
| `launch_in_suspended_state(cmd, args, env)` | Fork a child that waits before `execve`. |
| `pid()` | The child's PID before it has executed. |
| `unsuspend_and_run()` | Let it `execve`, returns [`process::RunningProcess`](crate::process::RunningProcess). |

### [`process::RunningProcess`](crate::process::RunningProcess)

| Method | What it does |
| --- | --- |
| `try_wait()` | Non-blocking wait. |
| `wait()` | Blocking wait until exit. |

### [`children`](crate::children)

| Function | What it does |
| --- | --- |
| `discover_all_descendants(root)` | Descendant PIDs via `/proc/<pid>/task/*/children`, falling back to `/proc/*/stat`. |

### [`state`](crate::state)

| Function or type | What it does |
| --- | --- |
| `ProcessExitWatcher::try_new(pid)` | pidfd-based exit watcher. |
| `ProcessExitWatcher::poll()` | Non-blocking exit check. |
| `process_exists(pid)` | Fallibly report whether the PID is observable in `/proc`. |
| `process_is_alive(watcher, pid)` | Fallibly check a pidfd, or `/proc` when no watcher exists. |
| `interrupt_process(pid)` | `SIGINT`. |
| `kill_process(pid)` | `SIGKILL`. |

## Workflow errors

Recording, spool reading, and symbolization return
[`stackpulse::Result`](crate::Result). Inspect [`Error::kind`](crate::Error::kind)
for stable control flow and include a wildcard arm when matching
[`ErrorKind`](crate::ErrorKind), which is non-exhaustive.

[`Error::frequency_limit`](crate::Error::frequency_limit) returns the requested
and permitted rates for a frequency-limit failure. [`Error::io_error`](crate::Error::io_error)
and [`Error::raw_os_error`](crate::Error::raw_os_error) retain OS details. A
custom native symbolizer's concrete error remains in the standard
[`Error::source`](std::error::Error::source) chain and can be downcast there.
Process operations classify `ESRCH`, and contextual `/proc` or perf `ENOENT`,
as [`ErrorKind::TargetGone`](crate::ErrorKind::TargetGone). Ordinary missing
files remain [`ErrorKind::Io`](crate::ErrorKind::Io).
[`Pid::try_from`](crate::Pid::try_from) and [`Tid::try_from`](crate::Tid::try_from)
errors convert to `ErrorKind::InvalidInput`, so they work with `?` in a
`stackpulse::Result` function.

Converting a StackPulse error into [`std::io::Error`] preserves the StackPulse
error as the inner source while mapping its category to the closest
[`std::io::ErrorKind`]. Prefer the crate error when exact classification
matters.

## Error statistics

[`SampleErrorStats`](crate::record::SampleErrorStats) records per-kind failures. It can
be cloned or reset.

| Item | What it does |
| --- | --- |
| [`SampleErrorKind`](crate::record::SampleErrorKind) | Native-unwinding failure kinds (register capture, missing user registers, stack read, stack truncation, framehop errors). |
| `record(kind)` | Bump a counter. |
| `record_with_log(kind, ctx)` | Bump and emit a throttled debug log. |
| `count(kind)` | Read one counter. |
| `total()` | Sum across kinds. |
| `has_errors()` | Report whether any counter is non-zero. |
| `nonzero_counts()` | Iterate the non-zero counters. |
| `reset()` | Zero everything. |

## Constants and helpers

| Item | Meaning |
| --- | --- |
| [`MAX_SAMPLE_USER_STACK`](crate::record::MAX_SAMPLE_USER_STACK) | Maximum user stack bytes perf will accept. |
| [`max_sample_rate`](crate::record::max_sample_rate) | Reads `/proc/sys/kernel/perf_event_max_sample_rate`, `None` if unavailable. |
| [`is_python_runtime_basename`](crate::profile::is_python_runtime_basename) | Report whether a basename looks like a Python executable or `libpython`. |
| [`PerfFrequencyLimit`](crate::record::PerfFrequencyLimit) | Error payload when requested frequency exceeds the kernel cap. |

## Spool format invariants

The spool is an append-only stream built around interning:

- Modules, frames, stack nodes, threads, samples, and Python-runtime records
  are separate record kinds.
- Frames are interned, so a repeated frame is stored once.
- Stacks are stored as prefix-linked nodes, so common suffixes are shared.
- Threads are interned by `(process_id, thread_id)`.
- Sample timestamps are stored as nanosecond deltas.
- `timestamp_us` maps perf time to profile time using the stored start
  timestamp and the first sample.

The byte-level layout is described in the SPULSE spool format chapter of the
[guide](crate::docs). Treat that description as informational: read spool
files through [`Snapshot`](crate::Snapshot) rather than parsing
the stream yourself.
