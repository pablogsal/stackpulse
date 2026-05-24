# How Linux perf sampling works in stackpulse

This page explains the model behind `stackpulse`. It is not a recipe. Read it
when you need to reason about overhead, missing frames, permissions, symbol
quality, or why the API is split into recording, reading, and symbolization.

## Sampling, not tracing

`stackpulse` is a statistical sampler. It does not record every function call.
Instead, the Linux kernel periodically interrupts threads, captures enough state
to describe where they were running, and places records into perf ring buffers.

If a function appears in 20% of samples, the useful interpretation is "the
program was observed in or below this function about 20% of sampled time." It is
not a call count. Short functions can be absent, and very short spikes can be
missed unless they overlap a sample.

## The recording pipeline

The runtime pipeline is:

```text
target threads
  -> Linux perf_event_open ring buffers
  -> PerfRecorder::consume_available
  -> native unwinding and module tracking
  -> compact spool file
  -> PerfSpoolReader
  -> PerfSymbolizer
  -> your aggregation, UI, or export format
```

This split is deliberate. Recording should do only the work required to preserve
the profile. Expensive or optional display work, such as symbol lookup and
aggregation, happens after the profile is safely written.

## What `perf_event_open` provides

`stackpulse` opens perf events for the target process and its threads. The event
configuration requests:

- frequency-based sampling;
- monotonic timestamps;
- task IDs in record IDs;
- user register capture;
- user stack byte copies;
- `mmap`, `comm`, `fork`, `exit`, and lost-event records;
- optional kernel callchains when kernel frames are requested.

The recorder first tries hardware CPU cycles, then falls back to software CPU
clock if hardware events are unavailable. Both are CPU-time oriented sampling
sources: they are good at finding where threads spend runnable/on-CPU time, not
where they are blocked off CPU.

Perf records arrive in per-event ring buffers. `PerfRecorder::wait` waits until
one or more buffers look readable. `PerfRecorder::consume_available` drains
records, sorts timestamped records across buffers, updates process/module state,
and writes the spool file.

## Attach modes

`StopAttachEnableResume` is for an existing process. The recorder briefly sends
`SIGSTOP`, opens perf events, registers known executable mappings from
`/proc/<pid>/maps`, enables the events, and resumes the process. The stop window
reduces races while the recorder is building its initial view of threads and
mappings.

`AttachWithEnableOnExec` is for a child that has been forked but not yet
executed. Use it with `process::SuspendedLaunchedProcess`. Perf events are
created before `execve` and enabled by the kernel on exec, so startup code is
captured.

## Threads and child processes

A process can have many threads, and Linux perf events are opened against tasks.
`stackpulse` tracks the process leader plus known threads. It asks perf to
inherit new thread events when possible. If inheritance is unavailable, or if the
event fan-out would be too large, `refresh_threads` can scan `/proc/<pid>/task`
and open missing threads explicitly.

Child processes are different from threads. Set `inherit_child_processes` to
record processes forked after the recording starts. The recorder listens for
fork events, clones relevant module state from the parent, and opens the child.
Existing descendants need explicit attachment.

## Native stack capture

For user-space frames, perf captures the interrupted thread's user registers and
a bounded byte copy of the user stack. `stackpulse` feeds those into `framehop`
to unwind native frames. This approach can recover call stacks even when perf
user callchains are not requested.

The copied stack size matters. If it is too small, unwinding can stop early and
`PerfSummary.error_stats` will show native stack read or truncation errors. If
it is too large, each sample copies more memory and can increase overhead. The
default recommendation is to start around `60 * 1024` bytes and adjust based on
summary counters.

Return addresses are normalized before being written: a return-address frame is
converted to the instruction before the return target. This makes symbol lookup
land in the call site rather than the next instruction after the call.

## Kernel frames

When `include_kernel` is true, `stackpulse` requests kernel callchains from
perf. User-space frames still come from the native unwinder. User callchain
frames reported by perf are counted in `ignored_user_callchain_frames` and are
not used as the primary user stack source.

Kernel sampling is often permission-gated. If opening perf events fails only
because kernel frames are denied, `PerfRecorder::attach` retries without kernel
frames and records `kernel_enabled = false` in the summary.

Kernel symbol names come from `/proc/kallsyms` when that file is readable and
contains usable addresses. Otherwise kernel frames fall back to names containing
the address.

## Module tracking

A raw instruction pointer is not enough to symbolize a frame. The resolver needs
to know which executable mapping owned that address and how the mapping relates
to the backing file.

`stackpulse` records executable mappings from two sources:

- existing mappings from `/proc/<pid>/maps` during attach;
- perf `mmap` records emitted while the process runs.

Each mapping becomes a `ModuleRecord` with a runtime address range, file offset,
inode, path, process ID, and kernel flag. When a frame is recorded, the recorder
resolves the absolute address to a module ID and module-relative instruction
pointer when possible. That makes later symbolization independent from the
target process still being alive.

## Symbolization

`PerfSymbolizer` resolves frames after recording. It uses several sources:

| Source | Used for | Result |
| --- | --- | --- |
| Python perf maps in `/tmp/perf-<pid>.map` | Python frames and JIT-like symbols emitted by runtimes. | `PythonFrame` or `NativeFrame` with `SymbolOrigin::PerfMap`. |
| ELF and debug data | Native user-space modules. | `NativeFrame` with `SymbolOrigin::Elf`. |
| `/proc/kallsyms` | Kernel frames. | `NativeFrame` with `FrameKind::Kernel`. |
| Address fallback | Missing symbols or unknown mappings. | `NativeFrame` with `SymbolOrigin::AddressOnly`. |

Python frames are available only when the Python runtime emits perf-map entries.
For current Python builds, run with `-X perf` or `PYTHONPERFSUPPORT=1`.
`stackpulse` records process exec markers so readers can restrict perf-map
lookup to processes that looked like Python runtimes during the recording.

The spool file does not embed perf-map contents. Symbolization reads
`/tmp/perf-<pid>.map` when `PerfSymbolizer` resolves frames. If analysis happens
after the process exits, after cleanup, or on another machine, preserve those
perf-map files next to the spool and make them available at symbolization time.

Native Python runtime frames are marked with `FrameFlags::PYTHON_RUNTIME` and
`FrameFlags::HIDDEN_DEFAULT` when the symbolizer can identify them. UIs can hide
them by default while still allowing users to inspect interpreter overhead.

## Why spool files are compact

Profiles are repetitive. Hot loops produce the same frames and the same stacks
many times. The spool format exploits that:

- module records are written when executable mappings are discovered;
- thread IDs are interned;
- frame records are interned;
- stacks are stored as prefix nodes so common suffixes are shared;
- samples point to a thread ID and a stack ID;
- sample timestamps are stored as deltas.

This keeps recording writes small and makes repeated stacks cheap to store.
`PerfSpoolReader` expands stack IDs back into `FrameRecord` values when the
analysis phase needs them.

## Accuracy and bias

Sampling has predictable limitations:

- It observes where threads are when samples fire, not every call.
- CPU-time sampling favors runnable and on-CPU work. Waiting on I/O, locks, or
  sleep can be underrepresented.
- Very high sample rates can lose events if ring buffers are not drained fast
  enough.
- Stack unwinding can fail when stack bytes are insufficient, metadata is
  missing, or the sampled thread is in a hard-to-unwind state.
- Symbolization quality depends on binaries, debug info, runtime maps, kernel
  symbol visibility, and whether the target's mappings were observed.
- PID reuse can make stale `/tmp/perf-<pid>.map` files dangerous unless lookup
  is restricted to processes whose latest exec marker says they are Python
  runtimes.

The counters in `PerfSummary` exist to make these problems visible. Treat a
profile as high quality only when sample counts, lost events, empty stacks,
truncation markers, and error stats are acceptable for your use case.

## Overhead model

The main recording costs are:

- kernel interrupt and sample collection work at the requested frequency;
- copied user stack bytes per sample;
- perf ring buffer traffic;
- native unwinding in `consume_available`;
- spool writes;
- extra perf events for many threads, CPUs, and inherited child processes.

Symbolization is intentionally outside the hot recording loop. It can read ELF
data, debug data, kernel symbols, and perf maps lazily after the profile has
been written.

Lower overhead by reducing `frequency`, reducing `stack_size`, avoiding kernel
frames when not needed, limiting child-process inheritance, and draining from a
dedicated worker often enough to avoid lost events.

## Permissions and system configuration

Linux perf access is controlled by the kernel and distribution policy. The
common gates are:

- ownership of the target process;
- `/proc/sys/kernel/perf_event_paranoid`;
- `/proc/sys/kernel/perf_event_max_sample_rate`;
- capabilities such as `CAP_PERFMON` or administrator privileges;
- visibility of `/proc/<pid>` inside containers or PID namespaces;
- read access to `/proc/kallsyms` for kernel names.

Design profilers to degrade gracefully. User-space capture without kernel frames
is often still valuable. Address-only frames are still useful for correlation if
you can symbolize them later with the same binaries and mappings.
