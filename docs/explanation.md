# How it works

StackPulse uses `perf_event` to capture CPU stack samples and resolves symbols
after recording. This chapter explains the kernel interface, native unwinding,
module tracking, symbol lookup, and recording overhead.

## Statistical sampling

StackPulse is a statistical sampler. It does not record every function
call. The kernel periodically interrupts threads, snapshots enough state to
describe where they were, and drops records into perf ring buffers.

If a function shows up in 20% of samples, the right reading is "the program
was observed in or below that function about 20% of sampled time", not a
call count. Short functions can be invisible, and brief spikes can be missed
if no sample lands on them.

## Recording flow

```text
target threads
  → perf_event_open ring buffers
  → Recorder::poll
  → native unwinding + module tracking
  → compact spool file
      ├─ completed: Snapshot or Replay
      └─ growing: Tail::poll
  → Symbolizer
  → your aggregator / UI / exporter
```

Recording writes addresses and mapping metadata to the spool. Symbol lookup
and aggregation happen after capture.

## Perf events

`perf_event_open` exposes the kernel's Performance Monitoring Unit (PMU) and
software event sources to user space. A call describes the event, target task,
and CPUs. The returned file descriptor owns a counter and, for sampled events,
a shared ring buffer of records.

Two event families matter here:

- Hardware events from the CPU's PMU. The most useful one for profiling
  is the CPU cycles counter, which ticks whenever the core is running. The
  PMU is finite (a handful of counters per core) and many distros and
  virtualization layers restrict access to it.
- Software events synthesized by the kernel. The relevant fallback is the
  CPU clock, a monotonic per-task timer. It doesn't need PMU hardware, so
  it works inside containers and VMs where the PMU is hidden.

StackPulse tries hardware CPU cycles first and falls back to the software
CPU clock if the kernel refuses or the hardware event isn't available. Both
are CPU-time sources: they tick when a thread is actually on a CPU, so they
under-represent time spent blocked on I/O, locks, or sleep. Off-CPU
attribution is out of scope here; that needs a different sampling
discipline (sched switches, eBPF, or wallclock samplers).

Sampling vs. counting: in frequency mode the kernel picks a sample period
itself and writes one record each time the counter overflows that period,
adjusting the period over time to keep the record rate near the requested
frequency. That's how a frequency-based profiler gets roughly N samples per
second per CPU without knowing the exact cycle count in advance.

For each target, StackPulse configures the event to emit:

- frequency-based sampling at the requested rate;
- monotonic timestamps, so records from different ring buffers can be
  merged into a single timeline;
- task IDs (PID + TID) inside each sample;
- the user-mode register set at the moment the sample fired;
- a copy of the user-mode stack bytes. The kernel literally `memcpy`s up
  to `stack_size` bytes of the user stack into the record;
- `mmap`, `comm`, `fork`, and `exit` side-band records, so we learn about
  new executable mappings, process names, forks, and exits without
  re-reading `/proc`;
- lost-event records, so the kernel can tell us when it had to drop
  samples because we were too slow;
- kernel callchains when `include_kernel` is on; user callchains are excluded
  because user frames come from DWARF unwinding.

Each event has its own mmap'd ring buffer. The kernel is the producer, we
are the consumer, and the two sides coordinate through head/tail pointers
in a header page. Because samples are generated on many CPUs in parallel,
records from different buffers don't arrive in global timestamp order.
`poll` waits up to the caller's timeout, drains every ready buffer, merges
records by timestamp, updates the recorder's process and module state, runs
the native unwinder, and writes compact records to the spool.

If the consumer can't keep up, the ring buffer fills, the kernel starts
dropping samples, and emits a `LOST` record so we can count what was lost
in `RecordingSummary.lost_events`.

## Attach modes

Two modes cover the practical cases:

`StopWhileAttaching` is for an existing process. The recorder briefly
`SIGSTOP`s the target, opens the perf events, registers the executable
mappings from `/proc/<pid>/maps`, enables the events, and resumes the
target. The short stop window keeps the initial view of threads and
mappings consistent with what perf will see going forward.

`OnExec` is for a forked-but-not-yet-`execve`d child:
create the events first, let the kernel turn them on at `execve`, and
nothing is missed during startup.

## Threads vs. child processes

Perf events open against tasks. StackPulse tracks the process leader plus
known threads and asks perf to inherit events for new threads. When
inheritance isn't an option, `refresh_threads` scans `/proc/<pid>/task` and
opens missing ones.

Child processes are not threads. Use `RecorderOptions::inherit_children` to
follow forks after recording starts. The recorder watches for fork events, clones
the relevant module state from the parent, and opens the child. Pre-existing
descendants need explicit attachment.

## Native stack capture

For user frames, perf hands us the interrupted thread's user registers plus
a bounded byte copy of the user stack. `framehop` unwinds from there. As with
`perf record --call-graph=dwarf`, the perf event excludes user callchains to
prevent duplicate user frames.

Stack-copy size is a trade-off. Too small and unwinding stops short, and
`RecordingSummary.error_stats` shows truncation. Too large and every sample
copies more memory than necessary, which raises overhead at the same
sampling rate. The examples use `60 * 1024`; adjust it when the summary
counters show truncation.

Return-address frames are normalized: each return address is rewound to the
instruction before the return target, so symbol lookup lands on the call
site instead of the instruction after it.

## Kernel frames

The recorder asks perf for callchains and uses them for kernel frames when
`include_kernel` is enabled. User frames come only from the native DWARF
unwinder. If the kernel unexpectedly supplies user callchain frames despite
their exclusion, they are discarded and counted in
`ignored_user_callchain_frames`.

Kernel sampling is usually permission-gated. If `perf_event_open` fails only
because kernel sampling was denied, attach retries without kernel frames and
reports `kernel_enabled = false`.

Kernel names come from `/proc/kallsyms` when it's readable and usable;
otherwise kernel frames render with an address-based name.

## Module tracking

A raw IP isn't enough to symbolize a frame. The resolver needs to know
which mapping owned that address and how the mapping ties to its backing
file.

Mappings come from two places:

- the snapshot of `/proc/<pid>/maps` taken at attach;
- perf `mmap` records emitted while the process runs.

Each mapping becomes a `ModuleRecord` with its runtime address range, file
offset, inode, path, owning PID, and kernel flag. The recorder resolves each
frame's absolute address to a module ID plus a file-relative IP when
possible, so symbolization doesn't need the target process to still exist.

## Symbolization

`Symbolizer` resolves frames after the fact, from several sources:

| Source | Used for | Result |
| --- | --- | --- |
| Python perf maps (`/tmp/perf-<pid>.map`) | Python frames and JIT-like symbols emitted by runtimes. | `PythonFrame`, or `NativeFrame` with `SymbolOrigin::PerfMap`. |
| ELF + debug data | Native user-space modules. Routed through a pluggable [`NativeSymbolizer`](crate::symbolize::NativeSymbolizer); default is `wholesym`. | `NativeFrame` with `SymbolOrigin::Elf`. |
| `/proc/kallsyms` | Kernel frames. | `NativeFrame` with `FrameKind::Kernel`. |
| Address fallback | No symbols or mapping unknown. | `NativeFrame` with `SymbolOrigin::AddressOnly`. |

Python frames exist only when the runtime emits perf-map entries. For
modern CPython that means running with `-X perf` or
`PYTHONPERFSUPPORT=1`. The recorder writes
Python-runtime records so readers can restrict perf-map lookup to PIDs that
actually looked like Python runtimes during recording.

The spool file does not embed perf-map content. Symbolization reads
`/tmp/perf-<pid>.map` by default. For later or remote analysis, preserve those
files and select their directory with `SymbolizerBuilder::perf_map_dir`.

Native frames inside the Python runtime get `FrameFlags::PYTHON_RUNTIME` and
`FrameFlags::HIDDEN_DEFAULT` when the symbolizer can identify them. UIs can
hide interpreter machinery by default while still letting users dig in.

Native symbolization is delegated to a `NativeSymbolizer` created per process.
The default is the bundled `wholesym`
backend, configured from `STACKPULSE_DEBUG_DIRS`, `DEBUGINFOD_URLS`, and
related environment variables. Applications with their own debuginfod,
debug-directory, or source-info setup can replace that backend through
`SymbolizerBuilder::native`; fallible setup can use
`SymbolizerBuilder::try_native`. `Symbolizer` still handles kernel and perf-map
resolution. Each `NativeLookup` contains the exact image selected by StackPulse and
the absolute, relative, and image addresses needed by a backend. Requests are
batched per process.

## Why spool files are small

Profiles repeat themselves. Hot loops produce the same frames and stacks
many times. The format exploits that:

- module records are written once when a mapping is discovered;
- thread IDs are interned;
- frame records are interned;
- stacks are stored as prefix nodes so common suffixes are shared;
- samples point to a thread ID and a stack ID;
- timestamps are stored as deltas.

Writes stay small and repeated stacks are cheap. `Snapshot` expands
stack IDs back into frame records when an analysis needs them.

## Processing while recording

`Tail` reads complete records from a spool that is still growing. Each poll
returns a bounded sample batch and any definitions needed by those samples.
The batch borrows reusable storage from the reader, so processing finishes
before the next poll reuses that storage.

Live symbolization has one extra step. `Symbolizer::update` installs the
batch's new definitions, refreshes changing symbol sources such as Python perf
maps, and reports which caller-owned prepared stacks are stale. Resource
retirement is ordered after the last batch that can refer to the retired
mapping. Recording and symbolization remain separate: the recorder only
unwinds and writes raw frames, while the tail-side consumer resolves them.

Definitions accumulate for the lifetime of a tail because later samples can
refer to earlier frame and stack IDs. Sample storage stays bounded and is
reused across polls. A consumer that falls behind reads consecutive batches
until `TailBatch::has_more()` becomes false, then waits for another writer
flush. That flag reports already-visible input; it does not report whether the
writer is alive.

## Accuracy and bias

Sampling has predictable limits:

- It records where threads were when samples fired, not every call.
- CPU-time sources under-represent off-CPU work (I/O, locks, sleep).
- Very high frequencies can lose events if buffers aren't drained fast
  enough.
- Unwinding can fail when stack bytes are short, metadata is missing, or
  the thread is in a hard-to-unwind state.
- Symbol quality depends on binaries, debug info, perf maps, kernel
  symbol visibility, and whether the mappings were observed.
- PID reuse makes stale `/tmp/perf-<pid>.map` files dangerous unless lookup
  is restricted to PIDs whose latest runtime record marks them as Python.

Check `RecordingSummary` before interpreting a profile. It reports the sample count,
lost events, effective data-ring capacity, empty stacks, truncation markers, and
unwind errors.

## Overhead

Recording costs:

- kernel interrupt + sample collection at the requested frequency;
- copied user stack bytes per sample;
- ring buffer traffic;
- native unwinding in `poll`;
- spool writes;
- extra events for many threads, CPUs, or inherited children.

Symbolization is intentionally off the hot path. ELF data, debug info,
kernel symbols, and perf maps are read lazily after recording.

To trim overhead: lower the sample rate or stack size, skip kernel frames
unless you need them, limit child-process inheritance, and drain often
enough from a dedicated worker that you don't lose events.

## Permissions

Linux perf access is gated by the kernel and by distro policy. The usual
gates:

- ownership of the target process;
- `/proc/sys/kernel/perf_event_paranoid`;
- `/proc/sys/kernel/perf_event_max_sample_rate`;
- capabilities such as `CAP_PERFMON` or `CAP_SYS_ADMIN`;
- `/proc/<pid>` visibility inside containers and PID namespaces;
- read access to `/proc/kallsyms` for kernel symbol names.

If kernel capture is denied, attach retries with user-space frames only and
sets `kernel_enabled` to `false`. Address-only frames can still be symbolized
later against the same binaries.
