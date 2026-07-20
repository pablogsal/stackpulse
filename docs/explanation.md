# How it works

This chapter explains the mental model behind stackpulse: how the kernel
samples threads, what ends up in the spool, why recording and symbolization
are separate phases, and where overhead and dropped frames come from. Read
it when something looks off in your profiles and you need to know whether
to blame the kernel, the symbolizer, or your own configuration.

## Sampling, not tracing

`stackpulse` is a statistical sampler. It doesn't record every function
call. The kernel periodically interrupts threads, snapshots enough state to
describe where they were, and drops records into perf ring buffers.

If a function shows up in 20% of samples, the right reading is "the program
was observed in or below that function about 20% of sampled time", not a
call count. Short functions can be invisible, and brief spikes can be missed
if no sample lands on them.

## The pipeline

```text
target threads
  → perf_event_open ring buffers
  → PerfRecorder::consume_available
  → native unwinding + module tracking
  → compact spool file
  → PerfSpoolReader
  → PerfSymbolizer
  → your aggregator / UI / exporter
```

The split is deliberate. Recording does only what's needed to preserve the
profile. Expensive optional work (symbol lookup, aggregation) happens
after the data is safely written.

## A short tour of perf events

`perf_event_open` is the Linux syscall that exposes the kernel's
Performance Monitoring Unit (PMU) and a handful of software event sources
to user space. You ask the kernel "tell me about this event for this task
on these CPUs" and get back a file descriptor. The kernel keeps a counter
behind that fd and, if you asked it to, also emits a stream of records
into a shared ring buffer whenever the event fires.

Two event families matter here:

- Hardware events from the CPU's PMU. The most useful one for profiling
  is the CPU cycles counter, which ticks whenever the core is running. The
  PMU is finite (a handful of counters per core) and many distros and
  virtualization layers restrict access to it.
- Software events synthesized by the kernel. The relevant fallback is the
  CPU clock, a monotonic per-task timer. It doesn't need PMU hardware, so
  it works inside containers and VMs where the PMU is hidden.

`stackpulse` tries hardware CPU cycles first and falls back to the software
CPU clock if the kernel refuses or the hardware event isn't available. Both
are CPU-time sources: they tick when a thread is actually on a CPU, so they
under-represent time spent blocked on I/O, locks, or sleep. Off-CPU
attribution is out of scope here; that needs a different sampling
discipline (sched switches, eBPF, or wallclock samplers).

Sampling vs. counting: when you set `freq` and a sample period, the kernel
treats the counter as a target rate and writes one record every time the
counter overflows the period. That's how a frequency-based profiler gets
roughly N samples per second per CPU without you knowing the exact cycle
count. The kernel adjusts the period over time to keep the rate near the
requested frequency.

For each target, `stackpulse` configures the event to emit:

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
in a header page. Because samples can be generated on any CPU, on many
CPUs in parallel, records from different buffers don't arrive in global
timestamp order. `wait` blocks (via `epoll` on the event fds) until at
least one buffer looks readable; `consume_available` then drains every
ready buffer, merges records across them by timestamp, updates the
recorder's view of processes and modules, runs the native unwinder on
sample records, and writes the resulting compact records to the spool.

If the consumer can't keep up, the ring buffer fills, the kernel starts
dropping samples, and emits a `LOST` record so we can count what was lost
in `PerfSummary.lost_events`. That's the single most important
back-pressure signal during recording.

## Attach modes

Two modes cover the practical cases:

`StopAttachEnableResume` is for an existing process. The recorder briefly
`SIGSTOP`s the target, opens the perf events, registers the executable
mappings from `/proc/<pid>/maps`, enables the events, and resumes the
target. The short stop window keeps the initial view of threads and
mappings consistent with what perf will see going forward.

`AttachWithEnableOnExec` is for a forked-but-not-yet-`execve`d child:
create the events first, let the kernel turn them on at `execve`, and
nothing is missed during startup.

## Threads vs. child processes

Perf events open against tasks. `stackpulse` tracks the process leader plus
known threads and asks perf to inherit events for new threads. When
inheritance isn't an option, `refresh_threads` scans `/proc/<pid>/task` and
opens missing ones.

Child processes are not threads. Use `inherit_child_processes` to follow
forks after recording starts. The recorder watches for fork events, clones
the relevant module state from the parent, and opens the child. Pre-existing
descendants need explicit attachment.

## Native stack capture

For user frames, perf hands us the interrupted thread's user registers plus
a bounded byte copy of the user stack. `framehop` unwinds from there. As with
`perf record --call-graph=dwarf`, the perf event excludes user callchains so
there is only one authoritative user unwind.

Stack-copy size is a trade-off. Too small and unwinding stops short, and
`PerfSummary.error_stats` shows truncation. Too large and every sample
copies more memory than necessary, which raises overhead at the same
sampling rate. Starting around `60 * 1024` and adjusting based on the
summary counters works for most workloads.

Return-address frames are normalized: each return address is rewound to the
instruction before the return target so symbol lookup lands on the call
site, not the next instruction after.

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

`PerfSymbolizer` resolves frames after the fact, from several sources:

| Source | Used for | Result |
| --- | --- | --- |
| Python perf maps (`/tmp/perf-<pid>.map`) | Python frames and JIT-like symbols emitted by runtimes. | `PythonFrame`, or `NativeFrame` with `SymbolOrigin::PerfMap`. |
| ELF + debug data | Native user-space modules. Routed through a pluggable [`NativeSymbolizer`]; default is wholesym. | `NativeFrame` with `SymbolOrigin::Elf`. |
| `/proc/kallsyms` | Kernel frames. | `NativeFrame` with `FrameKind::Kernel`. |
| Address fallback | No symbols or mapping unknown. | `NativeFrame` with `SymbolOrigin::AddressOnly`. |

Python frames exist only when the runtime emits perf-map entries. For
modern CPython, `-X perf` or `PYTHONPERFSUPPORT=1`. The recorder writes
Python-runtime records so readers can restrict perf-map lookup to PIDs that
actually looked like Python runtimes during recording.

The spool file does not embed perf-map content. Symbolization reads the
on-disk `/tmp/perf-<pid>.map`. If you'll analyze later, on another host, or
after the process exits, preserve those map files next to the spool.

Native frames inside the Python runtime get `FrameFlags::PYTHON_RUNTIME` and
`FrameFlags::HIDDEN_DEFAULT` when the symbolizer can identify them. UIs can
hide interpreter machinery by default while still letting users dig in.

Native symbolization is delegated to a `NativeSymbolizer` implementor, one
per non-overlapping module group. The default is the bundled wholesym
backend, configured from `STACKPULSE_DEBUG_DIRS`, `DEBUGINFOD_URLS`, and
related environment variables. Embedders with their own debuginfod,
debug-dir, or source-info pipeline can swap that backend through
`PerfSymbolizerBuilder::native_symbolizer_factory`, and `PerfSymbolizer` keeps owning
kernel-frame and perf-map resolution. Each `SymModule` handed to the plug-in
already carries a resolved `ModuleImageBase`, so the plug-in only needs to
parse ELF for symbol lookup, not for layout.

## Why spool files are small

Profiles repeat themselves. Hot loops produce the same frames and stacks
many times. The format exploits that:

- module records are written once when a mapping is discovered;
- thread IDs are interned;
- frame records are interned;
- stacks are stored as prefix nodes so common suffixes are shared;
- samples point to a thread ID and a stack ID;
- timestamps are stored as deltas.

Writes stay small and repeated stacks are cheap. `PerfSpoolReader` expands
stack IDs back into frame records when an analysis needs them.

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

The `PerfSummary` counters exist to make those limits visible. A profile is
only as trustworthy as those numbers say it is: check sample count, lost
events, empty stacks, truncation markers, and error stats before drawing
conclusions from a recording.

## Overhead

Recording costs:

- kernel interrupt + sample collection at the requested frequency;
- copied user stack bytes per sample;
- ring buffer traffic;
- native unwinding in `consume_available`;
- spool writes;
- extra events for many threads, CPUs, or inherited children.

Symbolization is intentionally off the hot path. ELF data, debug info,
kernel symbols, and perf maps are read lazily after recording.

To trim overhead: lower `frequency`, lower `stack_size`, skip kernel frames
unless you need them, limit child-process inheritance, and drain often
enough from a dedicated worker that you don't lose events.

## Permissions

Linux perf access is gated by the kernel and by distro policy. The usual
gates:

- ownership of the target process;
- `/proc/sys/kernel/perf_event_paranoid`;
- `/proc/sys/kernel/perf_event_max_sample_rate`;
- capabilities such as `CAP_PERFMON` (or full admin on older kernels);
- `/proc/<pid>` visibility inside containers and PID namespaces;
- read access to `/proc/kallsyms` for kernel symbol names.

Plan for graceful degradation. User-space capture without kernel frames is
usually still useful, and address-only frames remain useful as long as you
can symbolize them later against the same binaries.
