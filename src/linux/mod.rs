mod attach;
#[cfg(any(test, feature = "bench-support"))]
mod bench;
mod convert_regs;
mod cpu;
pub(crate) mod perf_event;
mod perf_group;
/// Spawn and attach helpers for the target process.
///
/// Provides [`process::SuspendedLaunchedProcess`] for launching a child in a
/// suspended state, used together with [`AttachMode::AttachWithEnableOnExec`]
/// so a recorder can be wired up before the target executes its first
/// instruction, and unsuspended afterwards.
pub mod process;
mod sorter;
mod types;
mod unwind;

#[cfg(any(test, feature = "bench-support"))]
pub(crate) use bench::{
    bench_parse_live_perf_samples, bench_replay_live_perf_ring_records,
    live_perf_sample_bench_fixture, LivePerfSampleBenchFixture,
};

use std::io;
use std::os::fd::RawFd;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use crate::state::{process_is_alive, try_new_exit_watcher, ProcessExitWatcher};
use crate::{SampleErrorKind, SampleErrorStats};
use framehop::{Error as FramehopError, FrameAddress, Unwinder};
use perf_event_open::sample::record::mmap::{Info as MmapInfo, Mmap};
use perf_event_open::sample::record::sample::Abi as SampleRegsAbi;
use perf_event_open::sample::record::sample::{CallChain, Sample};
use perf_event_open::sample::record::{Priv, Record};
use rustc_hash::{FxHashMap, FxHashSet};

use crate::spool::{FrameMode, FrameRecord, ModuleRecord, ModuleTable, PerfSpoolWriter};
use attach::read_process_start_time;
use convert_regs::ConvertRegs;
use perf_event::{
    CallChainEntry, CallChainIter, CallChainRef, EventRecord, EventRef, EventSource,
    SampleRecordRef,
};
pub use perf_group::AttachMode;
use perf_group::{EventConsumer, PerfGroupOptions, ProcessFork, RecoveredProcessFork, ThreadFork};
use sorter::EventSorter;
use types::{StackFrame, StackMode};
use unwind::{NativeUnwinder, ProcessUnwinder};

#[cfg(target_arch = "x86_64")]
type ConvertRegsNative = convert_regs::ConvertRegsX86_64;

#[cfg(target_arch = "aarch64")]
type ConvertRegsNative = convert_regs::ConvertRegsAarch64;

#[derive(Debug, PartialEq, Eq)]
enum LifecycleAction {
    ProcessRetire {
        pid: u32,
    },
    ProcessFork {
        pid: u32,
        parent_tid: u32,
    },
    ThreadFork {
        tid: u32,
        pid: u32,
        parent_tid: u32,
    },
    ThreadExit {
        tid: u32,
        pid: u32,
        timestamp_ns: u64,
    },
}

#[derive(Clone, Copy)]
enum DrainMode {
    Consume,
    Flush,
}

/// Options used when attaching a [`PerfRecorder`] to a process.
#[derive(Clone, Debug, Default)]
pub struct PerfRecorderOptions {
    /// Requested samples per second.
    pub frequency: u32,
    /// Number of bytes of user stack to copy per sample.
    pub stack_size: u32,
    /// Include kernel frames when the system permits it.
    pub include_kernel: bool,
    /// Follow child processes created after recording starts.
    pub inherit_child_processes: bool,
    /// Timestamp anchor stored in the spool file.
    pub start_timestamp_us: u64,
    /// Optional sampling interval metadata stored in the spool file.
    pub sample_interval_us: u64,
}

/// Counters collected while recording.
#[derive(Clone, Debug, Default)]
pub struct PerfSummary {
    /// Raw sample events seen by the recorder.
    pub sample_events: u64,
    /// Samples written to the spool file.
    pub samples: u64,
    /// Events reported lost by the kernel.
    pub lost_events: u64,
    /// Recovery passes triggered by one or more lost records.
    pub lifecycle_gaps: u64,
    /// Whether kernel frame capture remained enabled after attach.
    pub kernel_enabled: bool,
    /// Samples skipped because the process id was missing.
    pub missing_pid_samples: u64,
    /// Samples skipped because the thread id was missing.
    pub missing_tid_samples: u64,
    /// Samples skipped because they were attributed to an idle thread.
    pub idle_tid_samples: u64,
    /// Samples skipped because the timestamp was missing.
    pub missing_timestamp_samples: u64,
    /// Samples that did not contain frames.
    pub empty_stack_samples: u64,
    /// Markers written when a stack had to be truncated.
    pub truncated_frame_markers: u64,
    /// User callchain frames ignored because user stacks are unwound from DWARF.
    pub ignored_user_callchain_frames: u64,
    /// Per-kind sample error counts.
    pub error_stats: SampleErrorStats,
}

/// Records stack samples for one or more Linux processes.
pub struct PerfRecorder {
    perf: perf_group::PerfGroup,
    event_sorter: EventSorter<RawFd, u64, PreparedEvent>,
    writer: PerfSpoolWriter<std::io::BufWriter<std::fs::File>>,
    modules: ModuleTable,
    processes: ProcessTable,
    stack_scratch: Vec<StackFrame>,
    summary: PerfSummary,
}

struct EventContext<'a, W: std::io::Write> {
    modules: &'a mut ModuleTable,
    processes: &'a mut ProcessTable,
    writer: &'a mut PerfSpoolWriter<W>,
    summary: &'a mut PerfSummary,
    stack_scratch: &'a mut Vec<StackFrame>,
    lifecycle_actions: &'a mut Vec<LifecycleAction>,
    inherit_child_processes: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ProcessImageIdentity {
    device: u64,
    inode: u64,
}

#[derive(Default)]
enum ProcessTracking {
    #[default]
    Untracked,
    Tracked(Option<ProcessExitWatcher>),
}

impl ProcessTracking {
    fn is_tracked(&self) -> bool {
        matches!(self, Self::Tracked(_))
    }

    fn poll_alive(&mut self, pid: i32) -> Option<bool> {
        match self {
            Self::Untracked => None,
            Self::Tracked(watcher) => Some(process_is_alive(watcher, pid)),
        }
    }
}

#[derive(Default)]
struct ProcessState {
    tracking: ProcessTracking,
    unwinder: Option<ProcessUnwinder>,
    image: Option<ProcessImageIdentity>,
    start_time: Option<u64>,
    // Per-exec probe result. `None` means it has not been probed; `Some(false)`
    // deliberately avoids re-reading /proc for every runtime-looking mmap.
    python_perf_support: Option<bool>,
    python_runtime: bool,
}

#[derive(Default)]
struct ForkInheritance {
    image: Option<ProcessImageIdentity>,
    python_perf_support: Option<bool>,
    python_runtime: bool,
    unwinder: ProcessUnwinder,
}

#[derive(Default)]
struct ProcessTable {
    states: FxHashMap<i32, ProcessState>,
}

impl ProcessTable {
    fn state_mut(&mut self, pid: i32) -> &mut ProcessState {
        self.states.entry(pid).or_default()
    }

    fn snapshot_for_fork(&self, parent_pid: i32) -> ForkInheritance {
        self.states
            .get(&parent_pid)
            .map_or_else(ForkInheritance::default, |state| ForkInheritance {
                image: state.image.clone(),
                python_perf_support: state.python_perf_support,
                python_runtime: state.python_runtime,
                unwinder: state
                    .unwinder
                    .as_ref()
                    .map_or_else(ProcessUnwinder::default, ProcessUnwinder::inherit_for_fork),
            })
    }

    fn install_fork_inheritance(
        &mut self,
        child_pid: i32,
        start_time: Option<u64>,
        inheritance: ForkInheritance,
    ) {
        let child = self.state_mut(child_pid);
        if let Some(image) = inheritance.image {
            child.image = Some(image);
        }
        if let Some(start_time) = start_time {
            child.start_time = Some(start_time);
        }
        if let Some(supported) = inheritance.python_perf_support {
            child.python_perf_support = Some(supported);
        }
        child.python_runtime |= inheritance.python_runtime;
        child.unwinder = Some(inheritance.unwinder);
    }

    fn track_or_refresh(&mut self, pid: i32) {
        let state = self.state_mut(pid);
        match &mut state.tracking {
            ProcessTracking::Untracked => {
                state.tracking = ProcessTracking::Tracked(try_new_exit_watcher(pid));
            }
            ProcessTracking::Tracked(watcher) => {
                if !process_is_alive(watcher, pid) {
                    *watcher = try_new_exit_watcher(pid);
                }
            }
        }
    }

    fn ensure_tracked(&mut self, pid: i32) {
        let state = self.state_mut(pid);
        if !state.tracking.is_tracked() {
            state.tracking = ProcessTracking::Tracked(try_new_exit_watcher(pid));
        }
    }

    fn is_tracked(&self, pid: i32) -> bool {
        self.states
            .get(&pid)
            .is_some_and(|state| state.tracking.is_tracked())
    }

    fn tracked_pids(&self) -> Vec<i32> {
        self.states
            .iter()
            .filter_map(|(&pid, state)| state.tracking.is_tracked().then_some(pid))
            .collect()
    }

    fn dead_or_reused_pids(&mut self) -> Vec<i32> {
        self.states
            .iter_mut()
            .filter_map(|(&pid, state)| {
                let dead = !state.tracking.poll_alive(pid)?;
                let generation_changed = u32::try_from(pid)
                    .ok()
                    .and_then(|pid| read_process_start_time(pid).ok())
                    .zip(state.start_time)
                    .is_some_and(|(current, previous)| current != previous);
                (dead || generation_changed).then_some(pid)
            })
            .collect()
    }

    fn tracked_process_is_stale(
        &mut self,
        pid: i32,
        current_start_time: Option<u64>,
    ) -> Option<bool> {
        let state = self.states.get_mut(&pid)?;
        let alive = state.tracking.poll_alive(pid)?;
        Some(
            !alive
                || state
                    .start_time
                    .zip(current_start_time)
                    .is_some_and(|(previous, current)| current != previous),
        )
    }

    fn process_is_active(&mut self, pid: i32) -> bool {
        self.states
            .get_mut(&pid)
            .and_then(|state| state.tracking.poll_alive(pid))
            .unwrap_or(false)
    }

    fn has_active_processes_except(&mut self, excluded_pid: i32) -> bool {
        self.states.iter_mut().any(|(&pid, state)| {
            pid != excluded_pid && state.tracking.poll_alive(pid).unwrap_or(false)
        })
    }

    fn active_process_count(&mut self) -> usize {
        self.states
            .iter_mut()
            .filter_map(|(&pid, state)| state.tracking.poll_alive(pid)?.then_some(()))
            .count()
    }

    fn capture_available_generation(&mut self, pid: i32) {
        let Ok(proc_pid) = u32::try_from(pid) else {
            return;
        };
        let image = read_process_image_identity(proc_pid)
            .ok()
            .map(|(identity, _)| identity);
        let start_time = read_process_start_time(proc_pid).ok();
        let Some(state) = self.states.get_mut(&pid) else {
            return;
        };
        if let Some(image) = image {
            state.image = Some(image);
        }
        if let Some(start_time) = start_time {
            state.start_time = Some(start_time);
        }
    }

    fn forget_generation(&mut self, pid: i32) {
        if let Some(state) = self.states.get_mut(&pid) {
            state.image = None;
            state.start_time = None;
        }
    }
}

fn read_process_image_identity(pid: u32) -> io::Result<(ProcessImageIdentity, Vec<u8>)> {
    let exe = format!("/proc/{pid}/exe");
    let metadata = std::fs::metadata(exe)?;
    let mut comm = std::fs::read(format!("/proc/{pid}/comm"))?;
    while matches!(comm.last(), Some(b'\n' | b'\r')) {
        comm.pop();
    }
    Ok((
        ProcessImageIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        },
        comm,
    ))
}

enum PreparedEvent {
    Sample(PreparedSample),
    Record {
        timestamp_ns: u64,
        privilege: Priv,
        record: Record,
    },
}

struct PreparedSample {
    meta: PreparedSampleMeta,
    privilege: Priv,
    code_addr: Option<u64>,
    user_regs: Option<Vec<u64>>,
    user_stack: Option<Vec<u8>>,
    callchain_stack: Vec<StackFrame>,
}

struct PreparedSampleMeta {
    timestamp_ns: u64,
    pid: i32,
    tid: u64,
}

struct DrainSink<'a, W: std::io::Write> {
    ctx: EventContext<'a, W>,
    sorter: &'a mut EventSorter<RawFd, u64, PreparedEvent>,
    result: io::Result<()>,
    last_finished_timestamp_ns: u64,
}

impl<W: std::io::Write> EventConsumer for DrainSink<'_, W> {
    type Prepared = Option<PreparedEvent>;

    fn begin_group(&mut self, fd: RawFd) {
        self.sorter.begin_group(fd);
    }

    fn prepare_event(&mut self, event_ref: EventRef<'_>) -> Self::Prepared {
        if self.result.is_err() {
            return None;
        }
        prepare_event(event_ref, self.ctx.summary)
    }

    fn queue_event(&mut self, timestamp: u64, prepared: Self::Prepared) {
        let Some(prepared) = prepared else { return };
        self.sorter.push_current_group(timestamp, prepared);
    }

    fn drain_ready_events(&mut self) {
        self.drain_sorter(false);
    }

    fn advance_round(&mut self) {
        self.sorter.advance_round();
    }

    fn flush_ready_events(&mut self) {
        self.drain_sorter(true);
    }
}

impl<W: std::io::Write> DrainSink<'_, W> {
    fn drain_sorter(&mut self, force: bool) {
        loop {
            let prepared = if force {
                self.sorter.force_pop()
            } else {
                self.sorter.pop()
            };
            let Some(prepared) = prepared else { break };
            self.finish_event(prepared);
            if self.result.is_err() {
                break;
            }
        }
    }

    fn finish_event(&mut self, prepared: PreparedEvent) {
        if self.result.is_err() {
            return;
        }
        let timestamp_ns = match &prepared {
            PreparedEvent::Sample(sample) => sample.meta.timestamp_ns,
            PreparedEvent::Record { timestamp_ns, .. } => *timestamp_ns,
        };
        if let Err(err) = finish_prepared_event(prepared, &mut self.ctx) {
            self.result = Err(err);
        } else {
            self.last_finished_timestamp_ns = self.last_finished_timestamp_ns.max(timestamp_ns);
        }
    }
}

impl PerfRecorder {
    /// Attach to `pid` and start writing samples to `output`.
    ///
    /// Use [`AttachMode::StopAttachEnableResume`] for a process that is already
    /// running. Use [`AttachMode::AttachWithEnableOnExec`] with
    /// [`process::SuspendedLaunchedProcess`] when launching a new process.
    pub fn attach<P: AsRef<Path>>(
        pid: u32,
        output: P,
        attach_mode: AttachMode,
        options: PerfRecorderOptions,
    ) -> io::Result<Self> {
        let mut perf = open_perf_group(pid, attach_mode, &options)?;
        let kernel_enabled = perf.kernel_enabled();
        let mut writer = PerfSpoolWriter::create(
            output,
            options.start_timestamp_us,
            options.sample_interval_us,
        )
        .map_err(|err| perf.resume_error_or(err))?;
        let mut modules = ModuleTable::default();
        let mut processes = ProcessTable::default();
        if let Some(pid_i32) = i32_from_u32(pid) {
            processes.ensure_tracked(pid_i32);
            processes.capture_available_generation(pid_i32);
        }
        let python_perf_support = process_has_python_perf_support(pid, &mut processes);
        (|| {
            let registered_existing_maps = attach_mode == AttachMode::StopAttachEnableResume
                && register_existing_maps(pid, &mut modules, &mut processes, &mut writer)?;
            if let Some(pid_i32) =
                i32_from_u32(pid).filter(|_| registered_existing_maps && python_perf_support)
            {
                mark_python_runtime_process(&mut processes, &mut writer, 0, pid_i32)?;
            }
            Ok::<_, io::Error>(())
        })()
        .map_err(|err| perf.resume_error_or(err))?;

        let mut recorder = Self {
            perf,
            event_sorter: EventSorter::new(),
            writer,
            modules,
            processes,
            stack_scratch: Vec::with_capacity(128),
            summary: PerfSummary {
                kernel_enabled,
                ..PerfSummary::default()
            },
        };
        if attach_mode == AttachMode::StopAttachEnableResume {
            recorder.perf.enable()?;
        }
        Ok(recorder)
    }

    /// Drain currently readable events into the spool file.
    pub fn consume_available(&mut self) -> io::Result<()> {
        self.drain_events(DrainMode::Consume)
    }

    #[allow(clippy::cognitive_complexity)]
    fn drain_events(&mut self, mode: DrainMode) -> io::Result<()> {
        let open_new_perf_events = match mode {
            DrainMode::Consume => true,
            DrainMode::Flush => false,
        };
        let Self {
            perf,
            event_sorter,
            modules,
            processes,
            stack_scratch,
            writer,
            summary,
        } = self;
        let mut lifecycle_actions = Vec::new();
        let mut recovered_process_forks = Vec::new();
        let inherit_child_processes = perf.inherit_child_processes;
        let lifecycle_gaps_before = summary.lifecycle_gaps;
        let (mut result, recovery_timestamp_ns) = {
            let ctx = EventContext {
                modules,
                processes,
                writer,
                summary,
                stack_scratch,
                lifecycle_actions: &mut lifecycle_actions,
                inherit_child_processes,
            };
            let mut sink = DrainSink {
                ctx,
                sorter: event_sorter,
                result: Ok(()),
                last_finished_timestamp_ns: 0,
            };
            match mode {
                DrainMode::Consume => perf.consume_events(&mut sink),
                DrainMode::Flush => perf.flush_events(&mut sink),
            }
            if sink.result.is_ok() {
                match perf.take_lost_records() {
                    Ok(lost) => sink.result = record_lost_events(sink.ctx.summary, lost),
                    Err(err) => sink.result = Err(err),
                }
            }
            if sink.result.is_ok() && sink.ctx.summary.lifecycle_gaps != lifecycle_gaps_before {
                // A /proc snapshot is current state, not state at the LOST
                // record timestamp. Drain every event already collected before
                // installing that snapshot so it cannot resolve older samples.
                sink.drain_sorter(true);
            }
            (sink.result, sink.last_finished_timestamp_ns)
        };
        let recovered_lifecycle_gap = summary.lifecycle_gaps != lifecycle_gaps_before;
        // Replay lifecycle mutations in event order. Batching forks and exits
        // by kind breaks when the kernel reuses a PID or TID in one drain.
        if result.is_ok() {
            for action in &lifecycle_actions {
                let action_result = match *action {
                    LifecycleAction::ProcessRetire { pid } => perf.remove_process(pid),
                    LifecycleAction::ProcessFork { pid, parent_tid } if open_new_perf_events => {
                        perf.open_forked_processes(&[ProcessFork { pid, parent_tid }])
                    }
                    LifecycleAction::ThreadFork {
                        tid,
                        pid,
                        parent_tid,
                    } if open_new_perf_events => perf.open_forked_threads(&[ThreadFork {
                        tid,
                        owner_pid: pid,
                        parent_tid,
                    }]),
                    LifecycleAction::ThreadExit { tid, .. } => perf.remove_thread(tid),
                    LifecycleAction::ProcessFork { .. } | LifecycleAction::ThreadFork { .. } => {
                        Ok(())
                    }
                };
                if let Err(err) = action_result {
                    result = Err(err);
                    break;
                }
            }
        }
        if result.is_ok() {
            let dead_processes = processes.dead_or_reused_pids();
            for pid in dead_processes {
                if let Ok(pid_u32) = u32::try_from(pid) {
                    if let Err(err) = perf.remove_process(pid_u32) {
                        result = Err(err);
                        break;
                    }
                }
                let timestamp_ns = lifecycle_actions
                    .iter()
                    .filter_map(|action| match action {
                        LifecycleAction::ThreadExit {
                            pid: exit_pid,
                            timestamp_ns,
                            ..
                        } if i32_from_u32(*exit_pid) == Some(pid) => Some(*timestamp_ns),
                        _ => None,
                    })
                    .max()
                    .unwrap_or(recovery_timestamp_ns);
                if let Err(err) = end_python_runtime_process(processes, writer, timestamp_ns, pid) {
                    result = Err(err);
                    break;
                }
                if let Err(err) = cleanup_process(pid, modules, processes, writer) {
                    result = Err(err);
                    break;
                }
            }
        }
        if result.is_ok() && recovered_lifecycle_gap {
            let tracked_pids = processes.tracked_pids();
            for pid in tracked_pids {
                let Ok(pid_u32) = u32::try_from(pid) else {
                    continue;
                };
                match reconcile_process_image(
                    pid_u32,
                    recovery_timestamp_ns,
                    modules,
                    processes,
                    writer,
                ) {
                    Ok(true) => {}
                    Ok(false) => {
                        if let Err(err) = perf.remove_process(pid_u32) {
                            result = Err(err);
                            break;
                        }
                        if let Err(err) = cleanup_process(pid, modules, processes, writer) {
                            result = Err(err);
                            break;
                        }
                    }
                    Err(err) => {
                        result = Err(err);
                        break;
                    }
                }
            }
        }
        if result.is_ok()
            && open_new_perf_events
            && recovered_lifecycle_gap
            && inherit_child_processes
        {
            let roots = processes.tracked_pids();
            let mut discovered = FxHashSet::default();
            for root in roots {
                for (child, parent) in crate::children::discover_descendant_edges(root) {
                    if !discovered.insert(child) || processes.is_tracked(child) {
                        continue;
                    }
                    let Ok(child_u32) = u32::try_from(child) else {
                        continue;
                    };
                    let python_perf_support = process_has_python_perf_support(child_u32, processes);
                    match register_existing_maps(child_u32, modules, processes, writer) {
                        Ok(true) if python_perf_support => {
                            if let Err(err) = mark_python_runtime_process(
                                processes,
                                writer,
                                recovery_timestamp_ns,
                                child,
                            ) {
                                result = Err(err);
                                break;
                            }
                        }
                        Ok(_) => {}
                        Err(err) if process_gone_error(&err) => continue,
                        Err(err) => {
                            result = Err(err);
                            break;
                        }
                    }
                    processes.ensure_tracked(child);
                    processes.capture_available_generation(child);
                    if let Ok(parent_u32) = u32::try_from(parent) {
                        recovered_process_forks.push(RecoveredProcessFork {
                            pid: child_u32,
                            parent_pid: parent_u32,
                        });
                    }
                }
                if result.is_err() {
                    break;
                }
            }
        }
        if result.is_ok() && open_new_perf_events {
            result = perf.recover_forked_processes(&recovered_process_forks);
        }
        if result.is_ok() && open_new_perf_events && recovered_lifecycle_gap {
            for pid in processes
                .tracked_pids()
                .into_iter()
                .filter_map(|pid| u32::try_from(pid).ok())
            {
                if let Err(err) = perf.refresh_threads(pid) {
                    if !process_gone_error(&err) {
                        result = Err(err);
                        break;
                    }
                }
            }
        }
        summary.kernel_enabled &= perf.kernel_enabled();
        result
    }

    /// Wait briefly for more profiling data to become readable.
    pub fn wait(&mut self) -> io::Result<()> {
        if self.event_sorter.has_more() {
            return Ok(());
        }
        self.perf.wait()
    }

    /// Add another process to this recording.
    pub fn open_process(&mut self, pid: u32, attach_mode: AttachMode) -> io::Result<()> {
        if let Some(pid_i32) = i32_from_u32(pid).filter(|pid| self.processes.is_tracked(*pid)) {
            let current_start_time = self
                .processes
                .states
                .get(&pid_i32)
                .and_then(|state| state.start_time)
                .and_then(|_| read_process_start_time(pid).ok());
            let stale = self
                .processes
                .tracked_process_is_stale(pid_i32, current_start_time)
                .expect("filtered to a tracked process");
            // Reopen only after proving that the old process is gone or
            // that this numeric PID now identifies a new generation.
            if !stale {
                return Ok(());
            }
            self.perf.remove_process(pid)?;
            cleanup_process(
                pid_i32,
                &mut self.modules,
                &mut self.processes,
                &mut self.writer,
            )?;
        }
        let opened = self.perf.open_process(pid, attach_mode)?;
        if let Some(pid_i32) = i32_from_u32(pid) {
            self.processes.track_or_refresh(pid_i32);
            self.processes.capture_available_generation(pid_i32);
            let python_perf_support = process_has_python_perf_support(pid, &mut self.processes);
            match register_existing_maps(
                pid,
                &mut self.modules,
                &mut self.processes,
                &mut self.writer,
            ) {
                Ok(true) if python_perf_support => {
                    if let Err(err) = mark_python_runtime_process(
                        &mut self.processes,
                        &mut self.writer,
                        0,
                        pid_i32,
                    ) {
                        return Err(self.rollback_open_process(pid, opened, err));
                    }
                }
                Ok(_) => {}
                Err(err) => {
                    return Err(self.rollback_open_process(pid, opened, err));
                }
            }
        }
        if attach_mode == AttachMode::StopAttachEnableResume {
            if let Err(err) = self.perf.enable() {
                return Err(self.rollback_open_process(pid, opened, err));
            }
        }
        self.summary.kernel_enabled &= self.perf.kernel_enabled();
        Ok(())
    }

    /// Discover newly-created threads for `pid` when needed.
    pub fn refresh_threads(&mut self, pid: u32) -> io::Result<()> {
        self.perf.refresh_threads(pid)
    }

    /// Disable sampling for all attached processes.
    pub fn disable(&mut self) {
        let _ = self.perf.disable();
    }

    /// Return whether userspace has queued events or [`Self::wait`] observed a
    /// readable perf buffer.
    pub fn has_pending_events(&self) -> bool {
        self.event_sorter.has_more() || self.perf.has_pending_events()
    }

    /// Return a snapshot of the current counters.
    pub fn summary(&self) -> PerfSummary {
        self.summary.clone()
    }

    /// Return whether `pid` is still believed to be alive.
    pub fn process_is_active(&mut self, pid: i32) -> bool {
        self.processes.process_is_active(pid)
    }

    /// Return whether any active process other than `pid` remains.
    pub fn has_active_processes_except(&mut self, pid: i32) -> bool {
        self.processes.has_active_processes_except(pid)
    }

    /// Return the number of processes still believed to be alive.
    pub fn active_process_count(&mut self) -> usize {
        self.processes.active_process_count()
    }

    /// Flush the spool file and return the final counters.
    pub fn finish(mut self) -> io::Result<PerfSummary> {
        self.perf.disable()?;
        self.drain_events(DrainMode::Flush)?;
        self.writer.flush()?;
        Ok(self.summary)
    }

    fn rollback_open_process(
        &mut self,
        pid: u32,
        opened: perf_group::OpenTransaction,
        original_error: io::Error,
    ) -> io::Error {
        let error = self.perf.resume_error_or(original_error);
        self.perf.rollback_open(opened);
        if let Some(pid) = i32_from_u32(pid) {
            let _ = cleanup_process(
                pid,
                &mut self.modules,
                &mut self.processes,
                &mut self.writer,
            );
        }
        error
    }
}

fn prepare_event(event_ref: EventRef, summary: &mut PerfSummary) -> Option<PreparedEvent> {
    let event_timestamp_ns = event_ref.timestamp().unwrap_or(0);
    let (privilege, record) = event_ref.into_parts();
    match record {
        EventRecord::Sample(sample) => prepare_sample_ref(summary, sample, privilege),
        EventRecord::Owned(Record::Sample(sample)) => prepare_sample(summary, *sample, privilege),
        EventRecord::Owned(record) => Some(PreparedEvent::Record {
            timestamp_ns: event_timestamp_ns,
            privilege,
            record,
        }),
    }
}

fn handle_non_sample_record<W: std::io::Write>(
    event_timestamp_ns: u64,
    privilege: Priv,
    record: Record,
    ctx: &mut EventContext<'_, W>,
) -> io::Result<()> {
    match record {
        Record::Mmap(mmap) => {
            record_mmap(ctx.modules, ctx.processes, ctx.writer, &mmap, privilege)?;
            record_python_runtime_mmap(
                &mmap,
                privilege,
                event_timestamp_ns,
                ctx.processes,
                ctx.writer,
            )
        }
        Record::Fork(fork) if fork.task.pid != fork.parent_task.pid => {
            if !ctx.inherit_child_processes {
                return Ok(());
            }
            let Some(pid) = i32_from_u32(fork.task.pid) else {
                return Ok(());
            };
            let Some(ppid) = i32_from_u32(fork.parent_task.pid) else {
                return Ok(());
            };

            // Snapshot all inherited state before touching the child: numeric
            // PID reuse can make child cleanup mutate the same table.
            let mut inheritance = ctx.processes.snapshot_for_fork(ppid);
            let current_start_time = read_process_start_time(fork.task.pid).ok();
            let reused_pid = ctx
                .processes
                .tracked_process_is_stale(pid, current_start_time)
                .unwrap_or(false);
            if reused_pid {
                end_python_runtime_process(ctx.processes, ctx.writer, event_timestamp_ns, pid)?;
                cleanup_process(pid, ctx.modules, ctx.processes, ctx.writer)?;
                ctx.lifecycle_actions
                    .push(LifecycleAction::ProcessRetire { pid: fork.task.pid });
            }
            ctx.processes.ensure_tracked(pid);
            if inheritance.python_runtime {
                mark_python_runtime_process(ctx.processes, ctx.writer, event_timestamp_ns, pid)?;
            }
            let updates = ctx.modules.clone_process_modules(ppid, pid, ctx.writer)?;
            for update in &updates {
                inheritance.unwinder.apply_module_update(update);
            }
            ctx.processes
                .install_fork_inheritance(pid, current_start_time, inheritance);
            ctx.lifecycle_actions.push(LifecycleAction::ProcessFork {
                pid: fork.task.pid,
                parent_tid: fork.parent_task.tid,
            });
            Ok(())
        }
        Record::Fork(fork) if fork.task.pid == fork.parent_task.pid => {
            if fork.task.tid != fork.parent_task.tid {
                ctx.lifecycle_actions.push(LifecycleAction::ThreadFork {
                    tid: fork.task.tid,
                    pid: fork.task.pid,
                    parent_tid: fork.parent_task.tid,
                });
            }
            Ok(())
        }
        Record::Comm(comm) if comm.task.pid == comm.task.tid => {
            let Some(pid) = i32_from_u32(comm.task.pid) else {
                return Ok(());
            };
            let current = read_process_image_identity(comm.task.pid).ok();
            let identity_changed = current.as_ref().is_some_and(|(identity, current_comm)| {
                ctx.processes
                    .states
                    .get(&pid)
                    .and_then(|state| state.image.as_ref())
                    .is_some_and(|previous| {
                        previous.device != identity.device || previous.inode != identity.inode
                    })
                    && current_comm.as_slice() == comm.comm.as_bytes()
            });
            if !comm.by_execve && !identity_changed {
                return Ok(());
            }

            // A confirmed exec is an epoch boundary. Do not read current maps
            // here: the subsequent MMAP records retain their proper ordering.
            cleanup_process_modules(pid, ctx.modules, ctx.processes, ctx.writer)?;
            if let Some(state) = ctx.processes.states.get_mut(&pid) {
                state.python_perf_support = None;
            }
            end_python_runtime_process(ctx.processes, ctx.writer, event_timestamp_ns, pid)?;
            ctx.processes.state_mut(pid).image = current.map(|(identity, _)| identity);
            Ok(())
        }
        Record::Exit(exit) => {
            // pid == tid identifies the thread-group leader, not necessarily
            // the death of the process: the leader may call pthread_exit while
            // siblings continue. Retire the thread here; drain_events performs
            // process cleanup only after pidfd or /proc confirms group death.
            ctx.lifecycle_actions.push(LifecycleAction::ThreadExit {
                tid: exit.task.tid,
                pid: exit.task.pid,
                timestamp_ns: event_timestamp_ns,
            });
            Ok(())
        }
        Record::LostRecords(_) => Ok(()),
        Record::LostSamples(lost) => {
            ctx.summary.lost_events = ctx.summary.lost_events.saturating_add(lost.lost_samples);
            Ok(())
        }
        _ => Ok(()),
    }
}

fn record_lost_events(summary: &mut PerfSummary, lost: u64) -> io::Result<()> {
    if lost == 0 {
        return Ok(());
    }
    summary.lost_events = summary
        .lost_events
        .checked_add(lost)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "perf lost-record overflow"))?;
    summary.lifecycle_gaps = summary
        .lifecycle_gaps
        .checked_add(1)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "perf lifecycle-gap overflow"))?;
    Ok(())
}

fn i32_from_u32(value: u32) -> Option<i32> {
    i32::try_from(value).ok()
}

fn cleanup_process(
    pid: i32,
    modules: &mut ModuleTable,
    processes: &mut ProcessTable,
    writer: &mut PerfSpoolWriter<impl std::io::Write>,
) -> io::Result<()> {
    let result = cleanup_process_modules(pid, modules, processes, writer);
    processes.states.remove(&pid);
    result
}

fn cleanup_process_modules<W: std::io::Write>(
    pid: i32,
    modules: &mut ModuleTable,
    processes: &mut ProcessTable,
    writer: &mut PerfSpoolWriter<W>,
) -> io::Result<()> {
    modules.deactivate_process_modules(pid, writer)?;
    if let Some(state) = processes.states.get_mut(&pid) {
        state.unwinder = None;
    }
    Ok(())
}

fn reconcile_process_image<W: std::io::Write>(
    pid: u32,
    timestamp_ns: u64,
    modules: &mut ModuleTable,
    processes: &mut ProcessTable,
    writer: &mut PerfSpoolWriter<W>,
) -> io::Result<bool> {
    let Some(pid_i32) = i32_from_u32(pid) else {
        return Ok(false);
    };

    let current_start_time = match read_process_start_time(pid) {
        Ok(start_time) => start_time,
        Err(err) if process_gone_error(&err) => {
            processes.forget_generation(pid_i32);
            return Ok(false);
        }
        Err(err) => return Err(err),
    };
    // /proc/<tgid>/exe can disappear after the thread-group leader exits even
    // while sibling threads remain alive. Start time and the maps snapshot,
    // not the exe symlink alone, determine whether this generation survives.
    let current_identity = read_process_image_identity(pid)
        .ok()
        .map(|(identity, _)| identity);

    let maps = match std::fs::read_to_string(format!("/proc/{pid}/maps")) {
        Ok(maps) => maps,
        Err(err) if process_gone_error(&err) => {
            processes.forget_generation(pid_i32);
            return Ok(false);
        }
        Err(err) => return Err(err),
    };
    let snapshot = executable_modules_from_maps(pid, &maps);
    if snapshot.is_empty() {
        // A live group whose leader has exited can expose an empty maps file.
        // Without a usable replacement snapshot, preserve the last known
        // modules and unwinder instead of destructively reconciling to empty.
        return Ok(true);
    }

    let image_matches = current_identity.as_ref().is_none_or(|identity| {
        processes
            .states
            .get(&pid_i32)
            .and_then(|state| state.image.as_ref())
            == Some(identity)
    });
    let start_time_matches = processes
        .states
        .get(&pid_i32)
        .and_then(|state| state.start_time)
        == Some(current_start_time);
    if image_matches && start_time_matches && modules.process_modules_match(pid_i32, &snapshot) {
        if let Some(identity) = current_identity {
            processes.state_mut(pid_i32).image = Some(identity);
        }
        return Ok(true);
    }

    cleanup_process_modules(pid_i32, modules, processes, writer)?;
    if let Some(state) = processes.states.get_mut(&pid_i32) {
        state.python_perf_support = None;
    }
    end_python_runtime_process(processes, writer, timestamp_ns, pid_i32)?;

    match register_existing_modules(snapshot, modules, processes, writer) {
        Ok(saw_python_runtime) => {
            let should_mark_python =
                saw_python_runtime && process_has_python_perf_support(pid, processes);
            let state = processes.state_mut(pid_i32);
            if let Some(identity) = current_identity {
                state.image = Some(identity);
            }
            state.start_time = Some(current_start_time);
            if should_mark_python {
                mark_python_runtime_process(processes, writer, timestamp_ns, pid_i32)?;
            }
            Ok(true)
        }
        Err(err) if process_gone_error(&err) => {
            processes.forget_generation(pid_i32);
            Ok(false)
        }
        Err(err) => Err(err),
    }
}

fn process_gone_error(err: &io::Error) -> bool {
    err.kind() == io::ErrorKind::NotFound || err.raw_os_error() == Some(libc::ESRCH)
}

fn process_has_python_perf_support_enabled(pid: u32) -> bool {
    process_has_python_perf_support_env(pid)
        || std::fs::read(format!("/proc/{pid}/cmdline"))
            .ok()
            .is_some_and(|cmdline| cmdline_has_python_perf_support(&cmdline))
}

fn process_has_python_perf_support_env(pid: u32) -> bool {
    std::fs::read(format!("/proc/{pid}/environ"))
        .ok()
        .is_some_and(|env| {
            env.split(|byte| *byte == 0)
                .any(|entry| entry == b"PYTHONPERFSUPPORT=1")
        })
}

fn cmdline_has_python_perf_support(cmdline: &[u8]) -> bool {
    let mut args = cmdline
        .split(|byte| *byte == 0)
        .filter(|arg| !arg.is_empty())
        .peekable();
    while let Some(arg) = args.next() {
        if arg == b"-Xperf" {
            return true;
        }
        if arg == b"-X"
            && args
                .peek()
                .is_some_and(|next| *next == b"perf" || next.starts_with(b"perf,"))
        {
            return true;
        }
    }
    false
}

fn process_has_python_perf_support(pid: u32, processes: &mut ProcessTable) -> bool {
    let Some(pid_i32) = i32_from_u32(pid) else {
        return false;
    };
    if let Some(supported) = processes
        .states
        .get(&pid_i32)
        .and_then(|state| state.python_perf_support)
    {
        return supported;
    }
    let supported = process_has_python_perf_support_enabled(pid);
    processes.state_mut(pid_i32).python_perf_support = Some(supported);
    supported
}

fn mark_python_runtime_process<W: std::io::Write>(
    processes: &mut ProcessTable,
    writer: &mut PerfSpoolWriter<W>,
    timestamp_ns: u64,
    pid: i32,
) -> io::Result<()> {
    let state = processes.state_mut(pid);
    if !std::mem::replace(&mut state.python_runtime, true) {
        writer.write_python_runtime(timestamp_ns, pid, true)?;
    }
    Ok(())
}

fn end_python_runtime_process<W: std::io::Write>(
    processes: &mut ProcessTable,
    writer: &mut PerfSpoolWriter<W>,
    timestamp_ns: u64,
    pid: i32,
) -> io::Result<()> {
    let Some(state) = processes.states.get_mut(&pid) else {
        return Ok(());
    };
    if !state.python_runtime {
        return Ok(());
    }
    writer.write_python_runtime(timestamp_ns, pid, false)?;
    state.python_runtime = false;
    Ok(())
}

fn record_python_runtime_mmap<W: std::io::Write>(
    mmap: &Mmap,
    privilege: Priv,
    timestamp_ns: u64,
    processes: &mut ProcessTable,
    writer: &mut PerfSpoolWriter<W>,
) -> io::Result<()> {
    if is_kernel_mode(privilege) || !mmap_is_executable(mmap) {
        return Ok(());
    }
    let Some(pid) = i32_from_u32(mmap.task.pid) else {
        return Ok(());
    };
    use std::os::unix::ffi::OsStrExt;

    let path = std::path::Path::new(std::ffi::OsStr::from_bytes(mmap.file.as_bytes()));
    if !crate::is_python_runtime_module_path(path) {
        return Ok(());
    }
    if process_has_python_perf_support(mmap.task.pid, processes) {
        mark_python_runtime_process(processes, writer, timestamp_ns, pid)?;
    }
    Ok(())
}

fn prepare_sample(
    summary: &mut PerfSummary,
    sample: Sample,
    privilege: Priv,
) -> Option<PreparedEvent> {
    let Sample {
        record_id,
        call_chain,
        user_stack,
        code_addr,
        user_regs,
        ..
    } = sample;
    let task = record_id.task.as_ref().map(|task| (task.pid, task.tid));
    let meta = prepare_sample_meta(summary, task, record_id.time)?;

    Some(PreparedEvent::Sample(PreparedSample {
        meta,
        privilege,
        code_addr: code_addr.map(|(ip, _)| ip),
        user_regs: user_regs.and_then(|(regs, abi)| (abi == SampleRegsAbi::_64).then_some(regs)),
        user_stack,
        callchain_stack: call_chain
            .as_deref()
            .map_or(SampleCallChain::None, SampleCallChain::Owned)
            .to_stack_frames(),
    }))
}

fn prepare_sample_ref(
    summary: &mut PerfSummary,
    sample: SampleRecordRef<'_>,
    privilege: Priv,
) -> Option<PreparedEvent> {
    prepare_sample_view(summary, SampleView::from_ref(sample), privilege)
}

#[derive(Clone, Copy)]
struct SampleView<'a> {
    task: Option<(u32, u32)>,
    timestamp_ns: Option<u64>,
    code_addr: Option<u64>,
    user_regs: Option<&'a [u64]>,
    user_stack: Option<&'a [u8]>,
    call_chain: SampleCallChain<'a>,
}

#[derive(Clone, Copy)]
struct StackInput<'a> {
    code_addr: Option<u64>,
    user_regs: Option<&'a [u64]>,
    user_stack: Option<&'a [u8]>,
}

#[derive(Clone, Copy)]
enum SampleCallChain<'a> {
    None,
    Owned(&'a [CallChain]),
    Borrowed(CallChainRef<'a>),
}

enum SampleCallChainIter<'a> {
    None,
    Owned(std::slice::Iter<'a, CallChain>),
    Borrowed(CallChainIter<'a>),
}

impl<'a> SampleCallChain<'a> {
    fn iter(self) -> SampleCallChainIter<'a> {
        match self {
            SampleCallChain::None => SampleCallChainIter::None,
            SampleCallChain::Owned(chains) => SampleCallChainIter::Owned(chains.iter()),
            SampleCallChain::Borrowed(chains) => SampleCallChainIter::Borrowed(chains.iter()),
        }
    }

    fn stack_frame_capacity(self) -> usize {
        match self {
            SampleCallChain::None => 0,
            SampleCallChain::Borrowed(chains) => chains.raw_address_count(),
            SampleCallChain::Owned(_) => self.iter().map(|(_, addresses)| addresses.len()).sum(),
        }
    }

    fn to_stack_frames(self) -> Vec<StackFrame> {
        let mut frames = Vec::with_capacity(self.stack_frame_capacity());
        push_sample_callchain(self, &mut frames);
        frames
    }
}

impl<'a> Iterator for SampleCallChainIter<'a> {
    type Item = (StackMode, &'a [u64]);

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            SampleCallChainIter::None => None,
            SampleCallChainIter::Owned(chains) => {
                for chain in chains {
                    let entry = match chain {
                        CallChain::Kernel(addresses)
                        | CallChain::Hv(addresses)
                        | CallChain::GuestKernel(addresses) => {
                            (StackMode::Kernel, addresses.as_slice())
                        }
                        CallChain::User(addresses)
                        | CallChain::Guest(addresses)
                        | CallChain::GuestUser(addresses)
                        | CallChain::Unknown(addresses) => (StackMode::User, addresses.as_slice()),
                        CallChain::UserDeferred { .. } => continue,
                    };
                    return Some(entry);
                }
                None
            }
            SampleCallChainIter::Borrowed(chains) => chains.next().map(|chain| match chain {
                CallChainEntry::Kernel(addresses)
                | CallChainEntry::Hv(addresses)
                | CallChainEntry::GuestKernel(addresses) => (StackMode::Kernel, addresses),
                CallChainEntry::User(addresses)
                | CallChainEntry::Guest(addresses)
                | CallChainEntry::GuestUser(addresses)
                | CallChainEntry::Unknown(addresses) => (StackMode::User, addresses),
            }),
        }
    }
}

impl<'a> SampleView<'a> {
    fn from_ref(sample: SampleRecordRef<'a>) -> Self {
        Self {
            task: sample.task.map(|task| (task.pid, task.tid)),
            timestamp_ns: sample.time,
            code_addr: sample.code_addr.map(|(ip, _)| ip),
            user_regs: sample.user_regs,
            user_stack: sample.user_stack,
            call_chain: sample
                .call_chain
                .map_or(SampleCallChain::None, SampleCallChain::Borrowed),
        }
    }

    #[cfg(test)]
    fn stack_input(self) -> StackInput<'a> {
        StackInput {
            code_addr: self.code_addr,
            user_regs: self.user_regs,
            user_stack: self.user_stack,
        }
    }
}

fn prepare_sample_view(
    summary: &mut PerfSummary,
    sample: SampleView<'_>,
    privilege: Priv,
) -> Option<PreparedEvent> {
    let meta = prepare_sample_meta(summary, sample.task, sample.timestamp_ns)?;

    Some(PreparedEvent::Sample(PreparedSample {
        meta,
        privilege,
        code_addr: sample.code_addr,
        user_regs: sample.user_regs.map(<[u64]>::to_vec),
        user_stack: sample.user_stack.map(<[u8]>::to_vec),
        callchain_stack: sample.call_chain.to_stack_frames(),
    }))
}

fn prepare_sample_meta(
    summary: &mut PerfSummary,
    task: Option<(u32, u32)>,
    timestamp_ns: Option<u64>,
) -> Option<PreparedSampleMeta> {
    bump(&mut summary.sample_events);
    let Some((raw_pid, raw_tid)) = task else {
        bump(&mut summary.missing_pid_samples);
        return None;
    };
    let Some(pid) = i32_from_u32(raw_pid) else {
        bump(&mut summary.missing_pid_samples);
        return None;
    };
    let Some(tid) = i32_from_u32(raw_tid) else {
        bump(&mut summary.missing_tid_samples);
        return None;
    };
    if tid == 0 {
        bump(&mut summary.idle_tid_samples);
        return None;
    }
    let Some(timestamp_ns) = timestamp_ns else {
        bump(&mut summary.missing_timestamp_samples);
        return None;
    };

    Some(PreparedSampleMeta {
        timestamp_ns,
        pid,
        tid: tid as u64,
    })
}

fn finish_prepared_event<W: std::io::Write>(
    prepared: PreparedEvent,
    ctx: &mut EventContext<'_, W>,
) -> io::Result<()> {
    match prepared {
        PreparedEvent::Sample(sample) => record_prepared_sample(ctx, sample),
        PreparedEvent::Record {
            timestamp_ns,
            privilege,
            record,
        } => handle_non_sample_record(timestamp_ns, privilege, record, ctx),
    }
}

fn record_prepared_sample<W: std::io::Write>(
    ctx: &mut EventContext<'_, W>,
    sample: PreparedSample,
) -> io::Result<()> {
    let pid = sample.meta.pid;
    refresh_maps_for_uncovered_user_pc(ctx, &sample)?;
    let input = StackInput {
        code_addr: sample.code_addr,
        user_regs: sample.user_regs.as_deref(),
        user_stack: sample.user_stack.as_deref(),
    };
    let unwinder = ctx
        .processes
        .state_mut(pid)
        .unwinder
        .get_or_insert_default();
    build_sample_stack::<ConvertRegsNative>(
        input,
        sample.privilege,
        unwinder,
        ctx.stack_scratch,
        &sample.callchain_stack,
        ctx.summary,
    );
    let stack_id = {
        let modules = &mut *ctx.modules;
        let summary = &mut *ctx.summary;
        ctx.writer.write_sample_frames(
            sample.meta.timestamp_ns,
            pid,
            sample.meta.tid,
            ctx.stack_scratch
                .iter()
                .copied()
                .filter_map(|frame| resolve_stack_frame(modules, summary, pid, frame)),
        )
    };
    match stack_id {
        Ok(None) => {
            bump(&mut ctx.summary.empty_stack_samples);
            Ok(())
        }
        Ok(Some(_)) => {
            bump(&mut ctx.summary.samples);
            Ok(())
        }
        Err(err) => Err(err),
    }
}

fn refresh_maps_for_uncovered_user_pc<W: std::io::Write>(
    ctx: &mut EventContext<'_, W>,
    sample: &PreparedSample,
) -> io::Result<()> {
    let Some(pid) = u32::try_from(sample.meta.pid).ok() else {
        return Ok(());
    };
    let register_pc = sample
        .user_regs
        .as_deref()
        .and_then(ConvertRegsNative::convert_regs)
        .map(|(pc, _, _)| pc);
    let sampled_user_pc = matches!(sample.privilege, Priv::User)
        .then_some(sample.code_addr)
        .flatten();
    let Some(pc) = register_pc.or(sampled_user_pc) else {
        return Ok(());
    };
    if ctx.modules.covers_user_pc(sample.meta.pid, pc) {
        return Ok(());
    }
    if !ctx
        .processes
        .state_mut(sample.meta.pid)
        .unwinder
        .get_or_insert_default()
        .should_refresh_for_uncovered_pc(pc)
    {
        return Ok(());
    }
    match register_existing_maps(pid, ctx.modules, ctx.processes, ctx.writer) {
        Ok(true) if process_has_python_perf_support(pid, ctx.processes) => {
            mark_python_runtime_process(
                ctx.processes,
                ctx.writer,
                sample.meta.timestamp_ns,
                sample.meta.pid,
            )
        }
        Ok(_) => Ok(()),
        Err(err) if process_gone_error(&err) => Ok(()),
        Err(err) => Err(err),
    }
}

fn bump(counter: &mut u64) {
    *counter = counter.saturating_add(1);
}

fn record_unwind_error(
    summary: &mut PerfSummary,
    kind: SampleErrorKind,
    context: impl FnOnce() -> String,
) {
    summary.error_stats.record_with_log(kind, context);
}

#[inline]
fn sample_error_for_framehop(error: FramehopError) -> SampleErrorKind {
    match error {
        FramehopError::CouldNotReadStack(_) => SampleErrorKind::NativeStackTruncated,
        FramehopError::DidNotAdvance => SampleErrorKind::NativeFramehopDidNotAdvance,
        FramehopError::ReturnAddressIsNull => SampleErrorKind::NativeFramehopReturnAddressNull,
        FramehopError::FramepointerUnwindingMovedBackwards => {
            SampleErrorKind::NativeFramehopMovedBackwards
        }
        FramehopError::IntegerOverflow => SampleErrorKind::NativeFramehopIntegerOverflow,
    }
}

fn is_kernel_mode(privilege: Priv) -> bool {
    matches!(privilege, Priv::Kernel | Priv::GuestKernel)
}

fn record_module<W: std::io::Write>(
    modules: &mut ModuleTable,
    processes: &mut ProcessTable,
    writer: &mut PerfSpoolWriter<W>,
    module: ModuleRecord,
) -> io::Result<()> {
    if module.path.is_empty() {
        return Ok(());
    }
    let update = modules.apply_module(module, writer)?;
    if update.active.is_empty() {
        return Ok(());
    }
    for activation in &update.active {
        let module = &activation.module;
        if !module.is_kernel {
            processes
                .state_mut(module.process_id)
                .unwinder
                .get_or_insert_default()
                .apply_module_update(&update);
            break;
        }
    }
    Ok(())
}

struct MmapEvent<'a> {
    pid: i32,
    privilege: Priv,
    is_executable: bool,
    address: u64,
    length: u64,
    page_offset: u64,
    path: &'a std::ffi::CString,
    inode: u64,
    device_major: u32,
    device_minor: u32,
    inode_generation: u64,
}

fn record_mmap_event<W: std::io::Write>(
    modules: &mut ModuleTable,
    processes: &mut ProcessTable,
    writer: &mut PerfSpoolWriter<W>,
    event: MmapEvent<'_>,
) -> io::Result<()> {
    let is_kernel = is_kernel_mode(event.privilege);
    if !is_kernel && !event.is_executable {
        return Ok(());
    }
    record_module(
        modules,
        processes,
        writer,
        ModuleRecord {
            id: 0,
            process_id: event.pid,
            start: event.address,
            end: event.address.saturating_add(event.length),
            file_offset: event.page_offset,
            path: c_string_to_string(event.path).into(),
            is_kernel,
            inode: event.inode,
            device_major: event.device_major,
            device_minor: event.device_minor,
            inode_generation: event.inode_generation,
        },
    )
}

fn record_mmap<W: std::io::Write>(
    modules: &mut ModuleTable,
    processes: &mut ProcessTable,
    writer: &mut PerfSpoolWriter<W>,
    mmap: &Mmap,
    privilege: Priv,
) -> io::Result<()> {
    let (inode, device_major, device_minor, inode_generation) = match &mmap.ext {
        Some(ext) => match &ext.info {
            MmapInfo::Device {
                major,
                minor,
                inode,
                inode_gen,
            } => (*inode, *major, *minor, *inode_gen),
            MmapInfo::BuildId(_) => (0, 0, 0, 0),
        },
        None => (0, 0, 0, 0),
    };
    let Some(pid) = i32_from_u32(mmap.task.pid) else {
        return Ok(());
    };
    record_mmap_event(
        modules,
        processes,
        writer,
        MmapEvent {
            pid,
            privilege,
            is_executable: mmap_is_executable(mmap),
            address: mmap.addr,
            length: mmap.len,
            page_offset: mmap.page_offset,
            path: &mmap.file,
            inode,
            device_major,
            device_minor,
            inode_generation,
        },
    )
}

fn mmap_is_executable(mmap: &Mmap) -> bool {
    const PROT_EXEC: u32 = 0b100;
    match &mmap.ext {
        Some(ext) => ext.prot & PROT_EXEC != 0,
        None => mmap.executable,
    }
}

fn open_perf_group(
    pid: u32,
    attach_mode: AttachMode,
    options: &PerfRecorderOptions,
) -> io::Result<perf_group::PerfGroup> {
    let regs_mask = ConvertRegsNative::regs_mask();
    perf_group::PerfGroup::open(
        pid,
        attach_mode,
        PerfGroupOptions {
            frequency: options.frequency,
            stack_size: options.stack_size,
            event_source: EventSource::HwCpuCycles,
            regs_mask,
            include_kernel: options.include_kernel,
            inherit_child_processes: options.inherit_child_processes,
        },
    )
}

fn register_existing_maps<W: std::io::Write>(
    pid: u32,
    modules: &mut ModuleTable,
    processes: &mut ProcessTable,
    writer: &mut PerfSpoolWriter<W>,
) -> io::Result<bool> {
    let maps = std::fs::read_to_string(format!("/proc/{pid}/maps"))?;
    register_existing_maps_snapshot(pid, &maps, modules, processes, writer)
}

fn register_existing_maps_snapshot<W: std::io::Write>(
    pid: u32,
    maps: &str,
    modules: &mut ModuleTable,
    processes: &mut ProcessTable,
    writer: &mut PerfSpoolWriter<W>,
) -> io::Result<bool> {
    register_existing_modules(
        executable_modules_from_maps(pid, maps),
        modules,
        processes,
        writer,
    )
}

fn executable_modules_from_maps(pid: u32, maps: &str) -> Vec<ModuleRecord> {
    crate::proc_maps::parse_iter(maps)
        .filter(|region| region.is_executable && !region.path.is_empty())
        .map(|region| ModuleRecord {
            id: 0,
            process_id: pid as i32,
            start: region.address.start,
            end: region.address.end,
            file_offset: region.file_offset,
            path: region.path.into(),
            is_kernel: false,
            inode: region.inode,
            device_major: region.device_major,
            device_minor: region.device_minor,
            inode_generation: 0,
        })
        .collect()
}

fn register_existing_modules<W: std::io::Write>(
    snapshot: Vec<ModuleRecord>,
    modules: &mut ModuleTable,
    processes: &mut ProcessTable,
    writer: &mut PerfSpoolWriter<W>,
) -> io::Result<bool> {
    let mut saw_python_runtime = false;
    for module in snapshot {
        saw_python_runtime |= crate::is_python_runtime_module_path(&module.path);
        record_module(modules, processes, writer, module)?;
    }
    Ok(saw_python_runtime)
}

#[cfg(test)]
fn get_sample_stack<C: ConvertRegs<UnwindRegs = <NativeUnwinder as Unwinder>::UnwindRegs>>(
    sample: SampleView<'_>,
    privilege: Priv,
    process_unwinder: &mut ProcessUnwinder,
    stack: &mut Vec<StackFrame>,
    callchain_stack: &mut Vec<StackFrame>,
    summary: &mut PerfSummary,
) {
    callchain_stack.clear();
    push_sample_callchain(sample.call_chain, callchain_stack);
    build_sample_stack::<C>(
        sample.stack_input(),
        privilege,
        process_unwinder,
        stack,
        callchain_stack,
        summary,
    );
}

fn build_sample_stack<C: ConvertRegs<UnwindRegs = <NativeUnwinder as Unwinder>::UnwindRegs>>(
    sample: StackInput<'_>,
    privilege: Priv,
    process_unwinder: &mut ProcessUnwinder,
    stack: &mut Vec<StackFrame>,
    callchain_stack: &[StackFrame],
    summary: &mut PerfSummary,
) {
    const MAX_NATIVE_UNWIND_FRAMES: usize = 1_024;

    stack.clear();

    let kernel_frame_count = callchain_stack
        .iter()
        .take_while(|&&frame| stack_frame_is_kernel(frame))
        .count();
    let (kernel_callchain_frames, user_callchain_frames) =
        callchain_stack.split_at(kernel_frame_count);
    stack.extend_from_slice(kernel_callchain_frames);
    let dwarf_start = stack.len();
    let mut dwarf_truncated = false;
    let user_stack = sample.user_stack.filter(|stack| !stack.is_empty());

    if sample.user_stack.is_some() && user_stack.is_none() {
        record_unwind_error(summary, SampleErrorKind::NativeStackRead, || {
            "perf sample reported zero user stack bytes".to_string()
        });
    }
    match (sample.user_regs, user_stack) {
        (Some(raw_regs), Some(user_stack)) => {
            if let Some((pc, sp, regs)) = C::convert_regs(raw_regs) {
                let (user_stack_words, _) = user_stack.as_chunks::<8>();
                let mut read_stack = |addr: u64| {
                    let index = addr
                        .checked_sub(sp)
                        .filter(|offset| offset % 8 == 0)
                        .and_then(|offset| usize::try_from(offset / 8).ok())
                        .ok_or(())?;
                    read_stack_u64(user_stack_words, index)
                };

                let mut frames = process_unwinder.unwinder.iter_frames(
                    pc,
                    regs,
                    &mut process_unwinder.cache,
                    &mut read_stack,
                );
                loop {
                    if stack.len().saturating_sub(dwarf_start) >= MAX_NATIVE_UNWIND_FRAMES {
                        dwarf_truncated = true;
                        break;
                    }
                    match frames.next() {
                        Ok(None) => break,
                        Ok(Some(FrameAddress::InstructionPointer(a))) => {
                            stack.push(StackFrame::InstructionPointer(a, StackMode::User))
                        }
                        Ok(Some(FrameAddress::ReturnAddress(a))) => {
                            stack.push(StackFrame::ReturnAddress(a.into(), StackMode::User))
                        }
                        Err(err) => {
                            record_unwind_error(summary, sample_error_for_framehop(err), || {
                                format!("framehop error during perf native unwind: {err}")
                            });
                            dwarf_truncated = true;
                            break;
                        }
                    }
                }
            } else {
                record_unwind_error(summary, SampleErrorKind::NativeRegisterCapture, || {
                    "perf sample contained incomplete user register state".to_string()
                });
            }
        }
        _ if !is_kernel_mode(privilege) => {
            if sample.user_regs.is_none() {
                record_unwind_error(summary, SampleErrorKind::NativeUserRegistersMissing, || {
                    "perf sample did not include user register state".to_string()
                });
            }
            if sample.user_stack.is_none() {
                record_unwind_error(summary, SampleErrorKind::NativeStackRead, || {
                    "perf sample did not include user stack bytes".to_string()
                });
            }
        }
        _ => {}
    }

    summary.ignored_user_callchain_frames = summary
        .ignored_user_callchain_frames
        .saturating_add(user_callchain_frames.len() as u64);
    if dwarf_truncated {
        stack.push(StackFrame::TruncatedStackMarker);
    }

    if stack.is_empty() {
        if let Some(ip) = sample.code_addr {
            stack.push(StackFrame::InstructionPointer(ip, privilege.into()));
        }
    }
}

fn stack_frame_is_kernel(frame: StackFrame) -> bool {
    matches!(
        frame,
        StackFrame::InstructionPointer(_, StackMode::Kernel)
            | StackFrame::ReturnAddress(_, StackMode::Kernel)
    )
}

fn push_sample_callchain(call_chain: SampleCallChain<'_>, stack: &mut Vec<StackFrame>) {
    for (mode, addresses) in call_chain.iter() {
        push_callchain_addresses(mode, addresses, stack);
    }
}

fn push_callchain_addresses(mode: StackMode, addresses: &[u64], stack: &mut Vec<StackFrame>) {
    for (index, &address) in addresses.iter().enumerate() {
        stack.push(if index == 0 {
            StackFrame::InstructionPointer(address, mode)
        } else {
            StackFrame::ReturnAddress(address, mode)
        });
    }
}

fn read_stack_u64(stack: &[[u8; 8]], index: usize) -> Result<u64, ()> {
    stack.get(index).copied().map(u64::from_ne_bytes).ok_or(())
}

fn resolve_stack_frame(
    modules: &mut ModuleTable,
    summary: &mut PerfSummary,
    process_id: i32,
    frame: StackFrame,
) -> Option<FrameRecord> {
    let (address, mode) = match frame {
        StackFrame::InstructionPointer(address, mode) => (address, mode),
        StackFrame::ReturnAddress(address, mode) => (address.saturating_sub(1), mode),
        StackFrame::TruncatedStackMarker => {
            summary.truncated_frame_markers = summary.truncated_frame_markers.saturating_add(1);
            return Some(FrameRecord::truncated_stack_marker());
        }
    };
    Some(modules.resolve_frame(process_id, address, frame_mode(mode)))
}

fn frame_mode(mode: StackMode) -> FrameMode {
    match mode {
        StackMode::User => FrameMode::User,
        StackMode::Kernel => FrameMode::Kernel,
    }
}

fn c_string_to_string(data: &std::ffi::CString) -> String {
    String::from_utf8_lossy(data.as_bytes()).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{SleepChild, TempDir};
    use perf_event_open::sample::record::comm::Comm;
    use perf_event_open::sample::record::lost::{LostRecords, LostSamples};
    use perf_event_open::sample::record::task::{Exit, Fork};
    use perf_event_open::sample::record::Task;

    #[test]
    fn perf_recorder_is_send() {
        fn assert_send<T: Send>() {}

        assert_send::<PerfRecorder>();
    }

    #[test]
    fn untracked_process_metadata_is_not_active() {
        let pid = i32::MAX;
        let mut processes = ProcessTable::default();
        let state = processes.state_mut(pid);
        state.unwinder = Some(ProcessUnwinder::default());
        state.image = Some(ProcessImageIdentity {
            device: 1,
            inode: 2,
        });
        state.start_time = Some(3);
        state.python_perf_support = Some(false);
        state.python_runtime = true;

        assert!(!processes.is_tracked(pid));
        assert!(processes.tracked_pids().is_empty());
        assert!(processes.dead_or_reused_pids().is_empty());
        assert_eq!(processes.tracked_process_is_stale(pid, Some(3)), None);
        assert!(!processes.process_is_active(pid));
        assert!(!processes.has_active_processes_except(0));
        assert_eq!(processes.active_process_count(), 0);
    }

    #[test]
    fn tracked_process_queries_follow_liveness() {
        let live_pid = i32::try_from(std::process::id()).expect("current PID fits in i32");
        let missing_pid = i32::MAX;
        let mut processes = ProcessTable::default();

        processes.track_or_refresh(live_pid);
        processes.track_or_refresh(live_pid);
        processes.track_or_refresh(missing_pid);
        processes.track_or_refresh(missing_pid);

        assert!(processes.is_tracked(live_pid));
        assert!(processes.is_tracked(missing_pid));
        let mut tracked = processes.tracked_pids();
        tracked.sort_unstable();
        assert_eq!(tracked, [live_pid, missing_pid]);
        assert_eq!(
            processes.tracked_process_is_stale(live_pid, None),
            Some(false)
        );
        assert_eq!(
            processes.tracked_process_is_stale(missing_pid, None),
            Some(true)
        );
        assert!(processes.process_is_active(live_pid));
        assert!(!processes.process_is_active(missing_pid));
        assert!(processes.has_active_processes_except(missing_pid));
        assert!(!processes.has_active_processes_except(live_pid));
        assert_eq!(processes.active_process_count(), 1);
        assert_eq!(processes.dead_or_reused_pids(), [missing_pid]);
    }

    #[test]
    fn reopening_the_same_process_is_idempotent() {
        let child = SleepChild::spawn();
        let temp = TempDir::new("duplicate-open");
        let mut recorder = match PerfRecorder::attach(
            child.pid_u32(),
            temp.path().join("profile.stackpulse"),
            AttachMode::StopAttachEnableResume,
            PerfRecorderOptions {
                frequency: 1,
                ..PerfRecorderOptions::default()
            },
        ) {
            Ok(recorder) => recorder,
            Err(err)
                if matches!(
                    err.kind(),
                    io::ErrorKind::PermissionDenied | io::ErrorKind::Unsupported
                ) || matches!(err.raw_os_error(), Some(libc::ENOSYS | libc::EOPNOTSUPP)) =>
            {
                return;
            }
            Err(err) => panic!("attach recorder: {err}"),
        };
        let before = recorder.perf.resource_counts();

        recorder
            .open_process(child.pid_u32(), AttachMode::StopAttachEnableResume)
            .expect("repeat process attachment");

        assert_eq!(recorder.perf.resource_counts(), before);
    }

    #[test]
    fn leader_exit_retires_thread_without_deactivating_process_modules() {
        let pid = std::process::id();
        let pid_i32 = i32::try_from(pid).unwrap();
        let mut modules = ModuleTable::default();
        let mut processes = ProcessTable::default();
        let mut writer = PerfSpoolWriter::from_writer(Vec::new(), 0, 0).unwrap();
        let mut summary = PerfSummary::default();
        let mut stack_scratch = Vec::new();
        let mut lifecycle_actions = Vec::new();
        let mut module = test_module(0x1000, 0x2000);
        module.process_id = pid_i32;
        modules.intern_module(module, &mut writer).unwrap();

        {
            let mut ctx = EventContext {
                modules: &mut modules,
                processes: &mut processes,
                writer: &mut writer,
                summary: &mut summary,
                stack_scratch: &mut stack_scratch,
                lifecycle_actions: &mut lifecycle_actions,
                inherit_child_processes: false,
            };
            handle_non_sample_record(
                123,
                Priv::User,
                Record::Exit(Box::new(Exit {
                    record_id: None,
                    task: Task { pid, tid: pid },
                    parent_task: Task { pid: 1, tid: 1 },
                    time: 123,
                })),
                &mut ctx,
            )
            .unwrap();
        }

        assert!(matches!(
            lifecycle_actions.as_slice(),
            [LifecycleAction::ThreadExit { tid, .. }] if *tid == pid
        ));
        assert!(modules
            .resolve_frame(pid_i32, 0x1800, FrameMode::User)
            .module_id
            .is_some());
    }

    #[test]
    fn reused_tid_actions_preserve_exit_then_fork_order() {
        let pid = std::process::id();
        let tid = pid.saturating_add(1);
        let mut modules = ModuleTable::default();
        let mut processes = ProcessTable::default();
        let mut writer = PerfSpoolWriter::from_writer(Vec::new(), 0, 0).unwrap();
        let mut summary = PerfSummary::default();
        let mut stack_scratch = Vec::new();
        let mut lifecycle_actions = Vec::new();
        let mut ctx = EventContext {
            modules: &mut modules,
            processes: &mut processes,
            writer: &mut writer,
            summary: &mut summary,
            stack_scratch: &mut stack_scratch,
            lifecycle_actions: &mut lifecycle_actions,
            inherit_child_processes: false,
        };

        handle_non_sample_record(
            100,
            Priv::User,
            Record::Exit(Box::new(Exit {
                record_id: None,
                task: Task { pid, tid },
                parent_task: Task { pid: 1, tid: 1 },
                time: 100,
            })),
            &mut ctx,
        )
        .unwrap();
        handle_non_sample_record(
            101,
            Priv::User,
            Record::Fork(Box::new(Fork {
                record_id: None,
                task: Task { pid, tid },
                parent_task: Task { pid, tid: pid },
                time: 101,
            })),
            &mut ctx,
        )
        .unwrap();

        assert_eq!(
            lifecycle_actions,
            [
                LifecycleAction::ThreadExit {
                    tid,
                    pid,
                    timestamp_ns: 100,
                },
                LifecycleAction::ThreadFork {
                    tid,
                    pid,
                    parent_tid: pid,
                },
            ]
        );
    }

    #[test]
    fn ring_lost_record_is_not_counted_twice() {
        let pid = i32::try_from(std::process::id()).unwrap();
        let mut modules = ModuleTable::default();
        let mut processes = ProcessTable::default();
        let mut writer = PerfSpoolWriter::from_writer(Vec::new(), 0, 0).unwrap();
        let mut summary = PerfSummary::default();
        let mut stack_scratch = Vec::new();
        let mut lifecycle_actions = Vec::new();
        let mut module = test_module(0x1000, 0x2000);
        module.process_id = pid;
        modules.intern_module(module, &mut writer).unwrap();

        let mut ctx = EventContext {
            modules: &mut modules,
            processes: &mut processes,
            writer: &mut writer,
            summary: &mut summary,
            stack_scratch: &mut stack_scratch,
            lifecycle_actions: &mut lifecycle_actions,
            inherit_child_processes: false,
        };
        handle_non_sample_record(
            123,
            Priv::User,
            Record::LostRecords(Box::new(LostRecords {
                record_id: None,
                id: 99,
                lost_records: 7,
            })),
            &mut ctx,
        )
        .unwrap();
        handle_non_sample_record(
            124,
            Priv::User,
            Record::LostSamples(Box::new(LostSamples {
                record_id: None,
                lost_samples: 11,
            })),
            &mut ctx,
        )
        .unwrap();

        assert_eq!(summary.lost_events, 11);
        assert_eq!(summary.lifecycle_gaps, 0);
        assert!(modules
            .resolve_frame(pid, 0x1800, FrameMode::User)
            .module_id
            .is_some());
    }

    #[test]
    fn authoritative_loss_advances_loss_and_recovery_once() {
        let mut summary = PerfSummary::default();

        record_lost_events(&mut summary, 0).unwrap();
        assert_eq!((summary.lost_events, summary.lifecycle_gaps), (0, 0));

        record_lost_events(&mut summary, 7).unwrap();
        assert_eq!((summary.lost_events, summary.lifecycle_gaps), (7, 1));

        summary.lost_events = u64::MAX;
        assert_eq!(
            record_lost_events(&mut summary, 1).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn empty_maps_snapshot_cannot_replace_live_process_modules() {
        assert!(executable_modules_from_maps(42, "").is_empty());
        assert!(executable_modules_from_maps(42, "1000-2000 r-xp 00000000 00:00 0\n").is_empty());
        assert_eq!(
            executable_modules_from_maps(42, "1000-2000 r-xp 00000000 08:01 42 /tmp/lib.so\n")
                .len(),
            1
        );
    }

    #[test]
    fn unchanged_process_reconciliation_preserves_module_generation() {
        let pid = std::process::id();
        let pid_i32 = i32::try_from(pid).unwrap();
        let maps = std::fs::read_to_string(format!("/proc/{pid}/maps")).unwrap();
        let snapshot = executable_modules_from_maps(pid, &maps);
        let probe_address = snapshot.first().expect("executable mapping").start;
        let mut modules = ModuleTable::default();
        let mut processes = ProcessTable::default();
        let mut writer = PerfSpoolWriter::from_writer(Vec::new(), 0, 0).unwrap();
        register_existing_modules(snapshot, &mut modules, &mut processes, &mut writer).unwrap();
        let module_id = modules
            .resolve_frame(pid_i32, probe_address, FrameMode::User)
            .module_id
            .expect("registered mapping");
        let state = processes.state_mut(pid_i32);
        state.image = Some(read_process_image_identity(pid).unwrap().0);
        state.start_time = Some(read_process_start_time(pid).unwrap());

        assert!(
            reconcile_process_image(pid, 123, &mut modules, &mut processes, &mut writer,).unwrap()
        );
        assert_eq!(
            modules
                .resolve_frame(pid_i32, probe_address, FrameMode::User)
                .module_id,
            Some(module_id)
        );
    }

    #[test]
    fn ordinary_leader_comm_does_not_create_an_exec_epoch() {
        let pid_u32 = std::process::id();
        let pid = i32::try_from(pid_u32).unwrap();
        let (identity, current_comm) = read_process_image_identity(pid_u32).unwrap();
        let mut modules = ModuleTable::default();
        let mut processes = ProcessTable::default();
        processes.state_mut(pid).image = Some(identity);
        let mut writer = PerfSpoolWriter::from_writer(Vec::new(), 0, 0).unwrap();
        let mut summary = PerfSummary::default();
        let mut stack_scratch = Vec::new();
        let mut lifecycle_actions = Vec::new();
        let mut module = test_module(0x1000, 0x2000);
        module.process_id = pid;
        let module_id = modules.intern_module(module, &mut writer).unwrap();

        let mut ctx = EventContext {
            modules: &mut modules,
            processes: &mut processes,
            writer: &mut writer,
            summary: &mut summary,
            stack_scratch: &mut stack_scratch,
            lifecycle_actions: &mut lifecycle_actions,
            inherit_child_processes: false,
        };
        handle_non_sample_record(
            123,
            Priv::User,
            Record::Comm(Box::new(Comm {
                record_id: None,
                by_execve: false,
                task: Task {
                    pid: pid_u32,
                    tid: pid_u32,
                },
                comm: std::ffi::CString::new(current_comm).unwrap(),
            })),
            &mut ctx,
        )
        .unwrap();

        assert_eq!(
            modules
                .resolve_frame(pid, 0x1800, FrameMode::User)
                .module_id,
            Some(module_id)
        );
    }

    #[test]
    fn fork_inherits_event_time_image_and_later_comm_detects_exec() {
        let child_pid_u32 = std::process::id();
        let child_pid = i32::try_from(child_pid_u32).unwrap();
        let parent_pid = 1;
        let inherited_identity = ProcessImageIdentity {
            device: u64::MAX,
            inode: u64::MAX,
        };
        let (_, current_comm) = read_process_image_identity(child_pid_u32).unwrap();
        let mut modules = ModuleTable::default();
        let mut processes = ProcessTable::default();
        processes.state_mut(parent_pid).image = Some(inherited_identity.clone());
        let mut writer = PerfSpoolWriter::from_writer(Vec::new(), 0, 0).unwrap();
        let mut summary = PerfSummary::default();
        let mut stack_scratch = Vec::new();
        let mut lifecycle_actions = Vec::new();
        let mut module = test_module(0x1000, 0x2000);
        module.process_id = parent_pid;
        modules.intern_module(module, &mut writer).unwrap();

        let mut ctx = EventContext {
            modules: &mut modules,
            processes: &mut processes,
            writer: &mut writer,
            summary: &mut summary,
            stack_scratch: &mut stack_scratch,
            lifecycle_actions: &mut lifecycle_actions,
            inherit_child_processes: true,
        };
        handle_non_sample_record(
            100,
            Priv::User,
            Record::Fork(Box::new(Fork {
                record_id: None,
                task: Task {
                    pid: child_pid_u32,
                    tid: child_pid_u32,
                },
                parent_task: Task { pid: 1, tid: 1 },
                time: 100,
            })),
            &mut ctx,
        )
        .unwrap();

        assert_eq!(
            ctx.processes
                .states
                .get(&child_pid)
                .and_then(|state| state.image.as_ref()),
            Some(&inherited_identity)
        );
        assert!(ctx
            .processes
            .states
            .get(&child_pid)
            .is_some_and(|state| state.start_time.is_some()));
        assert!(ctx
            .modules
            .resolve_frame(child_pid, 0x1800, FrameMode::User)
            .module_id
            .is_some());

        handle_non_sample_record(
            101,
            Priv::User,
            Record::Comm(Box::new(Comm {
                record_id: None,
                by_execve: false,
                task: Task {
                    pid: child_pid_u32,
                    tid: child_pid_u32,
                },
                comm: std::ffi::CString::new(current_comm).unwrap(),
            })),
            &mut ctx,
        )
        .unwrap();

        assert!(ctx
            .modules
            .resolve_frame(child_pid, 0x1800, FrameMode::User)
            .module_id
            .is_none());
    }

    #[test]
    fn uncovered_pc_refresh_is_once_per_page() {
        let mut unwinder = ProcessUnwinder::default();
        let page_size = crate::elf::system_page_size();

        assert!(unwinder.should_refresh_for_uncovered_pc(page_size + 1));
        assert!(!unwinder.should_refresh_for_uncovered_pc(page_size + 2));
        assert!(unwinder.should_refresh_for_uncovered_pc(page_size * 2));
    }

    #[test]
    fn uncovered_user_sample_ip_refreshes_without_unwind_registers() {
        let pid_u32 = std::process::id();
        let pid = i32::try_from(pid_u32).unwrap();
        let pc = uncovered_user_sample_ip_refreshes_without_unwind_registers as *const () as u64;
        let mut modules = ModuleTable::default();
        let mut processes = ProcessTable::default();
        let mut writer = PerfSpoolWriter::from_writer(Vec::new(), 0, 0).unwrap();
        let mut summary = PerfSummary::default();
        let mut stack_scratch = Vec::new();
        let mut lifecycle_actions = Vec::new();
        let mut ctx = EventContext {
            modules: &mut modules,
            processes: &mut processes,
            writer: &mut writer,
            summary: &mut summary,
            stack_scratch: &mut stack_scratch,
            lifecycle_actions: &mut lifecycle_actions,
            inherit_child_processes: false,
        };
        let sample = PreparedSample {
            meta: PreparedSampleMeta {
                timestamp_ns: 0,
                pid,
                tid: u64::from(pid_u32),
            },
            privilege: Priv::User,
            code_addr: Some(pc),
            user_regs: None,
            user_stack: None,
            callchain_stack: Vec::new(),
        };

        refresh_maps_for_uncovered_user_pc(&mut ctx, &sample).unwrap();

        assert!(ctx.modules.covers_user_pc(pid, pc));
    }

    #[test]
    fn hypervisor_sample_ip_does_not_refresh_user_maps() {
        let pid_u32 = std::process::id();
        let pid = i32::try_from(pid_u32).unwrap();
        let pc = hypervisor_sample_ip_does_not_refresh_user_maps as *const () as u64;
        let mut modules = ModuleTable::default();
        let mut processes = ProcessTable::default();
        let mut writer = PerfSpoolWriter::from_writer(Vec::new(), 0, 0).unwrap();
        let mut summary = PerfSummary::default();
        let mut stack_scratch = Vec::new();
        let mut lifecycle_actions = Vec::new();
        let mut ctx = EventContext {
            modules: &mut modules,
            processes: &mut processes,
            writer: &mut writer,
            summary: &mut summary,
            stack_scratch: &mut stack_scratch,
            lifecycle_actions: &mut lifecycle_actions,
            inherit_child_processes: false,
        };
        let sample = PreparedSample {
            meta: PreparedSampleMeta {
                timestamp_ns: 0,
                pid,
                tid: u64::from(pid_u32),
            },
            privilege: Priv::Hv,
            code_addr: Some(pc),
            user_regs: None,
            user_stack: None,
            callchain_stack: Vec::new(),
        };

        refresh_maps_for_uncovered_user_pc(&mut ctx, &sample).unwrap();

        assert!(!ctx.modules.covers_user_pc(pid, pc));
    }

    #[test]
    fn forked_unwinder_resets_refresh_cache() {
        let mut unwinder = ProcessUnwinder::default();
        assert!(unwinder.should_refresh_for_uncovered_pc(0x3000));

        let mut inherited = unwinder.inherit_for_fork();

        assert!(inherited.should_refresh_for_uncovered_pc(0x3000));
    }

    fn test_module(start: u64, end: u64) -> ModuleRecord {
        ModuleRecord {
            id: 0,
            process_id: 7,
            start,
            end,
            file_offset: 0,
            inode: 0,
            device_major: 0,
            device_minor: 0,
            inode_generation: 0,
            path: "/tmp/libtest.so".into(),
            is_kernel: false,
        }
    }

    #[test]
    fn sample_prepare_defers_unwind_until_finish() {
        let mut modules = ModuleTable::default();
        let mut processes = ProcessTable::default();
        let mut writer = PerfSpoolWriter::from_writer(Vec::new(), 0, 0).expect("spool writer");
        let mut summary = PerfSummary::default();
        let mut stack_scratch = Vec::new();
        let mut lifecycle_actions = Vec::new();
        let user_stack = [0_u8; 8];
        let chains = vec![CallChain::User(vec![0x1000, 0x2000])];
        let sample = SampleView {
            task: Some((7, 8)),
            timestamp_ns: Some(42),
            code_addr: None,
            user_regs: Some(&[]),
            user_stack: Some(&user_stack),
            call_chain: SampleCallChain::Owned(&chains),
        };
        let prepared =
            prepare_sample_view(&mut summary, sample, Priv::User).expect("prepared sample");

        assert!(processes.states.is_empty());
        assert_eq!(summary.sample_events, 1);
        assert_eq!(
            summary
                .error_stats
                .get(SampleErrorKind::NativeRegisterCapture),
            0
        );

        let mut ctx = EventContext {
            modules: &mut modules,
            processes: &mut processes,
            writer: &mut writer,
            summary: &mut summary,
            stack_scratch: &mut stack_scratch,
            lifecycle_actions: &mut lifecycle_actions,
            inherit_child_processes: false,
        };
        finish_prepared_event(prepared, &mut ctx).expect("finish sample");

        assert!(processes
            .states
            .get(&7)
            .is_some_and(|state| state.unwinder.is_some()));
        assert_eq!(
            summary
                .error_stats
                .get(SampleErrorKind::NativeRegisterCapture),
            1
        );
    }

    #[test]
    fn rejected_sample_metadata_updates_exact_counters() {
        for (task, timestamp, expected) in [
            (None, Some(1), (1, 1, 0, 0, 0)),
            (Some((u32::MAX, 1)), Some(1), (1, 1, 0, 0, 0)),
            (Some((1, u32::MAX)), Some(1), (1, 0, 1, 0, 0)),
            (Some((1, 0)), Some(1), (1, 0, 0, 1, 0)),
            (Some((1, 1)), None, (1, 0, 0, 0, 1)),
        ] {
            let mut summary = PerfSummary::default();
            assert!(prepare_sample_meta(&mut summary, task, timestamp).is_none());
            assert_eq!(
                (
                    summary.sample_events,
                    summary.missing_pid_samples,
                    summary.missing_tid_samples,
                    summary.idle_tid_samples,
                    summary.missing_timestamp_samples,
                ),
                expected
            );
        }
    }

    #[test]
    fn resolve_stack_frame_preserves_truncated_stack_marker() {
        let mut modules = ModuleTable::default();
        let mut summary = PerfSummary::default();

        let frame = resolve_stack_frame(
            &mut modules,
            &mut summary,
            123,
            StackFrame::TruncatedStackMarker,
        )
        .expect("truncated marker frame");

        assert!(frame.is_truncated_stack_marker());
        assert_eq!(summary.truncated_frame_markers, 1);
    }

    #[test]
    fn resolve_stack_frame_only_counts_explicit_truncated_marker() {
        let mut modules = ModuleTable::default();
        let mut summary = PerfSummary::default();

        let frame = resolve_stack_frame(
            &mut modules,
            &mut summary,
            123,
            StackFrame::InstructionPointer(0x1000, StackMode::User),
        )
        .expect("regular frame");

        assert!(!frame.is_truncated_stack_marker());
        assert_eq!(summary.truncated_frame_markers, 0);
    }

    #[test]
    fn bench_replay_live_perf_ring_records_smoke() {
        let fixture = live_perf_sample_bench_fixture();
        let checksum = bench_replay_live_perf_ring_records(&fixture, 1)
            .expect("replay synthetic ring records");

        assert!(checksum > 0);
    }

    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    struct TestConvertRegs;

    #[cfg(target_arch = "x86_64")]
    impl ConvertRegs for TestConvertRegs {
        type UnwindRegs = framehop::x86_64::UnwindRegsX86_64;

        fn convert_regs(regs: &[u64]) -> Option<(u64, u64, Self::UnwindRegs)> {
            let [pc, sp, bp] = *regs else {
                return None;
            };
            Some((pc, sp, Self::UnwindRegs::new(pc, sp, bp)))
        }

        fn regs_mask() -> u64 {
            0
        }
    }

    #[cfg(target_arch = "aarch64")]
    impl ConvertRegs for TestConvertRegs {
        type UnwindRegs = framehop::aarch64::UnwindRegsAarch64;

        fn convert_regs(regs: &[u64]) -> Option<(u64, u64, Self::UnwindRegs)> {
            let [pc, sp, fp] = *regs else {
                return None;
            };
            Some((pc, sp, Self::UnwindRegs::new(0, sp, fp)))
        }

        fn regs_mask() -> u64 {
            0
        }
    }

    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    #[test]
    fn truncated_dwarf_stack_ignores_user_callchain() {
        let user_regs = [0x1000, 0, 8];
        let user_stack: Vec<_> = [0, 40, 0x2000]
            .into_iter()
            .flat_map(u64::to_ne_bytes)
            .collect();
        let input = StackInput {
            code_addr: None,
            user_regs: Some(&user_regs),
            user_stack: Some(&user_stack),
        };
        let callchain_stack = [
            StackFrame::InstructionPointer(0x1000, StackMode::User),
            StackFrame::ReturnAddress(0x2000, StackMode::User),
            StackFrame::ReturnAddress(0x3000, StackMode::User),
        ];
        let mut process_unwinder = ProcessUnwinder::default();
        let mut stack = Vec::new();
        let mut summary = PerfSummary::default();

        build_sample_stack::<TestConvertRegs>(
            input,
            Priv::User,
            &mut process_unwinder,
            &mut stack,
            &callchain_stack,
            &mut summary,
        );

        assert_eq!(
            stack,
            vec![
                StackFrame::InstructionPointer(0x1000, StackMode::User),
                StackFrame::ReturnAddress(0x2000, StackMode::User),
                StackFrame::TruncatedStackMarker,
            ]
        );
        assert_eq!(summary.ignored_user_callchain_frames, 3);
        assert_eq!(
            summary
                .error_stats
                .get(SampleErrorKind::NativeStackTruncated),
            1
        );
    }

    #[test]
    fn each_callchain_context_starts_with_an_instruction_pointer() {
        let mut stack = Vec::new();

        push_callchain_addresses(StackMode::Kernel, &[0xffff_1000, 0xffff_2000], &mut stack);
        push_callchain_addresses(StackMode::User, &[0x1000, 0x2000], &mut stack);

        assert_eq!(
            stack,
            vec![
                StackFrame::InstructionPointer(0xffff_1000, StackMode::Kernel),
                StackFrame::ReturnAddress(0xffff_2000, StackMode::Kernel),
                StackFrame::InstructionPointer(0x1000, StackMode::User),
                StackFrame::ReturnAddress(0x2000, StackMode::User),
            ]
        );
    }

    #[test]
    fn resolving_multisegment_callchain_preserves_context_heads() {
        let mut stack = Vec::new();
        push_callchain_addresses(StackMode::Kernel, &[0xffff_1000, 0xffff_2000], &mut stack);
        push_callchain_addresses(StackMode::User, &[0x1000, 0x2000], &mut stack);
        let mut modules = ModuleTable::default();
        let mut summary = PerfSummary::default();

        let frames: Vec<_> = stack
            .into_iter()
            .map(|frame| resolve_stack_frame(&mut modules, &mut summary, 7, frame).unwrap())
            .collect();

        assert_eq!(frames[0].abs_ip, 0xffff_1000);
        assert_eq!(frames[1].abs_ip, 0xffff_1fff);
        assert_eq!(frames[2].abs_ip, 0x1000);
        assert_eq!(frames[3].abs_ip, 0x1fff);
    }

    #[test]
    fn get_sample_stack_ignores_unexpected_user_callchain() {
        let chains = vec![CallChain::User(vec![0x1000, 0x2000])];
        let sample = SampleView {
            task: None,
            timestamp_ns: None,
            code_addr: Some(0x3000),
            user_regs: None,
            user_stack: None,
            call_chain: SampleCallChain::Owned(&chains),
        };
        let mut process_unwinder = ProcessUnwinder::default();
        let mut stack = Vec::new();
        let mut callchain_stack = Vec::new();
        let mut summary = PerfSummary::default();

        get_sample_stack::<ConvertRegsNative>(
            sample,
            Priv::User,
            &mut process_unwinder,
            &mut stack,
            &mut callchain_stack,
            &mut summary,
        );

        assert_eq!(
            stack,
            vec![StackFrame::InstructionPointer(0x3000, StackMode::User)]
        );
        assert_eq!(summary.ignored_user_callchain_frames, 2);
        assert_eq!(
            summary
                .error_stats
                .get(SampleErrorKind::NativeUserRegistersMissing),
            1
        );
        assert_eq!(summary.error_stats.get(SampleErrorKind::NativeStackRead), 1);
    }

    #[test]
    fn build_sample_stack_keeps_kernel_callchain_and_ignores_user_tail() {
        let callchain_stack = [
            StackFrame::InstructionPointer(0xffff_1000, StackMode::Kernel),
            StackFrame::ReturnAddress(0xffff_2000, StackMode::Kernel),
            StackFrame::InstructionPointer(0x1000, StackMode::User),
            StackFrame::ReturnAddress(0x2000, StackMode::User),
        ];
        let mut process_unwinder = ProcessUnwinder::default();
        let mut stack = Vec::new();
        let mut summary = PerfSummary::default();

        build_sample_stack::<ConvertRegsNative>(
            StackInput {
                code_addr: None,
                user_regs: None,
                user_stack: None,
            },
            Priv::Kernel,
            &mut process_unwinder,
            &mut stack,
            &callchain_stack,
            &mut summary,
        );

        assert_eq!(stack, &callchain_stack[..2]);
        assert_eq!(summary.ignored_user_callchain_frames, 2);
    }

    #[test]
    fn get_sample_stack_treats_zero_user_stack_as_bad_sample() {
        let sample = SampleView {
            task: None,
            timestamp_ns: None,
            code_addr: Some(0x1000),
            user_regs: Some(&[]),
            user_stack: Some(&[]),
            call_chain: SampleCallChain::Owned(&[]),
        };
        let mut process_unwinder = ProcessUnwinder::default();
        let mut stack = Vec::new();
        let mut callchain_stack = Vec::new();
        let mut summary = PerfSummary::default();

        get_sample_stack::<ConvertRegsNative>(
            sample,
            Priv::User,
            &mut process_unwinder,
            &mut stack,
            &mut callchain_stack,
            &mut summary,
        );

        assert_eq!(
            stack,
            vec![StackFrame::InstructionPointer(0x1000, StackMode::User)]
        );
        assert_eq!(summary.error_stats.get(SampleErrorKind::NativeStackRead), 1);
        assert_eq!(
            summary
                .error_stats
                .get(SampleErrorKind::NativeRegisterCapture),
            0
        );
        assert_eq!(
            summary
                .error_stats
                .get(SampleErrorKind::NativeStackTruncated),
            0
        );
    }

    #[test]
    fn cmdline_detects_python_x_perf_flag() {
        assert!(cmdline_has_python_perf_support(
            b"python3\0-X\0perf\0app.py\0"
        ));
        assert!(cmdline_has_python_perf_support(
            b"python3\0-X\0perf,jit\0app.py\0"
        ));
        assert!(cmdline_has_python_perf_support(
            b"python3\0-Xperf\0app.py\0"
        ));
        assert!(!cmdline_has_python_perf_support(
            b"python3\0-X\0dev\0app.py\0"
        ));
    }

    #[test]
    fn forked_python_runtime_child_gets_runtime_marker() {
        let path = std::env::temp_dir().join(format!(
            "stackpulse-forked-python-runtime-{}.spool",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let mut writer = PerfSpoolWriter::create(&path, 123, 10).unwrap();
        let mut processes = ProcessTable::default();
        processes.state_mut(7).python_runtime = true;

        if processes.states[&7].python_runtime {
            mark_python_runtime_process(&mut processes, &mut writer, 456, 8).unwrap();
        }
        writer.flush().unwrap();
        drop(writer);

        let reader = crate::spool::PerfSpoolReader::open(&path).unwrap();
        let _ = std::fs::remove_file(path);
        assert!(processes.states[&8].python_runtime);
        let [runtime] = reader.python_runtime_records() else {
            panic!("expected one Python-runtime record");
        };
        assert_eq!(runtime.timestamp_ns, 456);
        assert_eq!(runtime.process_id, 8);
        assert!(runtime.is_python_runtime);
    }
}
