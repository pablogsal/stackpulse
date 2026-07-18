mod attach;
mod convert_regs;
mod cpu;
pub(crate) mod elf_loader;
pub(crate) mod elf_types;
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
#[cfg(test)]
mod test_fixtures;
mod types;
mod unwind;

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
use perf_group::{EventConsumer, PerfGroupOptions};
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
    /// Timestamp anchor stored in the profile file.
    pub start_timestamp_us: u64,
    /// Optional sampling interval metadata stored in the profile file.
    pub sample_interval_us: u64,
}

/// Counters collected while recording.
#[derive(Clone, Debug, Default)]
pub struct PerfSummary {
    /// Raw sample events seen by the recorder.
    pub sample_events: u64,
    /// Samples written to the profile file.
    pub samples: u64,
    /// Events reported lost by the kernel.
    pub lost_events: u64,
    /// LOST lifecycle records observed; one drain may recover several at once.
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
    /// User frame-pointer callchain frames not needed after DWARF unwinding.
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
    unwinders: FxHashMap<i32, ProcessUnwinder>,
    active_processes: FxHashMap<i32, Option<ProcessExitWatcher>>,
    process_images: FxHashMap<i32, ProcessImageIdentity>,
    process_start_times: FxHashMap<i32, u64>,
    // Cached per-exec probe results (environ + cmdline); false entries avoid
    // re-reading /proc for every executable python-runtime mmap. Cleared on
    // execve, inherited across fork.
    python_perf_support_processes: FxHashMap<i32, bool>,
    python_runtime_processes: FxHashSet<i32>,
    stack_scratch: Vec<StackFrame>,
    summary: PerfSummary,
}

struct EventContext<'a, W: std::io::Write> {
    modules: &'a mut ModuleTable,
    unwinders: &'a mut FxHashMap<i32, ProcessUnwinder>,
    active_processes: &'a mut FxHashMap<i32, Option<ProcessExitWatcher>>,
    process_images: &'a mut FxHashMap<i32, ProcessImageIdentity>,
    process_start_times: &'a mut FxHashMap<i32, u64>,
    python_perf_support_processes: &'a mut FxHashMap<i32, bool>,
    python_runtime_processes: &'a mut FxHashSet<i32>,
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
    timestamp_ns: u64,
    pid: i32,
    tid: u64,
    privilege: Priv,
    code_addr: Option<(u64, bool)>,
    user_regs: Option<Vec<u64>>,
    user_stack: Option<Vec<u8>>,
    callchain_stack: Vec<StackFrame>,
}

struct PreparedSampleMeta {
    timestamp_ns: u64,
    pid: i32,
    tid: u64,
    privilege: Priv,
    code_addr: Option<(u64, bool)>,
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
        match prepare_event(event_ref, &mut self.ctx) {
            Ok(prepared) => prepared,
            Err(err) => {
                self.result = Err(err);
                None
            }
        }
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
            PreparedEvent::Sample(sample) => sample.timestamp_ns,
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
        let mut kernel_enabled = options.include_kernel;
        let perf = open_perf_group(pid, attach_mode, &options).or_else(|err| {
            if options.include_kernel && err.kind() == io::ErrorKind::PermissionDenied {
                kernel_enabled = false;
                open_perf_group(
                    pid,
                    attach_mode,
                    &PerfRecorderOptions {
                        include_kernel: false,
                        ..options.clone()
                    },
                )
            } else {
                Err(err)
            }
        })?;
        let mut writer = PerfSpoolWriter::create(
            output,
            options.start_timestamp_us,
            options.sample_interval_us,
        )?;
        let mut modules = ModuleTable::default();
        let mut unwinders = FxHashMap::default();
        let mut active_processes = FxHashMap::default();
        let mut process_images = FxHashMap::default();
        let mut process_start_times = FxHashMap::default();
        let mut python_perf_support_processes = FxHashMap::default();
        let mut python_runtime_processes = FxHashSet::default();
        if let Some(pid_i32) = i32_from_u32(pid) {
            active_processes.insert(pid_i32, try_new_exit_watcher(pid_i32));
            if let Ok((identity, _)) = read_process_image_identity(pid) {
                process_images.insert(pid_i32, identity);
            }
            if let Ok(start_time) = read_process_start_time(pid) {
                process_start_times.insert(pid_i32, start_time);
            }
        }
        let python_perf_support =
            process_has_python_perf_support(pid, &mut python_perf_support_processes);
        let registered_existing_maps = attach_mode == AttachMode::StopAttachEnableResume
            && register_existing_maps(pid, &mut modules, &mut unwinders, &mut writer)?;
        if let Some(pid_i32) =
            i32_from_u32(pid).filter(|_| registered_existing_maps && python_perf_support)
        {
            mark_python_runtime_process(&mut python_runtime_processes, &mut writer, 0, pid_i32)?;
        }

        let mut recorder = Self {
            perf,
            event_sorter: EventSorter::new(),
            writer,
            modules,
            unwinders,
            active_processes,
            process_images,
            process_start_times,
            python_perf_support_processes,
            python_runtime_processes,
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

    /// Drain currently readable events into the profile file.
    pub fn consume_available(&mut self) -> io::Result<()> {
        self.drain_events(DrainMode::Consume, true)
    }

    #[allow(clippy::cognitive_complexity)]
    fn drain_events(&mut self, mode: DrainMode, open_new_perf_events: bool) -> io::Result<()> {
        let Self {
            perf,
            event_sorter,
            modules,
            unwinders,
            active_processes,
            process_images,
            process_start_times,
            python_perf_support_processes,
            python_runtime_processes,
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
                unwinders,
                active_processes,
                process_images,
                process_start_times,
                python_perf_support_processes,
                python_runtime_processes,
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
                    LifecycleAction::ProcessRetire { pid } => {
                        perf.remove_process(pid);
                        Ok(())
                    }
                    LifecycleAction::ProcessFork { pid, parent_tid } if open_new_perf_events => {
                        perf.open_forked_processes(&[(pid, parent_tid)])
                    }
                    LifecycleAction::ThreadFork {
                        tid,
                        pid,
                        parent_tid,
                    } if open_new_perf_events => {
                        perf.open_forked_threads(&[(tid, pid, parent_tid)])
                    }
                    LifecycleAction::ThreadExit { tid, .. } => {
                        perf.remove_thread(tid);
                        Ok(())
                    }
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
            let dead_processes: Vec<_> = active_processes
                .iter_mut()
                .filter_map(|(&pid, watcher)| {
                    let dead = !process_is_alive(watcher, pid);
                    let generation_changed = u32::try_from(pid)
                        .ok()
                        .and_then(|pid_u32| read_process_start_time(pid_u32).ok())
                        .zip(process_start_times.get(&pid).copied())
                        .is_some_and(|(current, previous)| current != previous);
                    (dead || generation_changed).then_some(pid)
                })
                .collect();
            for pid in dead_processes {
                if let Ok(pid_u32) = u32::try_from(pid) {
                    perf.remove_process(pid_u32);
                }
                if python_runtime_processes.contains(&pid) {
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
                    if let Err(err) = writer.write_process_exec(timestamp_ns, pid, false) {
                        result = Err(err);
                        break;
                    }
                    python_runtime_processes.remove(&pid);
                }
                if let Err(err) = cleanup_process(
                    pid,
                    modules,
                    unwinders,
                    writer,
                    active_processes,
                    process_images,
                    process_start_times,
                    python_perf_support_processes,
                    python_runtime_processes,
                ) {
                    result = Err(err);
                    break;
                }
            }
        }
        if result.is_ok() && recovered_lifecycle_gap {
            let tracked_pids: Vec<_> = active_processes.keys().copied().collect();
            for pid in tracked_pids {
                let Ok(pid_u32) = u32::try_from(pid) else {
                    continue;
                };
                match reconcile_process_image(
                    pid_u32,
                    recovery_timestamp_ns,
                    modules,
                    unwinders,
                    writer,
                    process_images,
                    process_start_times,
                    python_perf_support_processes,
                    python_runtime_processes,
                ) {
                    Ok(true) => {}
                    Ok(false) => {
                        perf.remove_process(pid_u32);
                        if let Err(err) = cleanup_process(
                            pid,
                            modules,
                            unwinders,
                            writer,
                            active_processes,
                            process_images,
                            process_start_times,
                            python_perf_support_processes,
                            python_runtime_processes,
                        ) {
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
            let roots: Vec<_> = active_processes.keys().copied().collect();
            let mut discovered = FxHashSet::default();
            for root in roots {
                for (child, parent) in crate::children::discover_descendant_edges(root) {
                    if !discovered.insert(child) || active_processes.contains_key(&child) {
                        continue;
                    }
                    let Ok(child_u32) = u32::try_from(child) else {
                        continue;
                    };
                    let python_perf_support =
                        process_has_python_perf_support(child_u32, python_perf_support_processes);
                    match register_existing_maps(child_u32, modules, unwinders, writer) {
                        Ok(true) if python_perf_support => {
                            if let Err(err) = mark_python_runtime_process(
                                python_runtime_processes,
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
                    active_processes.insert(child, try_new_exit_watcher(child));
                    if let Ok((identity, _)) = read_process_image_identity(child_u32) {
                        process_images.insert(child, identity);
                    }
                    if let Ok(start_time) = read_process_start_time(child_u32) {
                        process_start_times.insert(child, start_time);
                    }
                    if let Ok(parent_u32) = u32::try_from(parent) {
                        recovered_process_forks.push((child_u32, parent_u32));
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
            for pid in active_processes
                .keys()
                .filter_map(|pid| u32::try_from(*pid).ok())
            {
                if let Err(err) = perf.refresh_threads(pid) {
                    if !process_gone_error(&err) {
                        result = Err(err);
                        break;
                    }
                }
            }
        }
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
        if let Some(pid_i32) = i32_from_u32(pid) {
            let current_start_time = read_process_start_time(pid).ok();
            let stale = self
                .active_processes
                .get_mut(&pid_i32)
                .is_some_and(|watcher| {
                    !process_is_alive(watcher, pid_i32)
                        || current_start_time
                            .zip(self.process_start_times.get(&pid_i32).copied())
                            .is_some_and(|(current, previous)| current != previous)
                });
            if stale {
                self.perf.remove_process(pid);
                cleanup_process(
                    pid_i32,
                    &mut self.modules,
                    &mut self.unwinders,
                    &mut self.writer,
                    &mut self.active_processes,
                    &mut self.process_images,
                    &mut self.process_start_times,
                    &mut self.python_perf_support_processes,
                    &mut self.python_runtime_processes,
                )?;
            }
        }
        let opened = self.perf.open_process(pid, attach_mode)?;
        if let Some(pid_i32) = i32_from_u32(pid) {
            self.track_process(pid_i32);
            if let Ok((identity, _)) = read_process_image_identity(pid) {
                self.process_images.insert(pid_i32, identity);
            }
            if let Ok(start_time) = read_process_start_time(pid) {
                self.process_start_times.insert(pid_i32, start_time);
            }
            let python_perf_support =
                process_has_python_perf_support(pid, &mut self.python_perf_support_processes);
            match register_existing_maps(
                pid,
                &mut self.modules,
                &mut self.unwinders,
                &mut self.writer,
            ) {
                Ok(true) if python_perf_support => {
                    if let Err(err) = mark_python_runtime_process(
                        &mut self.python_runtime_processes,
                        &mut self.writer,
                        0,
                        pid_i32,
                    ) {
                        self.rollback_open_process(pid, opened);
                        return Err(err);
                    }
                }
                Ok(_) => {}
                Err(err) => {
                    self.rollback_open_process(pid, opened);
                    return Err(err);
                }
            }
        }
        if attach_mode == AttachMode::StopAttachEnableResume {
            if let Err(err) = self.perf.enable() {
                self.rollback_open_process(pid, opened);
                return Err(err);
            }
        }
        Ok(())
    }

    /// Discover newly-created threads for `pid` when needed.
    pub fn refresh_threads(&mut self, pid: u32) -> io::Result<()> {
        self.perf.refresh_threads(pid)
    }

    /// Disable sampling for all attached processes.
    pub fn disable(&mut self) {
        self.perf.disable();
    }

    /// Return whether unread profiling events are already queued.
    pub fn has_pending_events(&self) -> bool {
        self.event_sorter.has_more() || self.perf.has_pending_events()
    }

    /// Return a snapshot of the current counters.
    pub fn summary(&self) -> PerfSummary {
        self.summary.clone()
    }

    /// Return whether `pid` is still believed to be alive.
    pub fn process_is_active(&mut self, pid: i32) -> bool {
        self.active_processes
            .get_mut(&pid)
            .is_some_and(|watcher| process_is_alive(watcher, pid))
    }

    /// Return whether any active process other than `pid` remains.
    pub fn has_active_processes_except(&mut self, pid: i32) -> bool {
        self.active_processes
            .iter_mut()
            .any(|(&active_pid, watcher)| {
                active_pid != pid && process_is_alive(watcher, active_pid)
            })
    }

    /// Return the number of processes still believed to be alive.
    pub fn active_process_count(&mut self) -> usize {
        let mut count = 0;
        for (&pid, watcher) in &mut self.active_processes {
            count += usize::from(process_is_alive(watcher, pid));
        }
        count
    }

    /// Flush the profile file and return the final counters.
    pub fn finish(mut self) -> io::Result<PerfSummary> {
        self.perf.disable();
        self.drain_events(DrainMode::Flush, false)?;
        self.writer.flush()?;
        Ok(self.summary)
    }

    fn track_process(&mut self, pid: i32) {
        match self.active_processes.entry(pid) {
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert(try_new_exit_watcher(pid));
            }
            std::collections::hash_map::Entry::Occupied(mut entry) => {
                if !process_is_alive(entry.get_mut(), pid) {
                    entry.insert(try_new_exit_watcher(pid));
                }
            }
        }
    }

    fn rollback_open_process(&mut self, pid: u32, opened: perf_group::OpenTransaction) {
        self.perf.resume_stopped_processes();
        self.perf.rollback_open(opened);
        if let Some(pid) = i32_from_u32(pid) {
            let _ = cleanup_process(
                pid,
                &mut self.modules,
                &mut self.unwinders,
                &mut self.writer,
                &mut self.active_processes,
                &mut self.process_images,
                &mut self.process_start_times,
                &mut self.python_perf_support_processes,
                &mut self.python_runtime_processes,
            );
        }
    }
}

fn prepare_event<W: std::io::Write>(
    event_ref: EventRef,
    ctx: &mut EventContext<'_, W>,
) -> io::Result<Option<PreparedEvent>> {
    let event_timestamp_ns = event_ref.timestamp().unwrap_or(0);
    let (privilege, record) = event_ref.into_parts();
    match record {
        EventRecord::Sample(sample) => prepare_sample_ref(ctx, sample, privilege),
        EventRecord::Owned(Record::Sample(sample)) => prepare_sample(ctx, *sample, privilege),
        EventRecord::Owned(record) => Ok(Some(PreparedEvent::Record {
            timestamp_ns: event_timestamp_ns,
            privilege,
            record,
        })),
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
            record_mmap(ctx.modules, ctx.unwinders, ctx.writer, &mmap, privilege)?;
            record_python_runtime_mmap(
                &mmap,
                privilege,
                event_timestamp_ns,
                ctx.python_perf_support_processes,
                ctx.python_runtime_processes,
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

            let current_start_time = read_process_start_time(fork.task.pid).ok();
            let reused_pid = ctx.active_processes.get_mut(&pid).is_some_and(|watcher| {
                !process_is_alive(watcher, pid)
                    || current_start_time
                        .zip(ctx.process_start_times.get(&pid).copied())
                        .is_some_and(|(current, previous)| current != previous)
            });
            if reused_pid {
                if ctx.python_runtime_processes.remove(&pid) {
                    ctx.writer
                        .write_process_exec(event_timestamp_ns, pid, false)?;
                }
                cleanup_process(
                    pid,
                    ctx.modules,
                    ctx.unwinders,
                    ctx.writer,
                    ctx.active_processes,
                    ctx.process_images,
                    ctx.process_start_times,
                    ctx.python_perf_support_processes,
                    ctx.python_runtime_processes,
                )?;
                ctx.lifecycle_actions
                    .push(LifecycleAction::ProcessRetire { pid: fork.task.pid });
            }
            ctx.active_processes
                .entry(pid)
                .or_insert_with(|| try_new_exit_watcher(pid));
            if let Some(identity) = ctx.process_images.get(&ppid).cloned() {
                ctx.process_images.insert(pid, identity);
            }
            if let Some(start_time) = current_start_time {
                ctx.process_start_times.insert(pid, start_time);
            }
            if let Some(&supported) = ctx.python_perf_support_processes.get(&ppid) {
                ctx.python_perf_support_processes.insert(pid, supported);
            }
            inherit_python_runtime_process(
                ctx.python_runtime_processes,
                ctx.writer,
                event_timestamp_ns,
                ppid,
                pid,
            )?;
            let updates = ctx.modules.clone_process_modules(ppid, pid, ctx.writer)?;
            let mut child_unwinder = ctx.unwinders.get(&ppid).cloned().unwrap_or_default();
            for update in &updates {
                child_unwinder.apply_module_update(update);
            }
            ctx.unwinders.insert(pid, child_unwinder);
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
                ctx.process_images.get(&pid).is_some_and(|previous| {
                    previous.device != identity.device || previous.inode != identity.inode
                }) && current_comm.as_slice() == comm.comm.as_bytes()
            });
            if !comm.by_execve && !identity_changed {
                return Ok(());
            }

            // A confirmed exec is an epoch boundary. Do not read current maps
            // here: the subsequent MMAP records retain their proper ordering.
            cleanup_process_modules(pid, ctx.modules, ctx.unwinders, ctx.writer)?;
            ctx.python_perf_support_processes.remove(&pid);
            if ctx.python_runtime_processes.remove(&pid) {
                ctx.writer
                    .write_process_exec(event_timestamp_ns, pid, false)?;
            }
            if let Some((identity, _)) = current {
                ctx.process_images.insert(pid, identity);
            } else {
                ctx.process_images.remove(&pid);
            }
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
        Record::LostRecords(lost) => {
            ctx.summary.lost_events = ctx.summary.lost_events.saturating_add(lost.lost_records);
            ctx.summary.lifecycle_gaps = ctx.summary.lifecycle_gaps.saturating_add(1);
            Ok(())
        }
        Record::LostSamples(lost) => {
            ctx.summary.lost_events = ctx.summary.lost_events.saturating_add(lost.lost_samples);
            Ok(())
        }
        _ => Ok(()),
    }
}

fn i32_from_u32(value: u32) -> Option<i32> {
    i32::try_from(value).ok()
}

#[allow(clippy::too_many_arguments)]
fn cleanup_process(
    pid: i32,
    modules: &mut ModuleTable,
    unwinders: &mut FxHashMap<i32, ProcessUnwinder>,
    writer: &mut PerfSpoolWriter<impl std::io::Write>,
    active_processes: &mut FxHashMap<i32, Option<ProcessExitWatcher>>,
    process_images: &mut FxHashMap<i32, ProcessImageIdentity>,
    process_start_times: &mut FxHashMap<i32, u64>,
    python_perf_support_processes: &mut FxHashMap<i32, bool>,
    python_runtime_processes: &mut FxHashSet<i32>,
) -> io::Result<()> {
    let result = cleanup_process_modules(pid, modules, unwinders, writer);
    active_processes.remove(&pid);
    process_images.remove(&pid);
    process_start_times.remove(&pid);
    python_perf_support_processes.remove(&pid);
    python_runtime_processes.remove(&pid);
    result
}

fn cleanup_process_modules<W: std::io::Write>(
    pid: i32,
    modules: &mut ModuleTable,
    unwinders: &mut FxHashMap<i32, ProcessUnwinder>,
    writer: &mut PerfSpoolWriter<W>,
) -> io::Result<()> {
    modules.deactivate_process_modules(pid, writer)?;
    unwinders.remove(&pid);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn reconcile_process_image<W: std::io::Write>(
    pid: u32,
    timestamp_ns: u64,
    modules: &mut ModuleTable,
    unwinders: &mut FxHashMap<i32, ProcessUnwinder>,
    writer: &mut PerfSpoolWriter<W>,
    process_images: &mut FxHashMap<i32, ProcessImageIdentity>,
    process_start_times: &mut FxHashMap<i32, u64>,
    python_perf_support_processes: &mut FxHashMap<i32, bool>,
    python_runtime_processes: &mut FxHashSet<i32>,
) -> io::Result<bool> {
    let Some(pid_i32) = i32_from_u32(pid) else {
        return Ok(false);
    };

    let current_start_time = match read_process_start_time(pid) {
        Ok(start_time) => start_time,
        Err(err) if process_gone_error(&err) => {
            process_images.remove(&pid_i32);
            process_start_times.remove(&pid_i32);
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
            process_images.remove(&pid_i32);
            process_start_times.remove(&pid_i32);
            return Ok(false);
        }
        Err(err) => return Err(err),
    };
    let has_executable_maps = maps_snapshot_has_executable_files(&maps);
    if !has_executable_maps {
        // A live group whose leader has exited can expose an empty maps file.
        // Without a usable replacement snapshot, preserve the last known
        // modules and unwinder instead of destructively reconciling to empty.
        return Ok(true);
    }

    cleanup_process_modules(pid_i32, modules, unwinders, writer)?;
    python_perf_support_processes.remove(&pid_i32);
    if python_runtime_processes.remove(&pid_i32) {
        writer.write_process_exec(timestamp_ns, pid_i32, false)?;
    }

    let registered = register_existing_maps_snapshot(pid, &maps, modules, unwinders, writer);
    match registered {
        Ok(true) if process_has_python_perf_support(pid, python_perf_support_processes) => {
            if let Some(identity) = current_identity {
                process_images.insert(pid_i32, identity);
            }
            process_start_times.insert(pid_i32, current_start_time);
            mark_python_runtime_process(python_runtime_processes, writer, timestamp_ns, pid_i32)?;
            Ok(true)
        }
        Ok(_) => {
            if let Some(identity) = current_identity {
                process_images.insert(pid_i32, identity);
            }
            process_start_times.insert(pid_i32, current_start_time);
            Ok(true)
        }
        Err(err) if process_gone_error(&err) => {
            process_images.remove(&pid_i32);
            process_start_times.remove(&pid_i32);
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

fn process_has_python_perf_support(
    pid: u32,
    python_perf_support_processes: &mut FxHashMap<i32, bool>,
) -> bool {
    let Some(pid_i32) = i32_from_u32(pid) else {
        return false;
    };
    if let Some(&supported) = python_perf_support_processes.get(&pid_i32) {
        return supported;
    }
    let supported = process_has_python_perf_support_enabled(pid);
    python_perf_support_processes.insert(pid_i32, supported);
    supported
}

fn mark_python_runtime_process<W: std::io::Write>(
    python_runtime_processes: &mut FxHashSet<i32>,
    writer: &mut PerfSpoolWriter<W>,
    timestamp_ns: u64,
    pid: i32,
) -> io::Result<()> {
    if python_runtime_processes.insert(pid) {
        writer.write_process_exec(timestamp_ns, pid, true)?;
    }
    Ok(())
}

fn inherit_python_runtime_process<W: std::io::Write>(
    python_runtime_processes: &mut FxHashSet<i32>,
    writer: &mut PerfSpoolWriter<W>,
    timestamp_ns: u64,
    parent_pid: i32,
    child_pid: i32,
) -> io::Result<()> {
    if python_runtime_processes.contains(&parent_pid) {
        mark_python_runtime_process(python_runtime_processes, writer, timestamp_ns, child_pid)?;
    }
    Ok(())
}

fn record_python_runtime_mmap<W: std::io::Write>(
    mmap: &Mmap,
    privilege: Priv,
    timestamp_ns: u64,
    python_perf_support_processes: &mut FxHashMap<i32, bool>,
    python_runtime_processes: &mut FxHashSet<i32>,
    writer: &mut PerfSpoolWriter<W>,
) -> io::Result<()> {
    if is_kernel_mode(privilege) || !mmap_is_executable(mmap) {
        return Ok(());
    }
    let Some(pid) = i32_from_u32(mmap.task.pid) else {
        return Ok(());
    };
    if !c_string_is_python_runtime_path(&mmap.file) {
        return Ok(());
    }
    if process_has_python_perf_support(mmap.task.pid, python_perf_support_processes) {
        mark_python_runtime_process(python_runtime_processes, writer, timestamp_ns, pid)?;
    }
    Ok(())
}

fn prepare_sample<W: std::io::Write>(
    ctx: &mut EventContext<'_, W>,
    sample: Sample,
    privilege: Priv,
) -> io::Result<Option<PreparedEvent>> {
    let Sample {
        record_id,
        call_chain,
        user_stack,
        code_addr,
        user_regs,
        ..
    } = sample;
    let task = record_id.task.as_ref().map(|task| (task.pid, task.tid));
    let Some(meta) = prepare_sample_meta(ctx, task, record_id.time, code_addr, privilege) else {
        return Ok(None);
    };

    Ok(Some(PreparedEvent::Sample(PreparedSample {
        timestamp_ns: meta.timestamp_ns,
        pid: meta.pid,
        tid: meta.tid,
        privilege: meta.privilege,
        code_addr: meta.code_addr,
        user_regs: user_regs.and_then(|(regs, abi)| (abi == SampleRegsAbi::_64).then_some(regs)),
        user_stack,
        callchain_stack: call_chain
            .as_deref()
            .map_or(SampleCallChain::None, SampleCallChain::Owned)
            .to_stack_frames(),
    })))
}

fn prepare_sample_ref<W: std::io::Write>(
    ctx: &mut EventContext<'_, W>,
    sample: SampleRecordRef<'_>,
    privilege: Priv,
) -> io::Result<Option<PreparedEvent>> {
    prepare_sample_view(ctx, SampleView::from_ref(sample), privilege)
}

#[derive(Clone, Copy)]
struct SampleView<'a> {
    task: Option<(u32, u32)>,
    timestamp_ns: Option<u64>,
    code_addr: Option<(u64, bool)>,
    user_regs: Option<&'a [u64]>,
    user_stack: Option<&'a [u8]>,
    call_chain: SampleCallChain<'a>,
}

#[derive(Clone, Copy)]
struct StackInput<'a> {
    code_addr: Option<(u64, bool)>,
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
            code_addr: sample.code_addr,
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

fn prepare_sample_view<W: std::io::Write>(
    ctx: &mut EventContext<'_, W>,
    sample: SampleView<'_>,
    privilege: Priv,
) -> io::Result<Option<PreparedEvent>> {
    let Some(meta) = prepare_sample_meta(
        ctx,
        sample.task,
        sample.timestamp_ns,
        sample.code_addr,
        privilege,
    ) else {
        return Ok(None);
    };

    Ok(Some(PreparedEvent::Sample(PreparedSample {
        timestamp_ns: meta.timestamp_ns,
        pid: meta.pid,
        tid: meta.tid,
        privilege: meta.privilege,
        code_addr: meta.code_addr,
        user_regs: sample.user_regs.map(<[u64]>::to_vec),
        user_stack: sample.user_stack.map(<[u8]>::to_vec),
        callchain_stack: sample.call_chain.to_stack_frames(),
    })))
}

fn prepare_sample_meta<W: std::io::Write>(
    ctx: &mut EventContext<'_, W>,
    task: Option<(u32, u32)>,
    timestamp_ns: Option<u64>,
    code_addr: Option<(u64, bool)>,
    privilege: Priv,
) -> Option<PreparedSampleMeta> {
    bump(&mut ctx.summary.sample_events);
    let Some((raw_pid, raw_tid)) = task else {
        bump(&mut ctx.summary.missing_pid_samples);
        return None;
    };
    let Some(pid) = i32_from_u32(raw_pid) else {
        bump(&mut ctx.summary.missing_pid_samples);
        return None;
    };
    let Some(tid) = i32_from_u32(raw_tid) else {
        bump(&mut ctx.summary.missing_tid_samples);
        return None;
    };
    if tid == 0 {
        bump(&mut ctx.summary.idle_tid_samples);
        return None;
    }
    let Some(timestamp_ns) = timestamp_ns else {
        bump(&mut ctx.summary.missing_timestamp_samples);
        return None;
    };

    Some(PreparedSampleMeta {
        timestamp_ns,
        pid,
        tid: tid as u64,
        privilege,
        code_addr,
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
    let pid = sample.pid;
    refresh_maps_for_uncovered_user_pc(ctx, &sample)?;
    let input = StackInput {
        code_addr: sample.code_addr,
        user_regs: sample.user_regs.as_deref(),
        user_stack: sample.user_stack.as_deref(),
    };
    let unwinder = ctx.unwinders.entry(pid).or_default();
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
            sample.timestamp_ns,
            pid,
            sample.tid,
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
    let Some(pid) = u32::try_from(sample.pid).ok() else {
        return Ok(());
    };
    let Some(pc) = sample
        .user_regs
        .as_deref()
        .and_then(ConvertRegsNative::convert_regs)
        .map(|(pc, _, _)| pc)
    else {
        return Ok(());
    };
    if ctx.modules.covers_user_pc(sample.pid, pc) {
        return Ok(());
    }
    if !ctx
        .unwinders
        .entry(sample.pid)
        .or_default()
        .should_refresh_for_uncovered_pc(pc)
    {
        return Ok(());
    }
    match register_existing_maps(pid, ctx.modules, ctx.unwinders, ctx.writer) {
        Ok(true) if process_has_python_perf_support(pid, ctx.python_perf_support_processes) => {
            mark_python_runtime_process(
                ctx.python_runtime_processes,
                ctx.writer,
                sample.timestamp_ns,
                sample.pid,
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
    unwinders: &mut FxHashMap<i32, ProcessUnwinder>,
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
            unwinders
                .entry(module.process_id)
                .or_default()
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
    unwinders: &mut FxHashMap<i32, ProcessUnwinder>,
    writer: &mut PerfSpoolWriter<W>,
    event: MmapEvent<'_>,
) -> io::Result<()> {
    let is_kernel = is_kernel_mode(event.privilege);
    if !is_kernel && !event.is_executable {
        return Ok(());
    }
    record_module(
        modules,
        unwinders,
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
    unwinders: &mut FxHashMap<i32, ProcessUnwinder>,
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
        unwinders,
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
    let open = |source| {
        perf_group::PerfGroup::open(
            pid,
            attach_mode,
            PerfGroupOptions {
                frequency: options.frequency,
                stack_size: options.stack_size,
                event_source: source,
                regs_mask,
                include_kernel: options.include_kernel,
                inherit_child_processes: options.inherit_child_processes,
            },
        )
    };
    open(EventSource::HwCpuCycles).or_else(|_| open(EventSource::SwCpuClock))
}

fn register_existing_maps<W: std::io::Write>(
    pid: u32,
    modules: &mut ModuleTable,
    unwinders: &mut FxHashMap<i32, ProcessUnwinder>,
    writer: &mut PerfSpoolWriter<W>,
) -> io::Result<bool> {
    let maps = std::fs::read_to_string(format!("/proc/{pid}/maps"))?;
    register_existing_maps_snapshot(pid, &maps, modules, unwinders, writer)
}

fn register_existing_maps_snapshot<W: std::io::Write>(
    pid: u32,
    maps: &str,
    modules: &mut ModuleTable,
    unwinders: &mut FxHashMap<i32, ProcessUnwinder>,
    writer: &mut PerfSpoolWriter<W>,
) -> io::Result<bool> {
    let mut saw_python_runtime = false;
    for region in
        crate::proc_maps::parse_iter(maps).filter(|r| r.is_executable && !r.path.is_empty())
    {
        saw_python_runtime |= is_python_runtime_path(region.path);
        record_module(
            modules,
            unwinders,
            writer,
            ModuleRecord {
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
            },
        )?;
    }
    Ok(saw_python_runtime)
}

fn maps_snapshot_has_executable_files(maps: &str) -> bool {
    crate::proc_maps::parse_iter(maps).any(|region| region.is_executable && !region.path.is_empty())
}

fn is_python_runtime_path(path: &str) -> bool {
    path_basename_is_python_module(std::path::Path::new(path))
}

fn path_basename_is_python_module(path: &std::path::Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(crate::is_python_module)
}

fn c_string_is_python_runtime_path(path: &std::ffi::CString) -> bool {
    use std::os::unix::ffi::OsStrExt;

    path_basename_is_python_module(std::path::Path::new(std::ffi::OsStr::from_bytes(
        path.as_bytes(),
    )))
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
    let (kernel_callchain_frames, fp_user_frames) = callchain_stack.split_at(kernel_frame_count);
    stack.extend_from_slice(kernel_callchain_frames);
    let dwarf_start = stack.len();
    let mut dwarf_truncated = false;
    let user_stack = sample.user_stack.filter(|stack| !stack.is_empty());
    let missing_user_regs_for_user_tail = sample.user_regs.is_none() && !fp_user_frames.is_empty();

    if sample.user_stack.is_some() && user_stack.is_none() {
        record_unwind_error(summary, SampleErrorKind::NativeStackRead, || {
            "perf sample reported zero user stack bytes".to_string()
        });
    }
    if missing_user_regs_for_user_tail && is_kernel_mode(privilege) {
        record_unwind_error(summary, SampleErrorKind::NativeUserRegistersMissing, || {
            "perf sample did not include user register state for user callchain tail".to_string()
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

    let used_fp_user_frames =
        append_fp_user_callchain(stack, dwarf_start, fp_user_frames, dwarf_truncated);
    summary.ignored_user_callchain_frames = summary
        .ignored_user_callchain_frames
        .saturating_add(fp_user_frames.len().saturating_sub(used_fp_user_frames) as u64);
    if dwarf_truncated || missing_user_regs_for_user_tail {
        stack.push(StackFrame::TruncatedStackMarker);
    }

    if stack.is_empty() {
        if let Some((ip, _)) = sample.code_addr {
            stack.push(StackFrame::InstructionPointer(ip, privilege.into()));
        }
    }
}

fn append_fp_user_callchain(
    stack: &mut Vec<StackFrame>,
    dwarf_start: usize,
    fp_user_frames: &[StackFrame],
    dwarf_truncated: bool,
) -> usize {
    if fp_user_frames.is_empty() {
        return 0;
    }
    if stack.len() == dwarf_start {
        stack.extend_from_slice(fp_user_frames);
        return fp_user_frames.len();
    }
    if !dwarf_truncated {
        return 0;
    }

    let Some(last_dwarf_address) = stack[dwarf_start..]
        .iter()
        .rev()
        .find_map(|&frame| stack_frame_address(frame))
    else {
        return 0;
    };
    let Some(splice_index) = fp_user_frames
        .iter()
        .position(|&frame| stack_frame_address(frame) == Some(last_dwarf_address))
    else {
        return 0;
    };
    let tail = &fp_user_frames[splice_index + 1..];
    stack.extend_from_slice(tail);
    tail.len()
}

fn stack_frame_is_kernel(frame: StackFrame) -> bool {
    matches!(
        frame,
        StackFrame::InstructionPointer(_, StackMode::Kernel)
            | StackFrame::ReturnAddress(_, StackMode::Kernel)
    )
}

fn stack_frame_address(frame: StackFrame) -> Option<u64> {
    match frame {
        StackFrame::InstructionPointer(address, _) | StackFrame::ReturnAddress(address, _) => {
            Some(address)
        }
        StackFrame::TruncatedStackMarker => None,
    }
}

fn push_sample_callchain(call_chain: SampleCallChain<'_>, stack: &mut Vec<StackFrame>) {
    for (mode, addresses) in call_chain.iter() {
        let first_address_is_instruction_pointer = stack.is_empty();
        push_callchain_addresses(mode, addresses, first_address_is_instruction_pointer, stack);
    }
}

fn push_callchain_addresses(
    mode: StackMode,
    addresses: &[u64],
    first_address_is_instruction_pointer: bool,
    stack: &mut Vec<StackFrame>,
) {
    for (index, &address) in addresses.iter().enumerate() {
        stack.push(if index == 0 && first_address_is_instruction_pointer {
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

const LIVE_BENCH_PROCESS_ID: u32 = 42_000;
const LIVE_BENCH_USER_BASE: u64 = 0x7000_0000_0000;
const LIVE_BENCH_KERNEL_BASE: u64 = 0xffff_ffff_8100_0000;
const LIVE_BENCH_RING_COUNT: usize = 4;

pub(crate) struct LivePerfSampleBenchFixture {
    samples: perf_event::BenchSampleBatch,
    modules: Vec<ModuleRecord>,
    spool_capacity: usize,
}

impl LivePerfSampleBenchFixture {
    pub(crate) fn event_bytes(&self) -> usize {
        self.samples.event_bytes()
    }

    pub(crate) fn sample_count(&self) -> usize {
        self.samples.sample_count()
    }

    pub(crate) fn frame_count(&self) -> usize {
        self.samples.frame_count()
    }
}

pub(crate) fn live_perf_sample_bench_fixture() -> LivePerfSampleBenchFixture {
    let samples = perf_event::BenchSampleBatch::new(perf_event::BenchSampleBatchSpec {
        samples: 4_096,
        user_frames: 24,
        kernel_frames: 8,
        user_regs: ConvertRegsNative::regs_mask().count_ones() as usize,
        user_stack_bytes: 512,
        process_id: LIVE_BENCH_PROCESS_ID,
        thread_count: 32,
        user_base: LIVE_BENCH_USER_BASE,
        kernel_base: LIVE_BENCH_KERNEL_BASE,
    });
    let modules = live_perf_sample_bench_modules();
    let spool_capacity = 64 * 1024 + samples.frame_count() * 16 + samples.sample_count() * 16;
    LivePerfSampleBenchFixture {
        samples,
        modules,
        spool_capacity,
    }
}

pub(crate) fn bench_parse_live_perf_samples(
    fixture: &LivePerfSampleBenchFixture,
    rounds: u64,
) -> usize {
    perf_event::bench_parse_sample_records(&fixture.samples, rounds)
}

pub(crate) fn bench_record_live_perf_samples(
    fixture: &LivePerfSampleBenchFixture,
    rounds: u64,
) -> io::Result<usize> {
    let mut checksum = 0usize;
    for round in 0..rounds {
        let mut writer = PerfSpoolWriter::from_writer(
            Vec::with_capacity(fixture.spool_capacity),
            1_700_000_000_000_000 + round,
            1_000,
        )?;
        let mut modules = ModuleTable::default();
        let mut unwinders = FxHashMap::default();
        for module in &fixture.modules {
            record_module(&mut modules, &mut unwinders, &mut writer, module.clone())?;
        }

        let mut active_processes = FxHashMap::default();
        let mut process_images = FxHashMap::default();
        let mut process_start_times = FxHashMap::default();
        let mut python_perf_support_processes = FxHashMap::default();
        let mut python_runtime_processes = FxHashSet::default();
        let mut summary = PerfSummary::default();
        let mut stack_scratch = Vec::with_capacity(128);
        let mut lifecycle_actions = Vec::new();
        {
            let mut ctx = EventContext {
                modules: &mut modules,
                unwinders: &mut unwinders,
                active_processes: &mut active_processes,
                process_images: &mut process_images,
                process_start_times: &mut process_start_times,
                python_perf_support_processes: &mut python_perf_support_processes,
                python_runtime_processes: &mut python_runtime_processes,
                writer: &mut writer,
                summary: &mut summary,
                stack_scratch: &mut stack_scratch,
                lifecycle_actions: &mut lifecycle_actions,
                inherit_child_processes: false,
            };
            for record in fixture.samples.records() {
                let (privilege, sample) = fixture
                    .samples
                    .parse(record)
                    .expect("parse synthetic live sample");
                if let Some(prepared) = prepare_sample_ref(&mut ctx, sample, privilege)? {
                    finish_prepared_event(prepared, &mut ctx)?;
                }
            }
        }

        writer.flush()?;
        let bytes = writer.into_inner();
        checksum = checksum
            .wrapping_add(bytes.len())
            .wrapping_add(summary.samples as usize)
            .wrapping_add(summary.sample_events as usize)
            .wrapping_add(summary.ignored_user_callchain_frames as usize)
            .wrapping_add(lifecycle_actions.len());
    }
    Ok(checksum)
}

pub(crate) fn bench_replay_live_perf_ring_records(
    fixture: &LivePerfSampleBenchFixture,
    rounds: u64,
) -> io::Result<usize> {
    let mut checksum = 0usize;
    for round in 0..rounds {
        let mut writer = PerfSpoolWriter::from_writer(
            Vec::with_capacity(fixture.spool_capacity),
            1_700_000_000_000_000 + round,
            1_000,
        )?;
        let mut modules = ModuleTable::default();
        let mut unwinders = FxHashMap::default();
        for module in &fixture.modules {
            record_module(&mut modules, &mut unwinders, &mut writer, module.clone())?;
        }

        let mut active_processes = FxHashMap::default();
        let mut process_images = FxHashMap::default();
        let mut process_start_times = FxHashMap::default();
        let mut python_perf_support_processes = FxHashMap::default();
        let mut python_runtime_processes = FxHashSet::default();
        let mut summary = PerfSummary::default();
        let mut stack_scratch = Vec::with_capacity(128);
        let mut lifecycle_actions = Vec::new();
        let mut sorter = sorter::EventSorter::<usize, u64, PreparedEvent>::new();
        let mut result: io::Result<()> = Ok(());
        {
            let mut ctx = EventContext {
                modules: &mut modules,
                unwinders: &mut unwinders,
                active_processes: &mut active_processes,
                process_images: &mut process_images,
                process_start_times: &mut process_start_times,
                python_perf_support_processes: &mut python_perf_support_processes,
                python_runtime_processes: &mut python_runtime_processes,
                writer: &mut writer,
                summary: &mut summary,
                stack_scratch: &mut stack_scratch,
                lifecycle_actions: &mut lifecycle_actions,
                inherit_child_processes: false,
            };
            for ring in 0..LIVE_BENCH_RING_COUNT {
                sorter.begin_group(ring);
                for record in fixture
                    .samples
                    .records()
                    .iter()
                    .skip(ring)
                    .step_by(LIVE_BENCH_RING_COUNT)
                {
                    if result.is_err() {
                        break;
                    }
                    let (timestamp, prepared) =
                        fixture.samples.dispatch_event(record, &mut |event| {
                            let timestamp = event.timestamp().unwrap_or(0);
                            (timestamp, prepare_event(event, &mut ctx))
                        });
                    match prepared {
                        Ok(Some(prepared)) => sorter.push_current_group(timestamp, prepared),
                        Ok(None) => {}
                        Err(err) => {
                            result = Err(err);
                        }
                    }
                }
                while let Some(prepared) = sorter.pop() {
                    if result.is_ok() {
                        result = finish_prepared_event(prepared, &mut ctx);
                    }
                }
            }
            sorter.advance_round();
            while let Some(prepared) = sorter.pop() {
                if result.is_ok() {
                    result = finish_prepared_event(prepared, &mut ctx);
                }
            }
        }
        result?;

        writer.flush()?;
        let bytes = writer.into_inner();
        checksum = checksum
            .wrapping_add(bytes.len())
            .wrapping_add(summary.samples as usize)
            .wrapping_add(summary.sample_events as usize)
            .wrapping_add(summary.ignored_user_callchain_frames as usize)
            .wrapping_add(lifecycle_actions.len());
    }
    Ok(checksum)
}

fn live_perf_sample_bench_modules() -> Vec<ModuleRecord> {
    vec![
        ModuleRecord {
            id: 0,
            process_id: LIVE_BENCH_PROCESS_ID as i32,
            start: LIVE_BENCH_USER_BASE,
            end: LIVE_BENCH_USER_BASE + 0x0008_0000,
            file_offset: 0,
            inode: 1_000_001,
            device_major: 0,
            device_minor: 0,
            inode_generation: 0,
            path: "/opt/stackpulse/live-bench/libworkload.so".into(),
            is_kernel: false,
        },
        ModuleRecord {
            id: 0,
            process_id: LIVE_BENCH_PROCESS_ID as i32,
            start: LIVE_BENCH_USER_BASE + 0x0010_0000,
            end: LIVE_BENCH_USER_BASE + 0x0018_0000,
            file_offset: 0,
            inode: 1_000_002,
            device_major: 0,
            device_minor: 0,
            inode_generation: 0,
            path: "/opt/stackpulse/live-bench/python3.12".into(),
            is_kernel: false,
        },
        ModuleRecord {
            id: 0,
            process_id: -1,
            start: LIVE_BENCH_KERNEL_BASE,
            end: LIVE_BENCH_KERNEL_BASE + 0x0010_0000,
            file_offset: 0,
            inode: 0,
            device_major: 0,
            device_minor: 0,
            inode_generation: 0,
            path: "[kernel.kallsyms]".into(),
            is_kernel: true,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spool::ModuleTableTestExt;
    use perf_event_open::sample::record::comm::Comm;
    use perf_event_open::sample::record::lost::LostRecords;
    use perf_event_open::sample::record::task::{Exit, Fork};
    use perf_event_open::sample::record::Task;

    #[test]
    fn perf_recorder_is_send() {
        fn assert_send<T: Send>() {}

        assert_send::<PerfRecorder>();
    }

    #[test]
    fn leader_exit_retires_thread_without_deactivating_process_modules() {
        let pid = std::process::id();
        let pid_i32 = i32::try_from(pid).unwrap();
        let mut modules = ModuleTable::default();
        let mut unwinders = FxHashMap::default();
        let mut active_processes = FxHashMap::default();
        let mut process_images = FxHashMap::default();
        let mut process_start_times = FxHashMap::default();
        let mut python_perf_support_processes = FxHashMap::default();
        let mut python_runtime_processes = FxHashSet::default();
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
                unwinders: &mut unwinders,
                active_processes: &mut active_processes,
                process_images: &mut process_images,
                process_start_times: &mut process_start_times,
                python_perf_support_processes: &mut python_perf_support_processes,
                python_runtime_processes: &mut python_runtime_processes,
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
        let mut unwinders = FxHashMap::default();
        let mut active_processes = FxHashMap::default();
        let mut process_images = FxHashMap::default();
        let mut process_start_times = FxHashMap::default();
        let mut python_perf_support_processes = FxHashMap::default();
        let mut python_runtime_processes = FxHashSet::default();
        let mut writer = PerfSpoolWriter::from_writer(Vec::new(), 0, 0).unwrap();
        let mut summary = PerfSummary::default();
        let mut stack_scratch = Vec::new();
        let mut lifecycle_actions = Vec::new();
        let mut ctx = EventContext {
            modules: &mut modules,
            unwinders: &mut unwinders,
            active_processes: &mut active_processes,
            process_images: &mut process_images,
            process_start_times: &mut process_start_times,
            python_perf_support_processes: &mut python_perf_support_processes,
            python_runtime_processes: &mut python_runtime_processes,
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
    fn lost_record_defers_recovery_and_does_not_trust_record_id_task() {
        let pid = i32::try_from(std::process::id()).unwrap();
        let mut modules = ModuleTable::default();
        let mut unwinders = FxHashMap::default();
        let mut active_processes = FxHashMap::default();
        let mut process_images = FxHashMap::default();
        let mut process_start_times = FxHashMap::default();
        let mut python_perf_support_processes = FxHashMap::default();
        let mut python_runtime_processes = FxHashSet::default();
        let mut writer = PerfSpoolWriter::from_writer(Vec::new(), 0, 0).unwrap();
        let mut summary = PerfSummary::default();
        let mut stack_scratch = Vec::new();
        let mut lifecycle_actions = Vec::new();
        let mut module = test_module(0x1000, 0x2000);
        module.process_id = pid;
        modules.intern_module(module, &mut writer).unwrap();

        let mut ctx = EventContext {
            modules: &mut modules,
            unwinders: &mut unwinders,
            active_processes: &mut active_processes,
            process_images: &mut process_images,
            process_start_times: &mut process_start_times,
            python_perf_support_processes: &mut python_perf_support_processes,
            python_runtime_processes: &mut python_runtime_processes,
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

        assert_eq!(summary.lost_events, 7);
        assert_eq!(summary.lifecycle_gaps, 1);
        assert!(modules
            .resolve_frame(pid, 0x1800, FrameMode::User)
            .module_id
            .is_some());
    }

    #[test]
    fn empty_maps_snapshot_cannot_replace_live_process_modules() {
        assert!(!maps_snapshot_has_executable_files(""));
        assert!(!maps_snapshot_has_executable_files(
            "1000-2000 r-xp 00000000 00:00 0\n"
        ));
        assert!(maps_snapshot_has_executable_files(
            "1000-2000 r-xp 00000000 08:01 42 /tmp/lib.so\n"
        ));
    }

    #[test]
    fn ordinary_leader_comm_does_not_create_an_exec_epoch() {
        let pid_u32 = std::process::id();
        let pid = i32::try_from(pid_u32).unwrap();
        let (identity, current_comm) = read_process_image_identity(pid_u32).unwrap();
        let mut modules = ModuleTable::default();
        let mut unwinders = FxHashMap::default();
        let mut active_processes = FxHashMap::default();
        let mut process_images = FxHashMap::from_iter([(pid, identity)]);
        let mut process_start_times = FxHashMap::default();
        let mut python_perf_support_processes = FxHashMap::default();
        let mut python_runtime_processes = FxHashSet::default();
        let mut writer = PerfSpoolWriter::from_writer(Vec::new(), 0, 0).unwrap();
        let mut summary = PerfSummary::default();
        let mut stack_scratch = Vec::new();
        let mut lifecycle_actions = Vec::new();
        let mut module = test_module(0x1000, 0x2000);
        module.process_id = pid;
        let module_id = modules.intern_module(module, &mut writer).unwrap();

        let mut ctx = EventContext {
            modules: &mut modules,
            unwinders: &mut unwinders,
            active_processes: &mut active_processes,
            process_images: &mut process_images,
            process_start_times: &mut process_start_times,
            python_perf_support_processes: &mut python_perf_support_processes,
            python_runtime_processes: &mut python_runtime_processes,
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
        let mut unwinders = FxHashMap::default();
        let mut active_processes = FxHashMap::default();
        let mut process_images = FxHashMap::from_iter([(parent_pid, inherited_identity.clone())]);
        let mut process_start_times = FxHashMap::default();
        let mut python_perf_support_processes = FxHashMap::default();
        let mut python_runtime_processes = FxHashSet::default();
        let mut writer = PerfSpoolWriter::from_writer(Vec::new(), 0, 0).unwrap();
        let mut summary = PerfSummary::default();
        let mut stack_scratch = Vec::new();
        let mut lifecycle_actions = Vec::new();
        let mut module = test_module(0x1000, 0x2000);
        module.process_id = parent_pid;
        modules.intern_module(module, &mut writer).unwrap();

        let mut ctx = EventContext {
            modules: &mut modules,
            unwinders: &mut unwinders,
            active_processes: &mut active_processes,
            process_images: &mut process_images,
            process_start_times: &mut process_start_times,
            python_perf_support_processes: &mut python_perf_support_processes,
            python_runtime_processes: &mut python_runtime_processes,
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
            ctx.process_images.get(&child_pid),
            Some(&inherited_identity)
        );
        assert!(ctx.process_start_times.contains_key(&child_pid));
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
    fn cloned_unwinder_resets_refresh_cache() {
        let mut unwinder = ProcessUnwinder::default();
        assert!(unwinder.should_refresh_for_uncovered_pc(0x3000));

        let mut cloned = unwinder.clone();

        assert!(cloned.should_refresh_for_uncovered_pc(0x3000));
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
        let mut unwinders = FxHashMap::default();
        let mut active_processes = FxHashMap::default();
        let mut process_images = FxHashMap::default();
        let mut process_start_times = FxHashMap::default();
        let mut python_perf_support_processes = FxHashMap::default();
        let mut python_runtime_processes = FxHashSet::default();
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
        let prepared = {
            let mut ctx = EventContext {
                modules: &mut modules,
                unwinders: &mut unwinders,
                active_processes: &mut active_processes,
                process_images: &mut process_images,
                process_start_times: &mut process_start_times,
                python_perf_support_processes: &mut python_perf_support_processes,
                python_runtime_processes: &mut python_runtime_processes,
                writer: &mut writer,
                summary: &mut summary,
                stack_scratch: &mut stack_scratch,
                lifecycle_actions: &mut lifecycle_actions,
                inherit_child_processes: false,
            };
            prepare_sample_view(&mut ctx, sample, Priv::User)
                .expect("prepare sample")
                .expect("prepared sample")
        };

        assert!(unwinders.is_empty());
        assert_eq!(summary.sample_events, 1);
        assert_eq!(
            summary
                .error_stats
                .get(SampleErrorKind::NativeRegisterCapture),
            0
        );

        let mut ctx = EventContext {
            modules: &mut modules,
            unwinders: &mut unwinders,
            active_processes: &mut active_processes,
            process_images: &mut process_images,
            process_start_times: &mut process_start_times,
            python_perf_support_processes: &mut python_perf_support_processes,
            python_runtime_processes: &mut python_runtime_processes,
            writer: &mut writer,
            summary: &mut summary,
            stack_scratch: &mut stack_scratch,
            lifecycle_actions: &mut lifecycle_actions,
            inherit_child_processes: false,
        };
        finish_prepared_event(prepared, &mut ctx).expect("finish sample");

        assert!(unwinders.contains_key(&7));
        assert_eq!(
            summary
                .error_stats
                .get(SampleErrorKind::NativeRegisterCapture),
            1
        );
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

    #[test]
    fn fp_user_callchain_fills_missing_dwarf_stack() {
        let mut stack = vec![StackFrame::InstructionPointer(
            0xffff_1000,
            StackMode::Kernel,
        )];
        let fp_user_frames = [
            StackFrame::InstructionPointer(0x1000, StackMode::User),
            StackFrame::ReturnAddress(0x2000, StackMode::User),
        ];

        let used = append_fp_user_callchain(&mut stack, 1, &fp_user_frames, false);

        assert_eq!(used, 2);
        assert_eq!(
            stack,
            vec![
                StackFrame::InstructionPointer(0xffff_1000, StackMode::Kernel),
                StackFrame::InstructionPointer(0x1000, StackMode::User),
                StackFrame::ReturnAddress(0x2000, StackMode::User),
            ]
        );
    }

    #[test]
    fn fp_user_callchain_splices_after_truncated_dwarf_overlap() {
        let mut stack = vec![
            StackFrame::InstructionPointer(0xffff_1000, StackMode::Kernel),
            StackFrame::InstructionPointer(0x1000, StackMode::User),
            StackFrame::ReturnAddress(0x2000, StackMode::User),
        ];
        let fp_user_frames = [
            StackFrame::InstructionPointer(0x1000, StackMode::User),
            StackFrame::ReturnAddress(0x2000, StackMode::User),
            StackFrame::ReturnAddress(0x3000, StackMode::User),
        ];

        let used = append_fp_user_callchain(&mut stack, 1, &fp_user_frames, true);

        assert_eq!(used, 1);
        assert_eq!(
            stack,
            vec![
                StackFrame::InstructionPointer(0xffff_1000, StackMode::Kernel),
                StackFrame::InstructionPointer(0x1000, StackMode::User),
                StackFrame::ReturnAddress(0x2000, StackMode::User),
                StackFrame::ReturnAddress(0x3000, StackMode::User),
            ]
        );
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
    fn truncated_dwarf_stack_keeps_marker_after_spliced_user_callchain() {
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
                StackFrame::ReturnAddress(0x3000, StackMode::User),
                StackFrame::TruncatedStackMarker,
            ]
        );
        assert_eq!(summary.ignored_user_callchain_frames, 2);
        assert_eq!(
            summary
                .error_stats
                .get(SampleErrorKind::NativeStackTruncated),
            1
        );
    }

    #[test]
    fn fp_user_callchain_is_ignored_when_dwarf_stack_is_complete() {
        let mut stack = vec![StackFrame::InstructionPointer(0x1000, StackMode::User)];
        let fp_user_frames = [
            StackFrame::InstructionPointer(0x1000, StackMode::User),
            StackFrame::ReturnAddress(0x2000, StackMode::User),
        ];

        let used = append_fp_user_callchain(&mut stack, 0, &fp_user_frames, false);

        assert_eq!(used, 0);
        assert_eq!(
            stack,
            vec![StackFrame::InstructionPointer(0x1000, StackMode::User)]
        );
    }

    #[test]
    fn only_first_callchain_address_is_instruction_pointer() {
        let mut stack = Vec::new();

        push_callchain_addresses(
            StackMode::Kernel,
            &[0xffff_1000, 0xffff_2000],
            true,
            &mut stack,
        );
        push_callchain_addresses(StackMode::User, &[0x1000, 0x2000], false, &mut stack);

        assert_eq!(
            stack,
            vec![
                StackFrame::InstructionPointer(0xffff_1000, StackMode::Kernel),
                StackFrame::ReturnAddress(0xffff_2000, StackMode::Kernel),
                StackFrame::ReturnAddress(0x1000, StackMode::User),
                StackFrame::ReturnAddress(0x2000, StackMode::User),
            ]
        );
    }

    #[test]
    fn resolving_multisegment_callchain_adjusts_segment_head_return_addresses() {
        let mut stack = Vec::new();
        push_callchain_addresses(
            StackMode::Kernel,
            &[0xffff_1000, 0xffff_2000],
            true,
            &mut stack,
        );
        push_callchain_addresses(StackMode::User, &[0x1000, 0x2000], false, &mut stack);
        let mut modules = ModuleTable::default();
        let mut summary = PerfSummary::default();

        let frames: Vec<_> = stack
            .into_iter()
            .map(|frame| resolve_stack_frame(&mut modules, &mut summary, 7, frame).unwrap())
            .collect();

        assert_eq!(frames[0].abs_ip, 0xffff_1000);
        assert_eq!(frames[1].abs_ip, 0xffff_1fff);
        assert_eq!(frames[2].abs_ip, 0x0fff);
        assert_eq!(frames[3].abs_ip, 0x1fff);
    }

    #[test]
    fn get_sample_stack_marks_user_callchain_truncated_when_unwind_inputs_are_missing() {
        let chains = vec![CallChain::User(vec![0x1000, 0x2000])];
        let sample = SampleView {
            task: None,
            timestamp_ns: None,
            code_addr: None,
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
            vec![
                StackFrame::InstructionPointer(0x1000, StackMode::User),
                StackFrame::ReturnAddress(0x2000, StackMode::User),
                StackFrame::TruncatedStackMarker,
            ]
        );
        assert_eq!(summary.ignored_user_callchain_frames, 0);
        assert_eq!(
            summary
                .error_stats
                .get(SampleErrorKind::NativeUserRegistersMissing),
            1
        );
        assert_eq!(summary.error_stats.get(SampleErrorKind::NativeStackRead), 1);
    }

    #[test]
    fn get_sample_stack_marks_kernel_sample_user_tail_truncated_when_regs_are_missing() {
        let chains = vec![
            CallChain::Kernel(vec![0xffff_1000]),
            CallChain::User(vec![0x1000]),
        ];
        let sample = SampleView {
            task: None,
            timestamp_ns: None,
            code_addr: None,
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
            Priv::Kernel,
            &mut process_unwinder,
            &mut stack,
            &mut callchain_stack,
            &mut summary,
        );

        assert_eq!(
            stack,
            vec![
                StackFrame::InstructionPointer(0xffff_1000, StackMode::Kernel),
                StackFrame::ReturnAddress(0x1000, StackMode::User),
                StackFrame::TruncatedStackMarker,
            ]
        );
        assert_eq!(summary.ignored_user_callchain_frames, 0);
        assert_eq!(
            summary
                .error_stats
                .get(SampleErrorKind::NativeUserRegistersMissing),
            1
        );
    }

    #[test]
    fn get_sample_stack_uses_user_callchain_when_register_conversion_fails() {
        let chains = vec![CallChain::User(vec![0x1000, 0x2000])];
        let user_stack = [0_u8; 8];
        let sample = SampleView {
            task: None,
            timestamp_ns: None,
            code_addr: None,
            user_regs: Some(&[]),
            user_stack: Some(&user_stack),
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
            vec![
                StackFrame::InstructionPointer(0x1000, StackMode::User),
                StackFrame::ReturnAddress(0x2000, StackMode::User),
            ]
        );
        assert_eq!(summary.ignored_user_callchain_frames, 0);
        assert_eq!(
            summary
                .error_stats
                .get(SampleErrorKind::NativeRegisterCapture),
            1
        );
    }

    #[test]
    fn get_sample_stack_treats_zero_user_stack_as_bad_sample() {
        let chains = vec![CallChain::User(vec![0x1000, 0x2000])];
        let sample = SampleView {
            task: None,
            timestamp_ns: None,
            code_addr: None,
            user_regs: Some(&[]),
            user_stack: Some(&[]),
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
            vec![
                StackFrame::InstructionPointer(0x1000, StackMode::User),
                StackFrame::ReturnAddress(0x2000, StackMode::User),
            ]
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
    fn forked_python_runtime_child_gets_process_exec_marker() {
        let path = std::env::temp_dir().join(format!(
            "stackpulse-forked-python-runtime-{}.spool",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let mut writer = PerfSpoolWriter::create(&path, 123, 10).unwrap();
        let mut runtime_processes = FxHashSet::default();
        runtime_processes.insert(7);

        inherit_python_runtime_process(&mut runtime_processes, &mut writer, 456, 7, 8).unwrap();
        writer.flush().unwrap();
        drop(writer);

        let reader = crate::spool::PerfSpoolReader::open(&path).unwrap();
        let _ = std::fs::remove_file(path);
        assert!(runtime_processes.contains(&8));
        assert!(reader.process_execs().iter().any(|exec| {
            exec.timestamp_ns == 456 && exec.process_id == 8 && exec.is_python_runtime
        }));
    }
}
