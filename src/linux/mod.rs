mod convert_regs;
pub(crate) mod elf_loader;
pub(crate) mod elf_types;
pub(crate) mod perf_event;
mod perf_group;
pub mod process;
mod sorter;
#[cfg(test)]
mod test_fixtures;
mod types;

use std::io;
use std::path::Path;

use crate::state::{poll_exit_watcher, process_exists, try_new_exit_watcher, ProcessExitWatcher};
use crate::{SampleErrorKind, SampleErrorStats};
use framehop::{Error as FramehopError, FrameAddress, Unwinder};
use perf_event_open::sample::record::mmap::{Info as MmapInfo, Mmap};
use perf_event_open::sample::record::sample::{CallChain, Sample};
use perf_event_open::sample::record::{Priv, Record};
use rustc_hash::{FxHashMap, FxHashSet};

use crate::native_module::ElfSectionCache;
use crate::spool::{FrameMode, FrameRecord, ModuleRecord, ModuleTable, PerfSpoolWriter};
use convert_regs::ConvertRegs;
use perf_event::{
    CallChainEntry, CallChainRef, EventRecord, EventRef, EventSource, SampleRecordRef,
};
pub use perf_group::AttachMode;
use perf_group::PerfGroupOptions;
use types::{StackFrame, StackMode};

#[cfg(target_arch = "x86_64")]
type ConvertRegsNative = convert_regs::ConvertRegsX86_64;

#[cfg(target_arch = "aarch64")]
type ConvertRegsNative = convert_regs::ConvertRegsAarch64;

type UnwindPolicy = framehop::MayAllocateDuringUnwind;
type NativeUnwinder = framehop::UnwinderNative<elf_types::ElfSectionData, UnwindPolicy>;
type NativeCache = framehop::CacheNative<UnwindPolicy>;

enum ThreadAction {
    Fork { tid: u32, parent_tid: u32 },
    Exit { tid: u32 },
}

enum ProcessAction {
    Fork { pid: u32, parent_tid: u32 },
}

#[derive(Default)]
struct ProcessUnwinder {
    unwinder: NativeUnwinder,
    cache: NativeCache,
    loaded_module_starts: FxHashSet<u64>,
    elf_sections: ElfSectionCache,
}

impl Clone for ProcessUnwinder {
    /// Forks: clone the unwinder state and module set, but start with a fresh
    /// per-thread cache (cloning the cache would defeat its locality).
    fn clone(&self) -> Self {
        Self {
            unwinder: self.unwinder.clone(),
            cache: NativeCache::default(),
            loaded_module_starts: self.loaded_module_starts.clone(),
            elf_sections: self.elf_sections.clone(),
        }
    }
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
    /// User callchain frames ignored when kernel callchains were being used.
    pub ignored_user_callchain_frames: u64,
    /// Per-kind sample error counts.
    pub error_stats: SampleErrorStats,
}

/// Records stack samples for one or more Linux processes.
pub struct PerfRecorder {
    perf: perf_group::PerfGroup,
    writer: PerfSpoolWriter<std::io::BufWriter<std::fs::File>>,
    modules: ModuleTable,
    unwinders: FxHashMap<i32, ProcessUnwinder>,
    active_processes: FxHashMap<i32, Option<ProcessExitWatcher>>,
    python_perf_support_processes: FxHashSet<i32>,
    python_runtime_processes: FxHashSet<i32>,
    stack_scratch: Vec<StackFrame>,
    summary: PerfSummary,
}

struct EventContext<'a, W: std::io::Write> {
    modules: &'a mut ModuleTable,
    unwinders: &'a mut FxHashMap<i32, ProcessUnwinder>,
    active_processes: &'a mut FxHashMap<i32, Option<ProcessExitWatcher>>,
    python_perf_support_processes: &'a mut FxHashSet<i32>,
    python_runtime_processes: &'a mut FxHashSet<i32>,
    writer: &'a mut PerfSpoolWriter<W>,
    summary: &'a mut PerfSummary,
    stack_scratch: &'a mut Vec<StackFrame>,
    thread_actions: &'a mut Vec<ThreadAction>,
    process_actions: &'a mut Vec<ProcessAction>,
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
        let mut python_perf_support_processes = FxHashSet::default();
        let mut python_runtime_processes = FxHashSet::default();
        if let Some(pid_i32) = i32_from_u32(pid) {
            active_processes.insert(pid_i32, try_new_exit_watcher(pid_i32));
            if attach_mode == AttachMode::AttachWithEnableOnExec
                || process_has_python_perf_support_env(pid)
            {
                python_perf_support_processes.insert(pid_i32);
            }
        }
        let registered_existing_maps = attach_mode == AttachMode::StopAttachEnableResume
            && register_existing_maps(pid, &mut modules, &mut unwinders, &mut writer)?;
        if let Some(pid_i32) = i32_from_u32(pid).filter(|pid_i32| {
            registered_existing_maps && python_perf_support_processes.contains(pid_i32)
        }) {
            mark_python_runtime_process(&mut python_runtime_processes, &mut writer, 0, pid_i32)?;
        }

        let mut recorder = Self {
            perf,
            writer,
            modules,
            unwinders,
            active_processes,
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
        let Self {
            perf,
            modules,
            unwinders,
            active_processes,
            python_perf_support_processes,
            python_runtime_processes,
            stack_scratch,
            writer,
            summary,
        } = self;
        let mut result = Ok(());
        let mut thread_actions = Vec::new();
        let mut process_actions = Vec::new();
        {
            let mut ctx = EventContext {
                modules,
                unwinders,
                active_processes,
                python_perf_support_processes,
                python_runtime_processes,
                writer,
                summary,
                stack_scratch,
                thread_actions: &mut thread_actions,
                process_actions: &mut process_actions,
            };
            perf.consume_events(&mut |event_ref| {
                if result.is_err() {
                    return;
                }
                result = handle_event(event_ref, &mut ctx);
            });
        }
        if result.is_ok() {
            for action in &thread_actions {
                match action {
                    ThreadAction::Fork { tid, parent_tid } => {
                        result = perf.open_forked_threads(&[(*tid, *parent_tid)]);
                    }
                    ThreadAction::Exit { .. } => {}
                }
                if result.is_err() {
                    break;
                }
            }
        }
        if result.is_ok() {
            for action in process_actions {
                match action {
                    ProcessAction::Fork { pid, parent_tid } => {
                        result = perf.open_forked_processes(&[(pid, parent_tid)]);
                    }
                }
                if result.is_err() {
                    break;
                }
            }
        }
        if result.is_ok() {
            for action in thread_actions {
                if let ThreadAction::Exit { tid } = action {
                    perf.remove_thread(tid);
                }
            }
        }
        result
    }

    /// Wait briefly for more profiling data to become readable.
    pub fn wait(&mut self) -> io::Result<()> {
        self.perf.wait()
    }

    /// Add another process to this recording.
    pub fn open_process(&mut self, pid: u32, attach_mode: AttachMode) -> io::Result<()> {
        self.perf.open_process(pid, attach_mode)?;
        if let Some(pid_i32) = i32_from_u32(pid) {
            self.track_process(pid_i32);
            if process_has_python_perf_support_env(pid) {
                self.python_perf_support_processes.insert(pid_i32);
            }
            match register_existing_maps(
                pid,
                &mut self.modules,
                &mut self.unwinders,
                &mut self.writer,
            ) {
                Ok(true) if self.python_perf_support_processes.contains(&pid_i32) => {
                    if let Err(err) = mark_python_runtime_process(
                        &mut self.python_runtime_processes,
                        &mut self.writer,
                        0,
                        pid_i32,
                    ) {
                        self.perf.resume_stopped_processes();
                        return Err(err);
                    }
                }
                Ok(_) => {}
                Err(err) => {
                    self.perf.resume_stopped_processes();
                    return Err(err);
                }
            }
        }
        if attach_mode == AttachMode::StopAttachEnableResume {
            if let Err(err) = self.perf.enable() {
                self.perf.resume_stopped_processes();
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
        self.perf.has_pending_events()
    }

    /// Return a snapshot of the current counters.
    pub fn summary(&self) -> PerfSummary {
        self.summary.clone()
    }

    /// Return the process ids still believed to be alive.
    pub fn active_processes(&mut self) -> Vec<i32> {
        self.reconcile_active_processes();
        self.active_processes.keys().copied().collect()
    }

    /// Return whether `pid` is still believed to be alive.
    pub fn process_is_active(&mut self, pid: i32) -> bool {
        self.reconcile_active_processes();
        self.active_processes.contains_key(&pid)
    }

    /// Return whether any active process other than `pid` remains.
    pub fn has_active_processes_except(&mut self, pid: i32) -> bool {
        self.reconcile_active_processes();
        self.active_processes
            .keys()
            .any(|&active_pid| active_pid != pid)
    }

    /// Return active process ids, excluding `pid`.
    pub fn active_processes_except(&mut self, pid: i32) -> Vec<i32> {
        self.reconcile_active_processes();
        self.active_processes
            .keys()
            .copied()
            .filter(|&active_pid| active_pid != pid)
            .collect()
    }

    /// Flush the profile file and return the final counters.
    pub fn finish(mut self) -> io::Result<PerfSummary> {
        self.writer.flush()?;
        Ok(self.summary)
    }

    fn reconcile_active_processes(&mut self) {
        self.active_processes
            .retain(|&pid, watcher| !poll_exit_watcher(watcher, pid) && process_exists(pid));
    }

    fn track_process(&mut self, pid: i32) {
        self.active_processes
            .entry(pid)
            .or_insert_with(|| try_new_exit_watcher(pid));
    }
}

fn handle_event<W: std::io::Write>(
    event_ref: EventRef,
    ctx: &mut EventContext<'_, W>,
) -> io::Result<()> {
    let event_timestamp_ns = event_ref.timestamp().unwrap_or(0);
    let (privilege, record) = event_ref.into_parts();
    match record {
        EventRecord::Sample(sample) => record_sample_ref(ctx, sample, privilege),
        EventRecord::Owned(Record::Sample(sample)) => record_sample(ctx, &sample, privilege),
        EventRecord::Owned(Record::Mmap(mmap)) => {
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
        EventRecord::Owned(Record::Fork(fork)) if fork.task.pid != fork.parent_task.pid => {
            let Some(pid) = i32_from_u32(fork.task.pid) else {
                return Ok(());
            };
            let Some(ppid) = i32_from_u32(fork.parent_task.pid) else {
                return Ok(());
            };
            ctx.active_processes
                .entry(pid)
                .or_insert_with(|| try_new_exit_watcher(pid));
            if ctx.python_perf_support_processes.contains(&ppid) {
                ctx.python_perf_support_processes.insert(pid);
            }
            if let Some(parent) = ctx.unwinders.get(&ppid).cloned() {
                ctx.unwinders.insert(pid, parent);
            }
            ctx.process_actions.push(ProcessAction::Fork {
                pid: fork.task.pid,
                parent_tid: fork.parent_task.tid,
            });
            ctx.modules.clone_process_modules(ppid, pid, ctx.writer)
        }
        EventRecord::Owned(Record::Fork(fork)) if fork.task.pid == fork.parent_task.pid => {
            if fork.task.tid != fork.parent_task.tid {
                ctx.thread_actions.push(ThreadAction::Fork {
                    tid: fork.task.tid,
                    parent_tid: fork.parent_task.tid,
                });
            }
            Ok(())
        }
        EventRecord::Owned(Record::Comm(comm)) if comm.task.pid == comm.task.tid => {
            if let Some(pid) = i32_from_u32(comm.task.pid) {
                if comm.by_execve {
                    cleanup_process_modules(pid, ctx.modules, ctx.unwinders);
                }
                if let Some(is_python_runtime) = process_executable_is_python_runtime(comm.task.pid)
                {
                    if is_python_runtime
                        && process_has_python_perf_support(
                            comm.task.pid,
                            ctx.python_perf_support_processes,
                        )
                    {
                        mark_python_runtime_process(
                            ctx.python_runtime_processes,
                            ctx.writer,
                            event_timestamp_ns,
                            pid,
                        )?;
                    } else if ctx.python_runtime_processes.remove(&pid) {
                        ctx.writer
                            .write_process_exec(event_timestamp_ns, pid, false)?;
                    }
                }
                match register_existing_maps(comm.task.pid, ctx.modules, ctx.unwinders, ctx.writer)
                {
                    Ok(true)
                        if process_has_python_perf_support(
                            comm.task.pid,
                            ctx.python_perf_support_processes,
                        ) =>
                    {
                        mark_python_runtime_process(
                            ctx.python_runtime_processes,
                            ctx.writer,
                            event_timestamp_ns,
                            pid,
                        )?;
                    }
                    Ok(_) => {}
                    Err(err) => {
                        if !process_gone_error(&err) {
                            return Err(err);
                        }
                    }
                }
            }
            Ok(())
        }
        EventRecord::Owned(Record::Exit(exit)) if exit.task.pid == exit.task.tid => {
            if let Some(pid) = i32_from_u32(exit.task.pid) {
                if ctx.python_runtime_processes.remove(&pid) {
                    ctx.writer
                        .write_process_exec(event_timestamp_ns, pid, false)?;
                }
                cleanup_process(
                    pid,
                    ctx.modules,
                    ctx.unwinders,
                    ctx.active_processes,
                    ctx.python_perf_support_processes,
                    ctx.python_runtime_processes,
                );
            }
            Ok(())
        }
        EventRecord::Owned(Record::Exit(exit)) => {
            if exit.task.pid == exit.parent_task.pid {
                ctx.thread_actions
                    .push(ThreadAction::Exit { tid: exit.task.tid });
            }
            Ok(())
        }
        EventRecord::Owned(Record::LostRecords(lost)) => {
            ctx.summary.lost_events = ctx.summary.lost_events.saturating_add(lost.lost_records);
            Ok(())
        }
        EventRecord::Owned(Record::LostSamples(lost)) => {
            ctx.summary.lost_events = ctx.summary.lost_events.saturating_add(lost.lost_samples);
            Ok(())
        }
        _ => Ok(()),
    }
}

fn i32_from_u32(value: u32) -> Option<i32> {
    i32::try_from(value).ok()
}

fn cleanup_process(
    pid: i32,
    modules: &mut ModuleTable,
    unwinders: &mut FxHashMap<i32, ProcessUnwinder>,
    active_processes: &mut FxHashMap<i32, Option<ProcessExitWatcher>>,
    python_perf_support_processes: &mut FxHashSet<i32>,
    python_runtime_processes: &mut FxHashSet<i32>,
) {
    cleanup_process_modules(pid, modules, unwinders);
    active_processes.remove(&pid);
    python_perf_support_processes.remove(&pid);
    python_runtime_processes.remove(&pid);
}

fn cleanup_process_modules(
    pid: i32,
    modules: &mut ModuleTable,
    unwinders: &mut FxHashMap<i32, ProcessUnwinder>,
) {
    modules.deactivate_process_modules(pid);
    unwinders.remove(&pid);
}

fn process_gone_error(err: &io::Error) -> bool {
    err.kind() == io::ErrorKind::NotFound || err.raw_os_error() == Some(libc::ESRCH)
}

fn process_executable_is_python_runtime(pid: u32) -> Option<bool> {
    let exe = std::fs::read_link(format!("/proc/{pid}/exe")).ok()?;
    Some(
        exe.file_name()
            .and_then(|name| name.to_str())
            .is_some_and(crate::is_python_module),
    )
}

fn process_has_python_perf_support_env(pid: u32) -> bool {
    std::fs::read(format!("/proc/{pid}/environ"))
        .ok()
        .is_some_and(|env| {
            env.split(|byte| *byte == 0)
                .any(|entry| entry == b"PYTHONPERFSUPPORT=1")
        })
}

fn process_has_python_perf_support(
    pid: u32,
    python_perf_support_processes: &mut FxHashSet<i32>,
) -> bool {
    let Some(pid_i32) = i32_from_u32(pid) else {
        return false;
    };
    if python_perf_support_processes.contains(&pid_i32) {
        return true;
    }
    if process_has_python_perf_support_env(pid) {
        python_perf_support_processes.insert(pid_i32);
        return true;
    }
    false
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

fn record_python_runtime_mmap<W: std::io::Write>(
    mmap: &Mmap,
    privilege: Priv,
    timestamp_ns: u64,
    python_perf_support_processes: &mut FxHashSet<i32>,
    python_runtime_processes: &mut FxHashSet<i32>,
    writer: &mut PerfSpoolWriter<W>,
) -> io::Result<()> {
    if is_kernel_mode(privilege) || !mmap_is_executable(mmap) {
        return Ok(());
    }
    let Some(pid) = i32_from_u32(mmap.task.pid) else {
        return Ok(());
    };
    if !is_python_runtime_path(&c_string_to_string(&mmap.file)) {
        return Ok(());
    }
    if process_has_python_perf_support(mmap.task.pid, python_perf_support_processes) {
        mark_python_runtime_process(python_runtime_processes, writer, timestamp_ns, pid)?;
    }
    Ok(())
}

fn record_sample<W: std::io::Write>(
    ctx: &mut EventContext<'_, W>,
    sample: &Sample,
    privilege: Priv,
) -> io::Result<()> {
    record_sample_view(ctx, SampleView::from_owned(sample), privilege)
}

fn record_sample_ref<W: std::io::Write>(
    ctx: &mut EventContext<'_, W>,
    sample: SampleRecordRef<'_>,
    privilege: Priv,
) -> io::Result<()> {
    record_sample_view(ctx, SampleView::from_ref(sample), privilege)
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
enum SampleCallChain<'a> {
    None,
    Owned(&'a [CallChain]),
    Borrowed(CallChainRef<'a>),
}

impl<'a> SampleView<'a> {
    fn from_owned(sample: &'a Sample) -> Self {
        Self {
            task: sample
                .record_id
                .task
                .as_ref()
                .map(|task| (task.pid, task.tid)),
            timestamp_ns: sample.record_id.time,
            code_addr: sample.code_addr,
            user_regs: sample.user_regs.as_ref().map(|(regs, _)| regs.as_slice()),
            user_stack: sample.user_stack.as_deref(),
            call_chain: sample
                .call_chain
                .as_deref()
                .map_or(SampleCallChain::None, SampleCallChain::Owned),
        }
    }

    fn from_ref(sample: SampleRecordRef<'a>) -> Self {
        Self {
            task: sample.task.map(|task| (task.pid, task.tid)),
            timestamp_ns: sample.time,
            code_addr: sample.code_addr,
            user_regs: sample.user_regs.map(|regs| regs.as_slice()),
            user_stack: sample.user_stack,
            call_chain: sample
                .call_chain
                .map_or(SampleCallChain::None, SampleCallChain::Borrowed),
        }
    }
}

fn record_sample_view<W: std::io::Write>(
    ctx: &mut EventContext<'_, W>,
    sample: SampleView<'_>,
    privilege: Priv,
) -> io::Result<()> {
    bump(&mut ctx.summary.sample_events);
    let Some((raw_pid, raw_tid)) = sample.task else {
        bump(&mut ctx.summary.missing_pid_samples);
        return Ok(());
    };
    let Some(pid) = i32_from_u32(raw_pid) else {
        bump(&mut ctx.summary.missing_pid_samples);
        return Ok(());
    };
    let Some(tid) = i32_from_u32(raw_tid) else {
        bump(&mut ctx.summary.missing_tid_samples);
        return Ok(());
    };
    if tid == 0 {
        bump(&mut ctx.summary.idle_tid_samples);
        return Ok(());
    }
    let Some(timestamp_ns) = sample.timestamp_ns else {
        bump(&mut ctx.summary.missing_timestamp_samples);
        return Ok(());
    };

    let unwinder = ctx.unwinders.entry(pid).or_default();
    get_sample_stack::<ConvertRegsNative>(
        sample,
        privilege,
        unwinder,
        ctx.stack_scratch,
        ctx.summary,
    );
    let truncated_frames = ctx
        .stack_scratch
        .iter()
        .filter(|frame| matches!(frame, StackFrame::TruncatedStackMarker))
        .count();
    ctx.summary.truncated_frame_markers = ctx
        .summary
        .truncated_frame_markers
        .saturating_add(truncated_frames as u64);

    let stack_id = ctx.writer.write_sample_frames(
        timestamp_ns,
        pid,
        tid as u64,
        ctx.stack_scratch
            .iter()
            .copied()
            .filter_map(|frame| resolve_stack_frame(ctx.modules, pid, frame)),
    )?;
    if stack_id.is_none() {
        bump(&mut ctx.summary.empty_stack_samples);
        return Ok(());
    }
    bump(&mut ctx.summary.samples);
    Ok(())
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
    add_unwind_module(unwinders, &module);
    modules.intern_module(module, writer)?;
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
    let inode = match &mmap.ext {
        Some(ext) => match &ext.info {
            MmapInfo::Device { inode, .. } => *inode,
            MmapInfo::BuildId(_) => 0,
        },
        None => 0,
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

fn add_unwind_module(unwinders: &mut FxHashMap<i32, ProcessUnwinder>, module: &ModuleRecord) {
    if module.is_kernel || !Path::new(&module.path).is_file() {
        return;
    }
    let process_unwinder = unwinders.entry(module.process_id).or_default();
    if process_unwinder
        .loaded_module_starts
        .contains(&module.start)
    {
        return;
    }
    let Some(framehop_module) = module_to_framehop(&mut process_unwinder.elf_sections, module)
    else {
        return;
    };
    process_unwinder.loaded_module_starts.insert(module.start);
    process_unwinder.unwinder.add_module(framehop_module);
}

fn module_to_framehop(
    elf_sections: &mut ElfSectionCache,
    module: &ModuleRecord,
) -> Option<framehop::Module<elf_types::ElfSectionData>> {
    let (module_info, section_info) = elf_sections.module_info(module)?;
    elf_loader::module_to_framehop_with_section_info(&module_info, &section_info)
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
    let mut saw_python_runtime = false;
    for region in crate::proc_maps::parse(&maps)
        .into_iter()
        .filter(|r| r.is_executable && !r.path.is_empty())
    {
        saw_python_runtime |= is_python_runtime_path(&region.path);
        record_module(
            modules,
            unwinders,
            writer,
            ModuleRecord {
                id: 0,
                process_id: pid as i32,
                start: region.start,
                end: region.end,
                file_offset: region.file_offset,
                path: region.path.into(),
                is_kernel: false,
                inode: region.inode,
            },
        )?;
    }
    Ok(saw_python_runtime)
}

fn is_python_runtime_path(path: &str) -> bool {
    Path::new(path)
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(crate::is_python_module)
}

fn get_sample_stack<C: ConvertRegs<UnwindRegs = <NativeUnwinder as Unwinder>::UnwindRegs>>(
    sample: SampleView<'_>,
    privilege: Priv,
    process_unwinder: &mut ProcessUnwinder,
    stack: &mut Vec<StackFrame>,
    summary: &mut PerfSummary,
) {
    stack.clear();

    push_sample_callchain(sample.call_chain, stack, summary);

    match (sample.user_regs, sample.user_stack) {
        (Some(raw_regs), Some(user_stack)) => {
            let Some((pc, sp, regs)) = C::convert_regs(raw_regs) else {
                record_unwind_error(summary, SampleErrorKind::NativeRegisterCapture, || {
                    "perf sample contained incomplete user register state".to_string()
                });
                return;
            };
            let mut read_stack = |addr: u64| {
                let index = addr
                    .checked_sub(sp)
                    .and_then(|offset| usize::try_from(offset / 8).ok())
                    .ok_or(())?;
                read_stack_u64(user_stack, index)
            };

            let mut frames = process_unwinder.unwinder.iter_frames(
                pc,
                regs,
                &mut process_unwinder.cache,
                &mut read_stack,
            );
            loop {
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
                        stack.push(StackFrame::TruncatedStackMarker);
                        break;
                    }
                }
            }
        }
        _ if !is_kernel_mode(privilege) => {
            if sample.user_regs.is_none() {
                record_unwind_error(summary, SampleErrorKind::NativeRegisterCapture, || {
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

    if stack.is_empty() {
        if let Some((ip, _)) = sample.code_addr {
            stack.push(StackFrame::InstructionPointer(ip, privilege.into()));
        }
    }
}

fn push_sample_callchain(
    call_chain: SampleCallChain<'_>,
    stack: &mut Vec<StackFrame>,
    summary: &mut PerfSummary,
) {
    match call_chain {
        SampleCallChain::None => {}
        SampleCallChain::Owned(chains) => {
            for chain in chains {
                let (mode, addresses) = match chain {
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
                push_callchain_addresses(mode, addresses, stack, summary);
            }
        }
        SampleCallChain::Borrowed(chains) => {
            for chain in chains.iter() {
                let (mode, addresses) = match chain {
                    CallChainEntry::Kernel(addresses)
                    | CallChainEntry::Hv(addresses)
                    | CallChainEntry::GuestKernel(addresses) => (StackMode::Kernel, addresses),
                    CallChainEntry::User(addresses)
                    | CallChainEntry::Guest(addresses)
                    | CallChainEntry::GuestUser(addresses)
                    | CallChainEntry::Unknown(addresses) => (StackMode::User, addresses),
                };
                push_callchain_addresses(mode, addresses, stack, summary);
            }
        }
    }
}

fn push_callchain_addresses(
    mode: StackMode,
    addresses: &[u64],
    stack: &mut Vec<StackFrame>,
    summary: &mut PerfSummary,
) {
    if mode == StackMode::User {
        summary.ignored_user_callchain_frames = summary
            .ignored_user_callchain_frames
            .saturating_add(addresses.len() as u64);
        return;
    }
    for &address in addresses {
        stack.push(if stack.is_empty() {
            StackFrame::InstructionPointer(address, mode)
        } else {
            StackFrame::ReturnAddress(address, mode)
        });
    }
}

fn read_stack_u64(stack: &[u8], index: usize) -> Result<u64, ()> {
    let offset = index.checked_mul(std::mem::size_of::<u64>()).ok_or(())?;
    let bytes = stack
        .get(offset..offset + std::mem::size_of::<u64>())
        .ok_or(())?;
    Ok(u64::from_ne_bytes(bytes.try_into().map_err(|_| ())?))
}

fn resolve_stack_frame(
    modules: &mut ModuleTable,
    process_id: i32,
    frame: StackFrame,
) -> Option<FrameRecord> {
    let (address, mode) = match frame {
        StackFrame::InstructionPointer(address, mode) => (address, mode),
        StackFrame::ReturnAddress(address, mode) => (address.saturating_sub(1), mode),
        StackFrame::TruncatedStackMarker => return None,
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
