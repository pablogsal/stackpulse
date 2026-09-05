mod aligned_bytes;
mod attach;
#[cfg(any(test, feature = "bench-support"))]
mod bench;
mod convert_regs;
mod cpu;
mod module_tracking;
pub(crate) mod perf_event;
mod perf_group;
/// Launch a process suspended and attach recording before `execve`.
pub mod process;
mod ring_buffer;
mod sorter;
mod types;
mod unwind;

#[cfg(any(test, feature = "bench-support"))]
pub(crate) use bench::{
    bench_parse_live_perf_samples, bench_perf_ring_record_lifecycle,
    bench_replay_live_perf_ring_records, live_perf_sample_bench_fixture,
    LivePerfSampleBenchFixture,
};

use std::io;
use std::num::NonZeroU32;
use std::os::fd::RawFd;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::time::{Duration, Instant};

use crate::state::ProcessExitWatcher;
use crate::stats::{SampleErrorKind, SampleErrorStats};
use crate::unwind_stats::{UnwindFallbackKind, UnwindFallbackStats};

fn try_new_exit_watcher(pid: i32) -> Option<ProcessExitWatcher> {
    crate::Pid::new(pid).and_then(|pid| ProcessExitWatcher::try_new(pid).ok())
}

use framehop::{
    DwarfUnwinderError, Error as FramehopError, FrameAddress, FramePointerFallbackReason, Unwinder,
    UnwinderError,
};
use perf_event_open::sample::record::mmap::Mmap;
use perf_event_open::sample::record::sample::Abi as SampleRegsAbi;
use perf_event_open::sample::record::sample::{CallChain, Sample};
use perf_event_open::sample::record::{Priv, Record};
use rustc_hash::FxHashMap;

use crate::native_module::ElfSectionCache;
use crate::spool::{FrameMode, FrameRecord, ModuleTable, PerfSpoolWriter};
#[cfg(test)]
use crate::spool::{ModuleOwner, ModuleRecord};
use attach::read_process_start_time;
use convert_regs::ConvertRegs;
#[cfg(any(test, feature = "bench-support"))]
use module_tracking::record_module;
use module_tracking::{
    executable_modules_from_maps, mmap_is_executable, read_existing_maps, record_mmap,
    register_existing_maps_snapshot, register_existing_modules,
};
use perf_event::{
    CallChainEntry, CallChainIter, CallChainRef, EventRecord, EventRef, EventSource, RingSample,
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
    Final,
}

impl DrainMode {
    fn forces_bookkeeping(self) -> bool {
        matches!(self, Self::Flush | Self::Final)
    }

    fn opens_new_perf_events(self) -> bool {
        !matches!(self, Self::Final)
    }
}

pub(super) const DEFAULT_RING_BUFFER_STACKS: u32 = 32;
const LOST_RECORD_READ_INTERVAL: Duration = Duration::from_millis(100);
const RECOVERY_SWEEP_INTERVAL: Duration = Duration::from_millis(250);

pub(super) fn normalized_ring_stacks(ring_stacks: u32) -> u32 {
    if ring_stacks == 0 {
        DEFAULT_RING_BUFFER_STACKS
    } else {
        ring_stacks
    }
}

pub(super) fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

pub(super) fn checked_loss_sum(total: u64, lost: u64) -> io::Result<u64> {
    total
        .checked_add(lost)
        .ok_or_else(|| invalid_data("perf lost-record overflow"))
}

fn interval_due(last: &mut Option<Instant>, interval: Duration, force: bool) -> bool {
    let now = Instant::now();
    let due = force || last.is_none_or(|previous| now.duration_since(previous) >= interval);
    if due {
        *last = Some(now);
    }
    due
}

#[derive(Default)]
struct CapturePacing {
    last_lost_read: Option<Instant>,
    last_recovery_sweep: Option<Instant>,
    recovery_sweep_pending: bool,
}

impl CapturePacing {
    fn should_read_lost_records(&mut self, mode: DrainMode) -> bool {
        interval_due(
            &mut self.last_lost_read,
            LOST_RECORD_READ_INTERVAL,
            mode.forces_bookkeeping(),
        )
    }

    fn observe_recovery_gap(&mut self, gap_observed: bool) {
        self.recovery_sweep_pending |= gap_observed;
    }

    fn should_run_recovery_sweep(&mut self, mode: DrainMode) -> bool {
        if !self.recovery_sweep_pending {
            return false;
        }
        interval_due(
            &mut self.last_recovery_sweep,
            RECOVERY_SWEEP_INTERVAL,
            mode.forces_bookkeeping(),
        )
    }

    fn complete_recovery_sweep(&mut self) {
        self.recovery_sweep_pending = false;
    }
}

/// Valid sampling frequency.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SampleRate {
    /// Fixed samples per second.
    Hertz(NonZeroU32),
    /// Current kernel maximum from `perf_event_max_sample_rate`.
    Maximum,
}

impl SampleRate {
    /// Construct a positive fixed rate.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::InvalidInput`](crate::ErrorKind::InvalidInput) when
    /// `rate` is zero.
    pub fn hz(rate: u32) -> crate::Result<Self> {
        NonZeroU32::new(rate).map(Self::Hertz).ok_or_else(|| {
            crate::Error::message(
                crate::ErrorKind::InvalidInput,
                "sample rate must be positive",
            )
        })
    }

    fn resolve(self) -> io::Result<u32> {
        match self {
            Self::Hertz(rate) => Ok(rate.get()),
            Self::Maximum => {
                let rate = crate::record::read_max_sample_rate()?;
                u32::try_from(rate)
                    .ok()
                    .filter(|&rate| rate != 0)
                    .ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!(
                                "kernel maximum sample rate {rate} is outside 1..={}",
                                u32::MAX
                            ),
                        )
                    })
            }
        }
    }
}

/// Options used when attaching a [`Recorder`] to a process.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct RecorderOptions {
    sample_rate: SampleRate,
    stack_size: u32,
    ring_stacks: u32,
    include_kernel: bool,
    inherit_child_processes: bool,
    start_timestamp_us: u64,
    sample_interval_us: u64,
}

impl RecorderOptions {
    /// Construct a usable recording configuration.
    #[must_use]
    pub fn new(sample_rate: SampleRate) -> Self {
        Self {
            sample_rate,
            stack_size: 32 * 1024,
            ring_stacks: DEFAULT_RING_BUFFER_STACKS,
            include_kernel: false,
            inherit_child_processes: false,
            start_timestamp_us: 0,
            sample_interval_us: 0,
        }
    }

    /// Set the user-stack snapshot size in bytes.
    #[must_use]
    pub fn stack_size(mut self, stack_size: u32) -> Self {
        self.stack_size = stack_size;
        self
    }

    /// Set the target per-CPU perf data-ring capacity in stack-sized records.
    ///
    /// Capacity is the larger of the configured stack snapshot and system page
    /// size, times this count, with a floor large enough for any perf record and
    /// power-of-two page rounding. On 4 KiB-page hosts, the default count of 32
    /// gives a 1 MiB ring for the default 32 KiB stack and a 2 MiB ring for a
    /// 64 KiB stack. Memory is pinned per CPU. Values
    /// requiring more than 256 MiB per CPU are rejected. Larger valid values
    /// can absorb occasional long stalls, but should be benchmarked under
    /// sustained load before deployment. Zero selects the default. If mmap
    /// fails with `EPERM` or `ENOMEM`, attach progressively halves the ring down
    /// to the minimum valid capacity. All per-CPU rings in one recorder also
    /// share a 1 GiB aggregate data budget; effective capacities are available
    /// in [`RecordingSummary`].
    #[must_use]
    pub fn ring_buffer_stacks(mut self, stacks: u32) -> Self {
        self.ring_stacks = normalized_ring_stacks(stacks);
        self
    }

    /// Include kernel frames when permitted.
    #[must_use]
    pub fn include_kernel(mut self, include: bool) -> Self {
        self.include_kernel = include;
        self
    }

    /// Follow child processes created after recording starts.
    #[must_use]
    pub fn inherit_children(mut self, inherit: bool) -> Self {
        self.inherit_child_processes = inherit;
        self
    }

    /// Set the Unix-timeline anchor stored in the spool header.
    #[must_use]
    pub fn start_timestamp_us(mut self, timestamp: u64) -> Self {
        self.start_timestamp_us = timestamp;
        self
    }

    /// Set optional sampling-interval metadata stored in the spool header.
    #[must_use]
    pub fn sample_interval_us(mut self, interval: u64) -> Self {
        self.sample_interval_us = interval;
        self
    }
}

impl Default for RecorderOptions {
    fn default() -> Self {
        let rate = NonZeroU32::new(1_000).unwrap_or(NonZeroU32::MIN);
        Self::new(SampleRate::Hertz(rate))
    }
}

/// Counters collected while recording.
#[derive(Clone, Debug, Default)]
#[non_exhaustive]
pub struct RecordingSummary {
    /// Raw sample events seen by the recorder.
    pub sample_events: u64,
    /// Samples written to the spool file.
    pub samples: u64,
    /// Events reported lost by the kernel.
    pub lost_events: u64,
    /// Nonzero loss batches that made lifecycle state potentially incomplete.
    pub lifecycle_gaps: u64,
    /// Whether kernel frame capture remained enabled after attach.
    pub kernel_enabled: bool,
    /// Smallest effective per-CPU perf data-ring capacity after mmap fallback.
    pub minimum_ring_buffer_bytes: u64,
    /// Largest effective per-CPU perf data-ring capacity after mmap fallback.
    pub maximum_ring_buffer_bytes: u64,
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
    /// Successful unwind steps that used frame pointers, grouped by reason.
    pub unwind_fallbacks: UnwindFallbackStats,
}

/// Work completed by one [`Recorder::poll`] call.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PollSummary {
    samples: u64,
    lost_events: u64,
}

impl PollSummary {
    /// Return the number of samples written during this poll.
    #[must_use]
    pub const fn samples(self) -> u64 {
        self.samples
    }

    /// Return the number of kernel-reported lost events observed during this poll.
    #[must_use]
    pub const fn lost_events(self) -> u64 {
        self.lost_events
    }
}

/// Result of adding a process to an existing recording.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum AttachOutcome {
    /// The process was attached.
    Attached,
    /// The same live process was already attached.
    AlreadyAttached,
    /// The process exited before attachment completed.
    Exited,
}

/// Result of reconciling an attached process's thread list.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum RefreshOutcome {
    /// The live process's thread list was reconciled.
    Refreshed,
    /// The process exited before its thread list could be read.
    Exited,
}

/// Records stack samples for one or more Linux processes.
///
/// Call [`finish`](Self::finish) to drain perf rings, flush sorted events, and
/// report write errors. Dropping a recorder only disables sampling on a
/// best-effort basis; queued samples may be lost and flush errors cannot be
/// reported from `Drop`.
pub struct Recorder<W: std::io::Write = std::io::BufWriter<std::fs::File>> {
    perf: perf_group::PerfGroup,
    event_sorter: EventSorter<RawFd, u64, PreparedEvent>,
    writer: PerfSpoolWriter<W>,
    modules: ModuleTable,
    processes: ProcessTable,
    exact_images: Option<crate::native_module::ExactImageStore>,
    stack_scratch: Vec<StackFrame>,
    callchain_scratch: Vec<StackFrame>,
    capture_pacing: CapturePacing,
    summary: RecordingSummary,
    disable_on_drop: bool,
}

impl<W: std::io::Write> Drop for Recorder<W> {
    fn drop(&mut self) {
        if self.disable_on_drop {
            let _ = self.perf.disable();
        }
    }
}

impl<W: std::io::Write> std::fmt::Debug for Recorder<W> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Recorder")
            .field("active_processes", &self.processes.states.len())
            .field("summary", &self.summary)
            .finish_non_exhaustive()
    }
}

struct EventContext<'a, W: std::io::Write> {
    modules: &'a mut ModuleTable,
    processes: &'a mut ProcessTable,
    writer: &'a mut PerfSpoolWriter<W>,
    summary: &'a mut RecordingSummary,
    stack_scratch: &'a mut Vec<StackFrame>,
    callchain_scratch: &'a mut Vec<StackFrame>,
    lifecycle_actions: &'a mut Vec<LifecycleAction>,
    inherit_child_processes: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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

enum ProcessLiveness {
    Pidfd(bool),
    Procfs(bool),
}

impl ProcessTracking {
    fn is_tracked(&self) -> bool {
        matches!(self, Self::Tracked(_))
    }

    fn poll_alive_checked(&mut self, pid: crate::Pid) -> crate::Result<Option<bool>> {
        let Self::Tracked(watcher) = self else {
            return Ok(None);
        };
        crate::state::process_is_alive(watcher, pid).map(Some)
    }

    fn pidfd(&self) -> Option<i32> {
        let Self::Tracked(Some(watcher)) = self else {
            return None;
        };
        watcher.poll_fd()
    }

    fn observe_pidfd_revents(&mut self, revents: i16) -> io::Result<()> {
        let Self::Tracked(Some(watcher)) = self else {
            return Ok(());
        };
        watcher.observe_revents(revents)?;
        Ok(())
    }

    fn alive_after_pidfd_poll(&mut self, pid: i32) -> crate::Result<Option<ProcessLiveness>> {
        let Self::Tracked(watcher) = self else {
            return Ok(None);
        };
        Ok(match watcher {
            Some(watcher) => Some(ProcessLiveness::Pidfd(!watcher.is_exited())),
            None => {
                let Some(pid) = crate::Pid::new(pid) else {
                    return Ok(Some(ProcessLiveness::Procfs(false)));
                };
                Some(ProcessLiveness::Procfs(crate::state::process_is_alive(
                    watcher, pid,
                )?))
            }
        })
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
    elf_sections: ElfSectionCache,
    pidfd_pids: Vec<i32>,
    pidfd_poll: Vec<libc::pollfd>,
    dead_pid_scratch: Vec<i32>,
}

impl ProcessTable {
    fn state_mut(&mut self, pid: i32) -> &mut ProcessState {
        self.states.entry(pid).or_default()
    }

    fn apply_module_update(&mut self, pid: i32, update: &crate::spool::ModuleUpdate) {
        let Self {
            states,
            elf_sections,
            ..
        } = self;
        states
            .entry(pid)
            .or_default()
            .unwinder
            .get_or_insert_default()
            .apply_module_update(update, elf_sections);
    }

    fn apply_fork_module_update(&mut self, pid: i32, cloned: &crate::spool::ClonedProcessModules) {
        if !cloned.inherited_unwinder_layout {
            self.apply_module_update(pid, &cloned.update);
            return;
        }
        let Self {
            states,
            elf_sections,
            ..
        } = self;
        states
            .entry(pid)
            .or_default()
            .unwinder
            .get_or_insert_default()
            .reuse_inherited_modules(&cloned.update, elf_sections);
    }

    fn snapshot_for_fork(&self, parent_pid: i32) -> ForkInheritance {
        self.states
            .get(&parent_pid)
            .map_or_else(ForkInheritance::default, |state| ForkInheritance {
                image: state.image,
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

    fn track_or_refresh(&mut self, pid: i32) -> crate::Result<()> {
        let state = self.state_mut(pid);
        match &mut state.tracking {
            ProcessTracking::Untracked => {
                state.tracking = ProcessTracking::Tracked(try_new_exit_watcher(pid));
            }
            ProcessTracking::Tracked(watcher) => {
                let Some(pid) = crate::Pid::new(pid) else {
                    return Ok(());
                };
                if !crate::state::process_is_alive(watcher, pid)? {
                    *watcher = try_new_exit_watcher(pid.get());
                }
            }
        }
        Ok(())
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

    fn dead_or_reused_pids(&mut self) -> crate::Result<Vec<i32>> {
        let Self {
            states,
            pidfd_pids,
            pidfd_poll,
            dead_pid_scratch,
            elf_sections: _,
        } = self;
        pidfd_pids.clear();
        pidfd_poll.clear();
        for (&pid, state) in states.iter() {
            let Some(fd) = state.tracking.pidfd() else {
                continue;
            };
            pidfd_pids.push(pid);
            pidfd_poll.push(libc::pollfd {
                fd,
                events: libc::POLLIN,
                revents: 0,
            });
        }
        if !pidfd_poll.is_empty() {
            crate::state::poll_retry(pidfd_poll, 0)?;
            for (&pid, pollfd) in pidfd_pids.iter().zip(pidfd_poll.iter()) {
                if let Some(state) = states.get_mut(&pid) {
                    state.tracking.observe_pidfd_revents(pollfd.revents)?;
                }
            }
        }
        dead_pid_scratch.clear();
        for (&pid, state) in states.iter_mut() {
            match state.tracking.alive_after_pidfd_poll(pid)? {
                None => continue,
                Some(ProcessLiveness::Pidfd(false) | ProcessLiveness::Procfs(false)) => {
                    dead_pid_scratch.push(pid);
                    continue;
                }
                Some(ProcessLiveness::Pidfd(true)) => continue,
                Some(ProcessLiveness::Procfs(true)) => {}
            }
            let generation_changed = match u32::try_from(pid) {
                Ok(pid) => match read_process_start_time(pid) {
                    Ok(current) => state.start_time.is_some_and(|previous| current != previous),
                    Err(error) if crate::error::is_target_gone_io(&error) => true,
                    Err(error) => return Err(error.into()),
                },
                Err(_) => false,
            };
            if generation_changed {
                dead_pid_scratch.push(pid);
            }
        }
        Ok(std::mem::take(dead_pid_scratch))
    }

    fn recycle_dead_pid_scratch(&mut self, mut pids: Vec<i32>) {
        pids.clear();
        self.dead_pid_scratch = pids;
    }

    fn tracked_process_is_stale(
        &mut self,
        pid: i32,
        current_start_time: Option<u64>,
    ) -> crate::Result<Option<bool>> {
        let Some(state) = self.states.get_mut(&pid) else {
            return Ok(None);
        };
        let Some(pid) = crate::Pid::new(pid) else {
            return Ok(None);
        };
        let Some(alive) = state.tracking.poll_alive_checked(pid)? else {
            return Ok(None);
        };
        Ok(Some(
            !alive
                || state
                    .start_time
                    .zip(current_start_time)
                    .is_some_and(|(previous, current)| current != previous),
        ))
    }

    fn process_is_active(&mut self, pid: crate::Pid) -> crate::Result<bool> {
        let Some(state) = self.states.get_mut(&pid.get()) else {
            return Ok(false);
        };
        Ok(state.tracking.poll_alive_checked(pid)?.unwrap_or(false))
    }

    fn has_active_processes_except(&mut self, excluded_pid: i32) -> crate::Result<bool> {
        for (&pid, state) in &mut self.states {
            let Some(pid) = crate::Pid::new(pid).filter(|pid| pid.get() != excluded_pid) else {
                continue;
            };
            if state.tracking.poll_alive_checked(pid)?.unwrap_or(false) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn active_process_count(&mut self) -> crate::Result<usize> {
        let mut active = 0;
        for (&pid, state) in &mut self.states {
            let Some(pid) = crate::Pid::new(pid) else {
                continue;
            };
            active += usize::from(state.tracking.poll_alive_checked(pid)?.unwrap_or(false));
        }
        Ok(active)
    }

    fn capture_available_generation(&mut self, pid: i32) {
        let Ok(proc_pid) = u32::try_from(pid) else {
            return;
        };
        let image = read_process_image_identity(proc_pid).ok();
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

fn read_process_image_identity(pid: u32) -> io::Result<ProcessImageIdentity> {
    let exe = format!("/proc/{pid}/exe");
    let metadata = std::fs::metadata(exe)?;
    Ok(ProcessImageIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

fn read_process_comm(pid: u32) -> io::Result<Vec<u8>> {
    let mut comm = std::fs::read(format!("/proc/{pid}/comm"))?;
    while matches!(comm.last(), Some(b'\n' | b'\r')) {
        comm.pop();
    }
    Ok(comm)
}

enum PreparedEvent {
    Sample(PreparedSample),
    Record {
        timestamp_ns: u64,
        privilege: Priv,
        record: Record,
    },
}

impl PreparedEvent {
    fn detach_ring_storage(&mut self) {
        if let Self::Sample(PreparedSample {
            payload: PreparedSamplePayload::Ring(sample),
            ..
        }) = self
        {
            sample.detach();
        }
    }
}

struct PreparedSample {
    meta: PreparedSampleMeta,
    privilege: Priv,
    code_addr: Option<u64>,
    payload: PreparedSamplePayload,
}

enum PreparedSamplePayload {
    Owned {
        user_regs: Option<Vec<u64>>,
        user_stack: Option<Vec<u8>>,
        callchain_stack: Vec<StackFrame>,
    },
    Ring(RingSample),
}

#[derive(Clone, Copy)]
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

    fn prepare_event(&mut self, event_ref: EventRef) -> Self::Prepared {
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

    fn abort_round(&mut self) {
        self.sorter.abort_round();
    }

    fn has_queued_events(&self) -> bool {
        self.sorter.has_more()
    }

    fn detach_queued_events(&mut self) {
        self.sorter
            .visit_values_mut(PreparedEvent::detach_ring_storage);
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

impl Recorder {
    /// Attach to `pid` and start writing samples to `output`.
    ///
    /// Use [`AttachMode::StopWhileAttaching`] for a process that is already
    /// running. Use [`AttachMode::OnExec`] with
    /// [`process::SuspendedLaunchedProcess`] when launching a new process.
    ///
    /// # Errors
    ///
    /// Returns an error when the options are invalid, perf cannot attach, the
    /// process cannot be inspected, or the spool file cannot be created.
    pub fn attach<P: AsRef<Path>>(
        pid: crate::Pid,
        output: P,
        attach_mode: AttachMode,
        options: RecorderOptions,
    ) -> crate::Result<Self> {
        let raw_pid = pid.get_u32();
        let mut perf =
            open_perf_group(raw_pid, attach_mode, &options).map_err(crate::Error::target)?;
        let writer = PerfSpoolWriter::create(
            output,
            options.start_timestamp_us,
            options.sample_interval_us,
        )
        .map_err(|err| perf.resume_error_or(err))?;
        Self::finish_attach(pid, attach_mode, perf, writer)
    }

    /// Flush the spool and create an incremental reader that shares exact
    /// module images still held by this recorder's bounded image cache.
    ///
    /// A recorder can create one live tail. Continue polling and flushing the
    /// recorder, then call [`crate::Tail::poll`] to consume newly visible
    /// batches. Build the symbolizer through [`crate::Tail::symbolizer`] and
    /// update it before resolving each batch.
    ///
    /// # Errors
    ///
    /// Returns an invalid-input error after a tail has already been created.
    /// Returns an I/O error when the spool cannot be flushed, cloned, or read.
    pub fn tail(&mut self) -> crate::Result<crate::Tail> {
        let exact_images = self.exact_images.clone().ok_or_else(|| {
            crate::Error::message(
                crate::ErrorKind::InvalidInput,
                "this recorder already has a live tail",
            )
        })?;
        self.writer.flush()?;
        let file = self.writer.open_reader()?;
        let discarder = self.writer.open_discarder()?;
        let tail = crate::spool::Tail::from_recorder(file, discarder, exact_images)?;
        self.exact_images = None;
        Ok(tail)
    }
}

impl<W: std::io::Write> Recorder<W> {
    /// Attach to `pid` and write the spool to a caller-owned writer.
    ///
    /// The writer is used through static dispatch. Passing `&mut W` lets the
    /// caller recover the completed bytes after [`Self::finish`] consumes the
    /// recorder.
    ///
    /// # Errors
    ///
    /// Returns an error when the options are invalid, perf cannot attach, the
    /// process cannot be inspected, or the writer rejects the spool header.
    pub fn attach_with_writer(
        pid: crate::Pid,
        output: W,
        attach_mode: AttachMode,
        options: RecorderOptions,
    ) -> crate::Result<Self> {
        let raw_pid = pid.get_u32();
        let mut perf =
            open_perf_group(raw_pid, attach_mode, &options).map_err(crate::Error::target)?;
        let writer = PerfSpoolWriter::from_writer(
            output,
            options.start_timestamp_us,
            options.sample_interval_us,
        )
        .map_err(|err| perf.resume_error_or(err))?;
        Self::finish_attach(pid, attach_mode, perf, writer)
    }

    fn finish_attach(
        pid: crate::Pid,
        attach_mode: AttachMode,
        mut perf: perf_group::PerfGroup,
        mut writer: PerfSpoolWriter<W>,
    ) -> crate::Result<Self> {
        let raw_pid = pid.get_u32();
        let kernel_enabled = perf.kernel_enabled();
        let mut modules = ModuleTable::default();
        let exact_images = crate::native_module::ExactImageStore::default();
        let mut processes = ProcessTable {
            elf_sections: ElfSectionCache::publishing_exact_images_to(exact_images.clone()),
            ..ProcessTable::default()
        };
        if let Some(pid_i32) = i32_from_u32(raw_pid) {
            processes.ensure_tracked(pid_i32);
            processes.capture_available_generation(pid_i32);
        }
        let python_perf_support = process_has_python_perf_support(raw_pid, &mut processes);
        let registered_existing_maps = if matches!(
            attach_mode,
            AttachMode::Running | AttachMode::StopWhileAttaching
        ) {
            let maps = read_existing_maps(raw_pid)
                .map_err(|error| crate::Error::target(perf.resume_error_or(error)))?;
            register_existing_maps_snapshot(
                raw_pid,
                &maps,
                &mut modules,
                &mut processes,
                &mut writer,
            )
            .map_err(|error| crate::Error::from(perf.resume_error_or(error)))?
        } else {
            false
        };
        (|| {
            if let Some(pid_i32) =
                i32_from_u32(raw_pid).filter(|_| registered_existing_maps && python_perf_support)
            {
                mark_python_runtime_process(&mut processes, &mut writer, 0, pid_i32)?;
            }
            Ok::<_, io::Error>(())
        })()
        .map_err(|error| crate::Error::from(perf.resume_error_or(error)))?;

        let (minimum_ring_buffer_bytes, maximum_ring_buffer_bytes) =
            perf.ring_capacity_bytes_range().unwrap_or_default();
        let mut recorder = Self {
            perf,
            event_sorter: EventSorter::new(),
            writer,
            modules,
            processes,
            exact_images: Some(exact_images),
            stack_scratch: Vec::with_capacity(128),
            callchain_scratch: Vec::with_capacity(32),
            capture_pacing: CapturePacing::default(),
            summary: RecordingSummary {
                kernel_enabled,
                minimum_ring_buffer_bytes,
                maximum_ring_buffer_bytes,
                ..RecordingSummary::default()
            },
            disable_on_drop: true,
        };
        if matches!(
            attach_mode,
            AttachMode::Running | AttachMode::StopWhileAttaching
        ) {
            recorder.perf.enable().map_err(crate::Error::target)?;
        }
        Ok(recorder)
    }

    #[allow(clippy::cognitive_complexity)]
    fn drain_events(&mut self, mode: DrainMode) -> io::Result<()> {
        let open_new_perf_events = mode.opens_new_perf_events();
        let Self {
            perf,
            event_sorter,
            modules,
            processes,
            stack_scratch,
            callchain_scratch,
            capture_pacing,
            writer,
            summary,
            exact_images: _,
            disable_on_drop: _,
        } = self;
        let mut lifecycle_actions = Vec::new();
        let mut recovered_process_forks = Vec::new();
        let inherit_child_processes = perf.inherit_child_processes;
        let (mut result, recovery_timestamp_ns, mut recovered_lifecycle_gap) = {
            let ctx = EventContext {
                modules,
                processes,
                writer,
                summary,
                stack_scratch,
                callchain_scratch,
                lifecycle_actions: &mut lifecycle_actions,
                inherit_child_processes,
            };
            let mut sink = DrainSink {
                ctx,
                sorter: event_sorter,
                result: Ok(()),
                last_finished_timestamp_ns: 0,
            };
            let drain_result = match mode {
                DrainMode::Consume => perf.consume_events(&mut sink),
                DrainMode::Flush | DrainMode::Final => perf.flush_events(&mut sink),
            };
            if let Err(error) = drain_result {
                sink.result = Err(error);
            }
            // Forced drains read once after lifecycle replay so the same
            // syscall sweep includes final counters from retired members.
            if sink.result.is_ok()
                && !mode.forces_bookkeeping()
                && capture_pacing.should_read_lost_records(mode)
            {
                match perf.take_lost_records() {
                    Ok(lost) => {
                        sink.result =
                            record_observed_lost_events(sink.ctx.summary, capture_pacing, lost)
                    }
                    Err(err) => sink.result = Err(err),
                }
            }
            let run_recovery_sweep =
                sink.result.is_ok() && capture_pacing.should_run_recovery_sweep(mode);
            if run_recovery_sweep {
                // A /proc snapshot is current state, not state at the LOST
                // record timestamp. Drain every event already collected before
                // installing that snapshot so it cannot resolve older samples.
                sink.drain_sorter(true);
            }
            (
                sink.result,
                sink.last_finished_timestamp_ns,
                run_recovery_sweep,
            )
        };
        // Replay lifecycle mutations in event order. Only adjacent thread
        // forks can share one open transaction without crossing a reuse or
        // retirement boundary.
        if result.is_ok() {
            let mut action_index = 0;
            let mut thread_fork_batch = Vec::new();
            while action_index < lifecycle_actions.len() {
                if open_new_perf_events {
                    thread_fork_batch.clear();
                    while let Some(LifecycleAction::ThreadFork {
                        tid,
                        pid,
                        parent_tid,
                    }) = lifecycle_actions.get(action_index)
                    {
                        thread_fork_batch.push(ThreadFork {
                            tid: *tid,
                            owner_pid: *pid,
                            parent_tid: *parent_tid,
                        });
                        action_index += 1;
                    }
                    if !thread_fork_batch.is_empty() {
                        if let Err(error) = perf.open_forked_threads(&thread_fork_batch) {
                            result = Err(error);
                            break;
                        }
                        continue;
                    }
                }
                let action_result = match lifecycle_actions[action_index] {
                    LifecycleAction::ProcessRetire { pid } => perf.remove_process(pid),
                    LifecycleAction::ProcessFork { pid, parent_tid } if open_new_perf_events => {
                        perf.open_forked_processes(&[ProcessFork { pid, parent_tid }])
                    }
                    LifecycleAction::ThreadExit { tid, .. } => perf.remove_thread(tid),
                    LifecycleAction::ProcessFork { .. } | LifecycleAction::ThreadFork { .. } => {
                        Ok(())
                    }
                };
                action_index += 1;
                if let Err(err) = action_result {
                    result = Err(err);
                    break;
                }
            }
        }
        if result.is_ok() {
            let dead_processes = match processes.dead_or_reused_pids() {
                Ok(dead_processes) => dead_processes,
                Err(error) => {
                    result = Err(error.into());
                    Vec::new()
                }
            };
            let mut last_exit_by_pid = FxHashMap::<i32, u64>::default();
            if !dead_processes.is_empty() {
                for action in &lifecycle_actions {
                    let LifecycleAction::ThreadExit {
                        pid, timestamp_ns, ..
                    } = *action
                    else {
                        continue;
                    };
                    let Some(pid) = i32_from_u32(pid) else {
                        continue;
                    };
                    last_exit_by_pid
                        .entry(pid)
                        .and_modify(|latest| *latest = (*latest).max(timestamp_ns))
                        .or_insert(timestamp_ns);
                }
            }
            for &pid in &dead_processes {
                if let Ok(pid_u32) = u32::try_from(pid) {
                    if let Err(err) = perf.remove_process(pid_u32) {
                        result = Err(err);
                        break;
                    }
                }
                let timestamp_ns = last_exit_by_pid
                    .get(&pid)
                    .copied()
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
            processes.recycle_dead_pid_scratch(dead_processes);
        }
        // Retiring a member snapshots its final PERF_FORMAT_LOST value into
        // PerfGroup. Forced drains read here, after replay, so one counter
        // sweep includes both live and newly retired members.
        if result.is_ok() && mode.forces_bookkeeping() {
            match perf.take_lost_records() {
                Ok(lost) => {
                    result = record_observed_lost_events(summary, capture_pacing, lost);
                    if result.is_ok() {
                        recovered_lifecycle_gap |= capture_pacing.should_run_recovery_sweep(mode);
                    }
                }
                Err(err) => result = Err(err),
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
            for (child, parent) in crate::children::discover_descendant_edges_raw_for_roots(&roots)
            {
                if processes.is_tracked(child) {
                    continue;
                }
                match register_recovered_descendant(
                    child,
                    parent,
                    recovery_timestamp_ns,
                    modules,
                    processes,
                    writer,
                ) {
                    Ok(Some(process_fork)) => recovered_process_forks.push(process_fork),
                    Ok(None) => {}
                    Err(err) => {
                        result = Err(err);
                        break;
                    }
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
                    if !crate::error::is_target_gone_io(&err) {
                        result = Err(err);
                        break;
                    }
                }
            }
        }
        if result.is_ok() && recovered_lifecycle_gap {
            capture_pacing.complete_recovery_sweep();
        }
        refresh_recording_summary(summary, perf);
        result
    }

    /// Wait for data for at most `timeout`, then drain every ready event.
    ///
    /// # Errors
    ///
    /// Returns an error when polling perf, decoding events, unwinding a stack,
    /// or writing a spool record fails.
    pub fn poll(&mut self, timeout: std::time::Duration) -> crate::Result<PollSummary> {
        self.disable_on_drop = true;
        let samples = self.summary.samples;
        let lost_events = self.summary.lost_events;
        if !self.event_sorter.has_more() {
            self.perf.wait(timeout)?;
        }
        self.drain_events(DrainMode::Consume)?;
        Ok(PollSummary {
            samples: self.summary.samples.saturating_sub(samples),
            lost_events: self.summary.lost_events.saturating_sub(lost_events),
        })
    }

    /// Add another process to this recording.
    ///
    /// # Errors
    ///
    /// Returns an error when perf cannot attach, process metadata cannot be
    /// read, or the spool cannot record the new mappings.
    pub fn attach_process(
        &mut self,
        pid: crate::Pid,
        attach_mode: AttachMode,
    ) -> crate::Result<AttachOutcome> {
        let pid = pid.get_u32();
        if let Some(pid_i32) = i32_from_u32(pid) {
            let current_start_time = if self
                .processes
                .states
                .get(&pid_i32)
                .and_then(|state| state.start_time)
                .is_some()
            {
                Some(read_process_start_time(pid).map_err(crate::Error::target)?)
            } else {
                None
            };
            if let Some(stale) = self
                .processes
                .tracked_process_is_stale(pid_i32, current_start_time)?
            {
                // Reopen only after proving that the old process is gone or
                // that this numeric PID now identifies a new generation.
                if !stale {
                    return Ok(AttachOutcome::AlreadyAttached);
                }
                self.perf.remove_process(pid)?;
                cleanup_process(
                    pid_i32,
                    &mut self.modules,
                    &mut self.processes,
                    &mut self.writer,
                )?;
            }
        }
        let opened = match self.perf.open_process(pid, attach_mode) {
            Ok(opened) => opened,
            Err(error) if crate::error::is_target_gone_io(&error) => {
                return Ok(AttachOutcome::Exited)
            }
            Err(error) => return Err(error.into()),
        };
        if let Some(pid_i32) = i32_from_u32(pid) {
            self.processes.track_or_refresh(pid_i32)?;
            self.processes.capture_available_generation(pid_i32);
            let python_perf_support = process_has_python_perf_support(pid, &mut self.processes);
            let maps = match read_existing_maps(pid) {
                Ok(maps) => maps,
                Err(err) if crate::error::is_target_gone_io(&err) => {
                    return match self.rollback_open_process(pid, opened) {
                        Ok(()) => Ok(AttachOutcome::Exited),
                        Err(cleanup_error) => {
                            Err(crate::error::with_cleanup_error(err, cleanup_error).into())
                        }
                    };
                }
                Err(err) => {
                    return Err(self.rollback_open_process_error(pid, opened, err).into());
                }
            };
            match register_existing_maps_snapshot(
                pid,
                &maps,
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
                        return Err(self.rollback_open_process_error(pid, opened, err).into());
                    }
                }
                Ok(_) => {}
                Err(err) => {
                    return Err(self.rollback_open_process_error(pid, opened, err).into());
                }
            }
        }
        if matches!(
            attach_mode,
            AttachMode::Running | AttachMode::StopWhileAttaching
        ) {
            if let Err(err) = self.perf.enable() {
                return Err(self.rollback_open_process_error(pid, opened, err).into());
            }
        }
        refresh_recording_summary(&mut self.summary, &self.perf);
        self.disable_on_drop = true;
        Ok(AttachOutcome::Attached)
    }

    /// Discover newly-created threads for `pid` when needed.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::InvalidInput`](crate::ErrorKind::InvalidInput) when
    /// `pid` is not attached, or an I/O error when thread discovery fails.
    pub fn refresh_threads(&mut self, pid: crate::Pid) -> crate::Result<RefreshOutcome> {
        if !self.processes.is_tracked(pid.get()) {
            return Err(crate::Error::message(
                crate::ErrorKind::InvalidInput,
                format!("process {pid} is not attached"),
            ));
        }
        let refreshed = self.perf.refresh_threads(pid.get_u32())?;
        refresh_recording_summary(&mut self.summary, &self.perf);
        Ok(if refreshed {
            self.disable_on_drop = true;
            RefreshOutcome::Refreshed
        } else {
            RefreshOutcome::Exited
        })
    }

    /// Disable sampling for all attached processes.
    ///
    /// # Errors
    ///
    /// Returns the first perf-event disable failure.
    pub fn disable(&mut self) -> crate::Result<()> {
        self.perf.disable()?;
        self.disable_on_drop = false;
        Ok(())
    }

    /// Enable sampling for all attached processes.
    ///
    /// # Errors
    ///
    /// Returns the first perf-event enable or process-resume failure. When both
    /// fail, the enable failure remains primary and the resume failure is
    /// included as cleanup context.
    pub fn enable(&mut self) -> crate::Result<()> {
        self.disable_on_drop = true;
        Ok(self.perf.enable()?)
    }

    /// Drain all collected events, force loss bookkeeping and recovery, then
    /// flush the spool writer. Sampling and lifecycle discovery remain active.
    ///
    /// When loss has made lifecycle state uncertain, this call can perform an
    /// expensive reconciliation pass over tracked processes and `/proc`,
    /// discover descendants, rebuild module state, and open missing perf
    /// events before it flushes the writer.
    ///
    /// # Errors
    ///
    /// Returns an event-processing or writer error.
    pub fn flush(&mut self) -> crate::Result<()> {
        self.drain_events(DrainMode::Flush)?;
        Ok(self.writer.flush()?)
    }

    /// Return whether userspace has queued events or [`Self::poll`] observed a
    /// readable perf buffer.
    pub fn has_pending_events(&self) -> bool {
        self.event_sorter.has_more() || self.perf.has_pending_events()
    }

    /// Return a snapshot of the current counters.
    pub fn summary(&self) -> RecordingSummary {
        self.summary.clone()
    }

    /// Return whether `pid` is still believed to be alive.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when process state cannot be checked.
    pub fn process_is_active(&mut self, pid: crate::Pid) -> crate::Result<bool> {
        self.processes.process_is_active(pid)
    }

    /// Return whether any active process other than `pid` remains.
    ///
    /// # Errors
    ///
    /// Returns an error when process state cannot be inspected. Inspection
    /// failures are never treated as an alive or dead result.
    pub fn has_active_processes_except(&mut self, pid: crate::Pid) -> crate::Result<bool> {
        self.processes.has_active_processes_except(pid.get())
    }

    /// Return the number of processes still believed to be alive.
    ///
    /// # Errors
    ///
    /// Returns an error when any tracked process cannot be inspected.
    pub fn active_process_count(&mut self) -> crate::Result<usize> {
        self.processes.active_process_count()
    }

    /// Flush the spool file and return the final counters.
    ///
    /// # Errors
    ///
    /// Returns the first disable, drain, or flush error. Later failures are
    /// retained as cleanup context, and flushing is attempted in every case.
    pub fn finish(mut self) -> crate::Result<RecordingSummary> {
        let result = self.perf.disable();
        if result.is_ok() {
            self.disable_on_drop = false;
        }
        let result = crate::error::and_cleanup(result, self.drain_events(DrainMode::Final));
        crate::error::and_cleanup(result, self.writer.flush())?;
        Ok(std::mem::take(&mut self.summary))
    }

    fn rollback_open_process(
        &mut self,
        pid: u32,
        opened: perf_group::OpenTransaction,
    ) -> io::Result<()> {
        let resume_result = self.perf.resume_stopped_processes();
        self.perf.rollback_open(opened);
        let cleanup_result = if let Some(pid) = i32_from_u32(pid) {
            cleanup_process(
                pid,
                &mut self.modules,
                &mut self.processes,
                &mut self.writer,
            )
        } else {
            Ok(())
        };
        crate::error::and_cleanup(resume_result, cleanup_result)
    }

    fn rollback_open_process_error(
        &mut self,
        pid: u32,
        opened: perf_group::OpenTransaction,
        original_error: io::Error,
    ) -> io::Error {
        match self.rollback_open_process(pid, opened) {
            Ok(()) => original_error,
            Err(cleanup_error) => crate::error::with_cleanup_error(original_error, cleanup_error),
        }
    }
}

fn prepare_event(event_ref: EventRef, summary: &mut RecordingSummary) -> Option<PreparedEvent> {
    let event_timestamp_ns = event_ref.timestamp().unwrap_or(0);
    let (privilege, record) = event_ref.into_parts();
    match record {
        EventRecord::RingSample { sample, metadata } => {
            prepare_ring_sample(summary, sample, metadata, privilege)
        }
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
            let inheritance = ctx.processes.snapshot_for_fork(ppid);
            let current_start_time = read_process_start_time(fork.task.pid).ok();
            let reused_pid = ctx
                .processes
                .tracked_process_is_stale(pid, current_start_time)
                .map_err(io::Error::from)?
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
            let cloned = ctx.modules.clone_process_modules(ppid, pid, ctx.writer)?;
            ctx.processes
                .install_fork_inheritance(pid, current_start_time, inheritance);
            ctx.processes.apply_fork_module_update(pid, &cloned);
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
            let current_identity = read_process_image_identity(comm.task.pid).ok();
            let identity_changed = current_identity.as_ref().is_some_and(|identity| {
                ctx.processes
                    .states
                    .get(&pid)
                    .and_then(|state| state.image.as_ref())
                    .is_some_and(|previous| {
                        previous.device != identity.device || previous.inode != identity.inode
                    })
                    && read_process_comm(comm.task.pid).ok().as_deref()
                        == Some(comm.comm.as_bytes())
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
            ctx.processes.state_mut(pid).image = current_identity;
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
            ctx.summary.lost_events = checked_loss_sum(ctx.summary.lost_events, lost.lost_samples)?;
            Ok(())
        }
        _ => Ok(()),
    }
}

fn record_lost_events(summary: &mut RecordingSummary, lost: u64) -> io::Result<()> {
    if lost == 0 {
        return Ok(());
    }
    summary.lost_events = checked_loss_sum(summary.lost_events, lost)?;
    summary.lifecycle_gaps = summary
        .lifecycle_gaps
        .checked_add(1)
        .ok_or_else(|| invalid_data("perf lifecycle-gap overflow"))?;
    Ok(())
}

fn record_observed_lost_events(
    summary: &mut RecordingSummary,
    capture_pacing: &mut CapturePacing,
    lost: u64,
) -> io::Result<()> {
    let lifecycle_gaps_before = summary.lifecycle_gaps;
    record_lost_events(summary, lost)?;
    capture_pacing.observe_recovery_gap(summary.lifecycle_gaps != lifecycle_gaps_before);
    Ok(())
}

fn refresh_recording_summary(summary: &mut RecordingSummary, perf: &perf_group::PerfGroup) {
    summary.kernel_enabled &= perf.kernel_enabled();
    if let Some((minimum, maximum)) = perf.ring_capacity_bytes_range() {
        summary.minimum_ring_buffer_bytes = minimum;
        summary.maximum_ring_buffer_bytes = maximum;
    }
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
    modules.deactivate_process_modules(pid, writer, |module_id| {
        processes.elf_sections.remove(module_id);
    })?;
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
        Err(err) if crate::error::is_target_gone_io(&err) => {
            processes.forget_generation(pid_i32);
            return Ok(false);
        }
        Err(err) => return Err(err),
    };
    // /proc/<tgid>/exe can disappear after the thread-group leader exits even
    // while sibling threads remain alive. Start time and the maps snapshot,
    // not the exe symlink alone, determine whether this generation survives.
    let current_identity = read_process_image_identity(pid).ok();

    let maps = match std::fs::read_to_string(format!("/proc/{pid}/maps")) {
        Ok(maps) => maps,
        Err(err) if crate::error::is_target_gone_io(&err) => {
            processes.forget_generation(pid_i32);
            return Ok(false);
        }
        Err(err) => return Err(err),
    };
    let snapshot: Vec<_> = executable_modules_from_maps(pid, &maps).collect();
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
        Err(err) => Err(err),
    }
}

fn register_recovered_descendant<W: std::io::Write>(
    child: i32,
    parent: i32,
    timestamp_ns: u64,
    modules: &mut ModuleTable,
    processes: &mut ProcessTable,
    writer: &mut PerfSpoolWriter<W>,
) -> io::Result<Option<RecoveredProcessFork>> {
    let Ok(child_pid) = u32::try_from(child) else {
        return Ok(None);
    };
    let python_perf_support = process_has_python_perf_support(child_pid, processes);
    let maps = match read_existing_maps(child_pid) {
        Ok(maps) => maps,
        Err(err) if crate::error::is_target_gone_io(&err) => return Ok(None),
        Err(err) => return Err(err),
    };
    match register_existing_maps_snapshot(child_pid, &maps, modules, processes, writer) {
        Ok(true) if python_perf_support => {
            mark_python_runtime_process(processes, writer, timestamp_ns, child)?;
        }
        Ok(_) => {}
        Err(err) => return Err(err),
    }

    processes.ensure_tracked(child);
    processes.capture_available_generation(child);
    Ok(u32::try_from(parent)
        .ok()
        .map(|parent_pid| RecoveredProcessFork {
            pid: child_pid,
            parent_pid,
        }))
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
    summary: &mut RecordingSummary,
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
        payload: PreparedSamplePayload::Owned {
            user_regs: user_regs
                .and_then(|(regs, abi)| (abi == SampleRegsAbi::_64).then_some(regs)),
            user_stack,
            callchain_stack: call_chain
                .as_deref()
                .map_or(SampleCallChain::None, SampleCallChain::Owned)
                .to_stack_frames(),
        },
    }))
}

fn prepare_ring_sample(
    summary: &mut RecordingSummary,
    sample: RingSample,
    metadata: perf_event::SampleMetadata,
    privilege: Priv,
) -> Option<PreparedEvent> {
    let meta = prepare_sample_meta(
        summary,
        metadata.task.map(|task| (task.pid, task.tid)),
        metadata.time,
    )?;
    Some(PreparedEvent::Sample(PreparedSample {
        meta,
        privilege,
        code_addr: metadata.code_addr.map(|(ip, _)| ip),
        payload: PreparedSamplePayload::Ring(sample),
    }))
}

#[cfg(test)]
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

enum PreparedCallChain<'a> {
    Frames(&'a [StackFrame]),
    Raw(SampleCallChain<'a>),
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

#[cfg(test)]
impl<'a> SampleView<'a> {
    fn stack_input(self) -> StackInput<'a> {
        StackInput {
            code_addr: self.code_addr,
            user_regs: self.user_regs,
            user_stack: self.user_stack,
        }
    }
}

#[cfg(test)]
fn prepare_sample_view(
    summary: &mut RecordingSummary,
    sample: SampleView<'_>,
    privilege: Priv,
) -> Option<PreparedEvent> {
    let meta = prepare_sample_meta(summary, sample.task, sample.timestamp_ns)?;

    Some(PreparedEvent::Sample(PreparedSample {
        meta,
        privilege,
        code_addr: sample.code_addr,
        payload: PreparedSamplePayload::Owned {
            user_regs: sample.user_regs.map(<[u64]>::to_vec),
            user_stack: sample.user_stack.map(<[u8]>::to_vec),
            callchain_stack: sample.call_chain.to_stack_frames(),
        },
    }))
}

fn prepare_sample_meta(
    summary: &mut RecordingSummary,
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
    let PreparedSample {
        meta,
        privilege,
        code_addr,
        payload,
    } = sample;
    let (user_regs, user_stack, callchain_stack) = match payload {
        PreparedSamplePayload::Ring(ring_sample) => {
            return ring_sample
                .with_sample(|view| {
                    record_prepared_sample_input(
                        ctx,
                        meta,
                        privilege,
                        StackInput {
                            code_addr,
                            user_regs: view.user_regs,
                            user_stack: view.user_stack,
                        },
                        PreparedCallChain::Raw(
                            view.call_chain
                                .map_or(SampleCallChain::None, SampleCallChain::Borrowed),
                        ),
                    )
                })
                .unwrap_or_else(|| {
                    Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "held ring sample no longer parses",
                    ))
                });
        }
        PreparedSamplePayload::Owned {
            user_regs,
            user_stack,
            callchain_stack,
        } => (user_regs, user_stack, callchain_stack),
    };
    record_prepared_sample_input(
        ctx,
        meta,
        privilege,
        StackInput {
            code_addr,
            user_regs: user_regs.as_deref(),
            user_stack: user_stack.as_deref(),
        },
        PreparedCallChain::Frames(&callchain_stack),
    )
}

fn record_prepared_sample_input<W: std::io::Write>(
    ctx: &mut EventContext<'_, W>,
    meta: PreparedSampleMeta,
    privilege: Priv,
    input: StackInput<'_>,
    callchain: PreparedCallChain<'_>,
) -> io::Result<()> {
    let pid = meta.pid;
    refresh_maps_for_uncovered_user_pc(ctx, meta, privilege, input)?;
    let callchain_stack = match callchain {
        PreparedCallChain::Frames(frames) => frames,
        PreparedCallChain::Raw(call_chain) => {
            ctx.callchain_scratch.clear();
            push_sample_callchain(call_chain, ctx.callchain_scratch);
            &*ctx.callchain_scratch
        }
    };
    let unwinder = ctx
        .processes
        .state_mut(pid)
        .unwinder
        .get_or_insert_default();
    build_sample_stack::<ConvertRegsNative>(
        input,
        privilege,
        unwinder,
        ctx.stack_scratch,
        callchain_stack,
        ctx.summary,
    );
    let stack_id = {
        let modules = &mut *ctx.modules;
        let summary = &mut *ctx.summary;
        ctx.writer.write_sample_frames(
            meta.timestamp_ns,
            pid,
            meta.tid,
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
    meta: PreparedSampleMeta,
    privilege: Priv,
    input: StackInput<'_>,
) -> io::Result<()> {
    let Some(pid) = u32::try_from(meta.pid).ok() else {
        return Ok(());
    };
    let register_pc = input
        .user_regs
        .and_then(ConvertRegsNative::convert_regs)
        .map(|(pc, _, _)| pc);
    let sampled_user_pc = matches!(privilege, Priv::User)
        .then_some(input.code_addr)
        .flatten();
    let Some(pc) = register_pc.or(sampled_user_pc) else {
        return Ok(());
    };
    if ctx.modules.covers_user_pc(meta.pid, pc) {
        return Ok(());
    }
    if !ctx
        .processes
        .state_mut(meta.pid)
        .unwinder
        .get_or_insert_default()
        .should_refresh_for_uncovered_pc(pc)
    {
        return Ok(());
    }
    let maps = match read_existing_maps(pid) {
        Ok(maps) => maps,
        Err(err) if crate::error::is_target_gone_io(&err) => return Ok(()),
        Err(err) => return Err(err),
    };
    match register_existing_maps_snapshot(pid, &maps, ctx.modules, ctx.processes, ctx.writer) {
        Ok(true) if process_has_python_perf_support(pid, ctx.processes) => {
            mark_python_runtime_process(ctx.processes, ctx.writer, meta.timestamp_ns, meta.pid)
        }
        Ok(_) => Ok(()),
        Err(err) => Err(err),
    }
}

fn bump(counter: &mut u64) {
    *counter = counter.saturating_add(1);
}

fn record_unwind_error(
    summary: &mut RecordingSummary,
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

fn fallback_kind(reason: FramePointerFallbackReason) -> UnwindFallbackKind {
    match reason {
        FramePointerFallbackReason::NoModule => UnwindFallbackKind::NoModule,
        // Other Framehop format features can be enabled by another crate in the
        // dependency graph even though this Linux recorder cannot produce them.
        #[allow(unreachable_patterns)]
        FramePointerFallbackReason::UnwindInfo(error) => match error {
            UnwinderError::NoModuleUnwindData => UnwindFallbackKind::NoModuleUnwindData,
            UnwinderError::EhFrameHdrCouldNotFindAddress => UnwindFallbackKind::EhFrameHdrLookup,
            UnwinderError::DwarfCfiIndexCouldNotFindAddress => {
                UnwindFallbackKind::DwarfCfiIndexLookup
            }
            UnwinderError::Dwarf(error) => match error {
                DwarfUnwinderError::FdeFromOffsetFailed(_) => UnwindFallbackKind::DwarfFdeRead,
                DwarfUnwinderError::UnwindInfoForAddressFailed(_) => {
                    UnwindFallbackKind::DwarfUnwindInfo
                }
                DwarfUnwinderError::StackPointerMovedBackwards => {
                    UnwindFallbackKind::DwarfStackPointerMovedBackwards
                }
                DwarfUnwinderError::DidNotAdvance => UnwindFallbackKind::DwarfDidNotAdvance,
                DwarfUnwinderError::CouldNotRecoverCfa => {
                    UnwindFallbackKind::DwarfCouldNotRecoverCfa
                }
                DwarfUnwinderError::CouldNotRecoverReturnAddress => {
                    UnwindFallbackKind::DwarfCouldNotRecoverReturnAddress
                }
                DwarfUnwinderError::CouldNotRecoverFramePointer => {
                    UnwindFallbackKind::DwarfCouldNotRecoverFramePointer
                }
            },
            _ => UnwindFallbackKind::OtherUnwindFormat,
        },
    }
}

fn is_kernel_mode(privilege: Priv) -> bool {
    matches!(privilege, Priv::Kernel | Priv::GuestKernel)
}

fn open_perf_group(
    pid: u32,
    attach_mode: AttachMode,
    options: &RecorderOptions,
) -> io::Result<perf_group::PerfGroup> {
    let regs_mask = ConvertRegsNative::regs_mask();
    perf_group::PerfGroup::open(
        pid,
        attach_mode,
        PerfGroupOptions {
            frequency: options.sample_rate.resolve()?,
            stack_size: options.stack_size,
            ring_stacks: options.ring_stacks,
            event_source: EventSource::HwCpuCycles,
            regs_mask,
            include_kernel: options.include_kernel,
            inherit_child_processes: options.inherit_child_processes,
        },
    )
}

#[cfg(test)]
fn get_sample_stack<C: ConvertRegs<UnwindRegs = <NativeUnwinder as Unwinder>::UnwindRegs>>(
    sample: SampleView<'_>,
    privilege: Priv,
    process_unwinder: &mut ProcessUnwinder,
    stack: &mut Vec<StackFrame>,
    callchain_stack: &mut Vec<StackFrame>,
    summary: &mut RecordingSummary,
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
    summary: &mut RecordingSummary,
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
                    match frames.next_with_details() {
                        Ok(None) => break,
                        Ok(Some(frame)) => {
                            if let Some(reason) = frame.fallback_reason() {
                                summary.unwind_fallbacks.record(fallback_kind(reason));
                            }
                            match frame.address() {
                                FrameAddress::InstructionPointer(address) => stack
                                    .push(StackFrame::InstructionPointer(address, StackMode::User)),
                                FrameAddress::ReturnAddress(address) => stack.push(
                                    StackFrame::ReturnAddress(address.into(), StackMode::User),
                                ),
                            }
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
    summary: &mut RecordingSummary,
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
    use std::cell::Cell;
    use std::rc::Rc;

    use super::*;
    use crate::test_support::{SleepChild, TempDir};
    use perf_event_open::sample::record::comm::Comm;
    use perf_event_open::sample::record::lost::{LostRecords, LostSamples};
    use perf_event_open::sample::record::task::{Exit, Fork};
    use perf_event_open::sample::record::Task;

    #[test]
    fn capture_pacing_rate_limits_counter_reads_and_recovery_sweeps() {
        let now = Instant::now();
        let mut pacing = CapturePacing {
            last_lost_read: Some(now),
            last_recovery_sweep: Some(now),
            recovery_sweep_pending: false,
        };

        assert!(!pacing.should_read_lost_records(DrainMode::Consume));
        pacing.observe_recovery_gap(true);
        assert!(!pacing.should_run_recovery_sweep(DrainMode::Consume));
        assert!(pacing.recovery_sweep_pending);

        pacing.last_lost_read = Some(now - LOST_RECORD_READ_INTERVAL);
        pacing.last_recovery_sweep = Some(now - RECOVERY_SWEEP_INTERVAL);
        assert!(pacing.should_read_lost_records(DrainMode::Consume));
        pacing.observe_recovery_gap(false);
        assert!(pacing.should_run_recovery_sweep(DrainMode::Consume));
        assert!(pacing.recovery_sweep_pending);
        pacing.complete_recovery_sweep();
        assert!(!pacing.recovery_sweep_pending);
    }

    #[test]
    fn capture_flush_forces_pending_bookkeeping() {
        let now = Instant::now();
        let mut pacing = CapturePacing {
            last_lost_read: Some(now),
            last_recovery_sweep: Some(now),
            recovery_sweep_pending: true,
        };

        assert!(pacing.should_read_lost_records(DrainMode::Flush));
        pacing.observe_recovery_gap(false);
        assert!(pacing.should_run_recovery_sweep(DrainMode::Flush));
        assert!(DrainMode::Flush.opens_new_perf_events());
        assert!(!DrainMode::Final.opens_new_perf_events());
        assert!(pacing.recovery_sweep_pending);
        pacing.complete_recovery_sweep();
        assert!(!pacing.recovery_sweep_pending);
    }

    #[test]
    fn forced_recount_schedules_recovery_for_loss_retired_during_replay() {
        let now = Instant::now();
        let mut pacing = CapturePacing {
            last_lost_read: Some(now),
            last_recovery_sweep: Some(now),
            recovery_sweep_pending: false,
        };
        let mut summary = RecordingSummary::default();

        record_observed_lost_events(&mut summary, &mut pacing, 0).unwrap();
        assert!(!pacing.should_run_recovery_sweep(DrainMode::Final));

        record_observed_lost_events(&mut summary, &mut pacing, 7).unwrap();
        assert_eq!(summary.lost_events, 7);
        assert_eq!(summary.lifecycle_gaps, 1);
        assert!(pacing.should_run_recovery_sweep(DrainMode::Final));
    }

    #[test]
    fn failed_recovery_attempt_keeps_the_gap_pending() {
        let mut pacing = CapturePacing::default();
        pacing.observe_recovery_gap(true);

        assert!(pacing.should_run_recovery_sweep(DrainMode::Consume));
        assert!(pacing.recovery_sweep_pending);
        assert!(!pacing.should_run_recovery_sweep(DrainMode::Consume));
        assert!(pacing.should_run_recovery_sweep(DrainMode::Flush));
        assert!(pacing.recovery_sweep_pending);
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
        assert!(processes.dead_or_reused_pids().unwrap().is_empty());
        assert_eq!(
            processes.tracked_process_is_stale(pid, Some(3)).unwrap(),
            None
        );
        assert!(!processes
            .process_is_active(crate::Pid::new(pid).unwrap())
            .unwrap());
        assert!(!processes.has_active_processes_except(0).unwrap());
        assert_eq!(processes.active_process_count().unwrap(), 0);
    }

    #[test]
    fn tracked_process_queries_follow_liveness() {
        let live_pid = i32::try_from(std::process::id()).expect("current PID fits in i32");
        let missing_pid = i32::MAX;
        let mut processes = ProcessTable::default();

        processes.track_or_refresh(live_pid).unwrap();
        processes.track_or_refresh(live_pid).unwrap();
        processes.track_or_refresh(missing_pid).unwrap();
        processes.track_or_refresh(missing_pid).unwrap();

        assert!(processes.is_tracked(live_pid));
        assert!(processes.is_tracked(missing_pid));
        let mut tracked = processes.tracked_pids();
        tracked.sort_unstable();
        assert_eq!(tracked, [live_pid, missing_pid]);
        assert_eq!(
            processes.tracked_process_is_stale(live_pid, None).unwrap(),
            Some(false)
        );
        assert_eq!(
            processes
                .tracked_process_is_stale(missing_pid, None)
                .unwrap(),
            Some(true)
        );
        assert!(processes
            .process_is_active(crate::Pid::new(live_pid).unwrap())
            .unwrap());
        assert!(!processes
            .process_is_active(crate::Pid::new(missing_pid).unwrap())
            .unwrap());
        assert!(processes.has_active_processes_except(missing_pid).unwrap());
        assert!(!processes.has_active_processes_except(live_pid).unwrap());
        assert_eq!(processes.active_process_count().unwrap(), 1);
        assert_eq!(processes.dead_or_reused_pids().unwrap(), [missing_pid]);
    }

    #[test]
    fn batched_pidfd_poll_associates_exit_with_the_right_process() {
        let mut exited = SleepChild::spawn();
        let live = SleepChild::spawn();
        let exited_pid = exited.pid_i32();
        let live_pid = live.pid_i32();
        let mut processes = ProcessTable::default();
        processes.track_or_refresh(exited_pid).unwrap();
        processes.track_or_refresh(live_pid).unwrap();

        crate::state::kill_process(crate::Pid::new(exited_pid).unwrap()).unwrap();
        exited
            .wait_timeout(Duration::from_secs(2))
            .unwrap()
            .expect("child exits");

        assert_eq!(processes.dead_or_reused_pids().unwrap(), [exited_pid]);
        assert!(processes
            .process_is_active(crate::Pid::new(live_pid).unwrap())
            .unwrap());
    }

    #[test]
    fn reopening_the_same_process_is_idempotent() {
        let child = SleepChild::spawn();
        let temp = TempDir::new("duplicate-open");
        let mut recorder = match Recorder::attach(
            crate::Pid::try_from(child.pid_u32()).expect("child pid is valid"),
            temp.path().join("profile.stackpulse"),
            AttachMode::StopWhileAttaching,
            RecorderOptions::new(SampleRate::hz(1).expect("one hertz is valid")),
        ) {
            Ok(recorder) => recorder,
            Err(err)
                if matches!(
                    err.kind(),
                    crate::ErrorKind::Permission | crate::ErrorKind::Unsupported
                ) || matches!(err.raw_os_error(), Some(libc::ENOSYS | libc::EOPNOTSUPP)) =>
            {
                return;
            }
            Err(err) => panic!("attach recorder: {err}"),
        };
        let before = recorder.perf.resource_counts();

        recorder
            .attach_process(
                crate::Pid::try_from(child.pid_u32()).expect("child pid is valid"),
                AttachMode::StopWhileAttaching,
            )
            .expect("repeat process attachment");

        assert_eq!(recorder.perf.resource_counts(), before);

        let mut tail = recorder.tail().expect("create live tail");
        assert!(tail
            .poll()
            .expect("poll initial tail batch")
            .stacks()
            .next()
            .is_none());
        let error = recorder
            .tail()
            .expect_err("a recorder creates one live tail");
        assert_eq!(error.kind(), crate::ErrorKind::InvalidInput);
    }

    #[test]
    fn leader_exit_retires_thread_without_deactivating_process_modules() {
        let pid = std::process::id();
        let pid_i32 = i32::try_from(pid).unwrap();
        let mut modules = ModuleTable::default();
        let mut processes = ProcessTable::default();
        let mut writer = PerfSpoolWriter::from_writer(Vec::new(), 0, 0).unwrap();
        let mut summary = RecordingSummary::default();
        let mut stack_scratch = Vec::new();
        let mut callchain_scratch = Vec::new();
        let mut lifecycle_actions = Vec::new();
        let mut module = test_module(0x1000, 0x2000);
        module.set_pid(crate::Pid::new(pid_i32).unwrap());
        modules.intern_module(module, &mut writer).unwrap();

        {
            let mut ctx = EventContext {
                modules: &mut modules,
                processes: &mut processes,
                writer: &mut writer,
                summary: &mut summary,
                stack_scratch: &mut stack_scratch,
                callchain_scratch: &mut callchain_scratch,
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
        let mut summary = RecordingSummary::default();
        let mut stack_scratch = Vec::new();
        let mut callchain_scratch = Vec::new();
        let mut lifecycle_actions = Vec::new();
        let mut ctx = EventContext {
            modules: &mut modules,
            processes: &mut processes,
            writer: &mut writer,
            summary: &mut summary,
            stack_scratch: &mut stack_scratch,
            callchain_scratch: &mut callchain_scratch,
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
        let mut summary = RecordingSummary::default();
        let mut stack_scratch = Vec::new();
        let mut callchain_scratch = Vec::new();
        let mut lifecycle_actions = Vec::new();
        let mut module = test_module(0x1000, 0x2000);
        module.set_pid(crate::Pid::new(pid).unwrap());
        modules.intern_module(module, &mut writer).unwrap();

        let mut ctx = EventContext {
            modules: &mut modules,
            processes: &mut processes,
            writer: &mut writer,
            summary: &mut summary,
            stack_scratch: &mut stack_scratch,
            callchain_scratch: &mut callchain_scratch,
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
        let mut summary = RecordingSummary::default();

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
        assert_eq!(executable_modules_from_maps(42, "").count(), 0);
        assert_eq!(
            executable_modules_from_maps(42, "1000-2000 r-xp 00000000 00:00 0\n").count(),
            0
        );
        assert_eq!(
            executable_modules_from_maps(42, "1000-2000 r-xp 00000000 08:01 42 /tmp/lib.so\n")
                .count(),
            1
        );
    }

    #[test]
    fn unchanged_process_reconciliation_preserves_module_generation() {
        let pid = std::process::id();
        let pid_i32 = i32::try_from(pid).unwrap();
        let maps = std::fs::read_to_string(format!("/proc/{pid}/maps")).unwrap();
        let snapshot: Vec<_> = executable_modules_from_maps(pid, &maps).collect();
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
        state.image = Some(read_process_image_identity(pid).unwrap());
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
        let identity = read_process_image_identity(pid_u32).unwrap();
        let current_comm = read_process_comm(pid_u32).unwrap();
        let mut modules = ModuleTable::default();
        let mut processes = ProcessTable::default();
        processes.state_mut(pid).image = Some(identity);
        let mut writer = PerfSpoolWriter::from_writer(Vec::new(), 0, 0).unwrap();
        let mut summary = RecordingSummary::default();
        let mut stack_scratch = Vec::new();
        let mut callchain_scratch = Vec::new();
        let mut lifecycle_actions = Vec::new();
        let mut module = test_module(0x1000, 0x2000);
        module.set_pid(crate::Pid::new(pid).unwrap());
        let module_id = modules.intern_module(module, &mut writer).unwrap();

        let mut ctx = EventContext {
            modules: &mut modules,
            processes: &mut processes,
            writer: &mut writer,
            summary: &mut summary,
            stack_scratch: &mut stack_scratch,
            callchain_scratch: &mut callchain_scratch,
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
        let current_comm = read_process_comm(child_pid_u32).unwrap();
        let mut modules = ModuleTable::default();
        let mut processes = ProcessTable::default();
        processes.state_mut(parent_pid).image = Some(inherited_identity);
        let mut writer = PerfSpoolWriter::from_writer(Vec::new(), 0, 0).unwrap();
        let mut summary = RecordingSummary::default();
        let mut stack_scratch = Vec::new();
        let mut callchain_scratch = Vec::new();
        let mut lifecycle_actions = Vec::new();
        let mut module = test_module(0x1000, 0x2000);
        module.set_pid(crate::Pid::new(parent_pid).unwrap());
        modules.intern_module(module, &mut writer).unwrap();

        let mut ctx = EventContext {
            modules: &mut modules,
            processes: &mut processes,
            writer: &mut writer,
            summary: &mut summary,
            stack_scratch: &mut stack_scratch,
            callchain_scratch: &mut callchain_scratch,
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
        let mut summary = RecordingSummary::default();
        let mut stack_scratch = Vec::new();
        let mut callchain_scratch = Vec::new();
        let mut lifecycle_actions = Vec::new();
        let mut ctx = EventContext {
            modules: &mut modules,
            processes: &mut processes,
            writer: &mut writer,
            summary: &mut summary,
            stack_scratch: &mut stack_scratch,
            callchain_scratch: &mut callchain_scratch,
            lifecycle_actions: &mut lifecycle_actions,
            inherit_child_processes: false,
        };
        refresh_maps_for_uncovered_user_pc(
            &mut ctx,
            PreparedSampleMeta {
                timestamp_ns: 0,
                pid,
                tid: u64::from(pid_u32),
            },
            Priv::User,
            StackInput {
                code_addr: Some(pc),
                user_regs: None,
                user_stack: None,
            },
        )
        .unwrap();

        assert!(ctx.modules.covers_user_pc(pid, pc));
    }

    struct SwitchWriter {
        fail: Rc<Cell<bool>>,
    }

    impl io::Write for SwitchWriter {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            if self.fail.get() {
                Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "synthetic missing spool sink",
                ))
            } else {
                Ok(buffer.len())
            }
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[derive(Default)]
    struct HeaderOnlyWriter {
        writes: usize,
    }

    impl io::Write for HeaderOnlyWriter {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            if self.writes >= 3 {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "synthetic missing spool sink",
                ));
            }
            self.writes += 1;
            Ok(buffer.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn attach_does_not_classify_writer_not_found_as_target_gone() {
        let result = Recorder::attach_with_writer(
            crate::Pid::try_from(std::process::id()).expect("current PID is valid"),
            HeaderOnlyWriter::default(),
            AttachMode::Running,
            RecorderOptions::new(SampleRate::hz(1).expect("one hertz is valid")),
        );
        let error = match result {
            Err(error)
                if matches!(
                    error.kind(),
                    crate::ErrorKind::Permission | crate::ErrorKind::Unsupported
                ) || matches!(error.raw_os_error(), Some(libc::ENOSYS | libc::EOPNOTSUPP)) =>
            {
                return
            }
            Err(error) => error,
            Ok(_) => panic!("writer should reject the first module record"),
        };

        assert_eq!(error.kind(), crate::ErrorKind::Io);
        assert_eq!(error.to_string(), "synthetic missing spool sink");
    }

    #[test]
    fn map_refresh_does_not_mistake_writer_not_found_for_process_exit() {
        let pid_u32 = std::process::id();
        let pid = i32::try_from(pid_u32).unwrap();
        let pc = map_refresh_does_not_mistake_writer_not_found_for_process_exit as *const () as u64;
        let fail = Rc::new(Cell::new(false));
        let mut writer = PerfSpoolWriter::from_writer(
            SwitchWriter {
                fail: Rc::clone(&fail),
            },
            0,
            0,
        )
        .unwrap();
        fail.set(true);
        let mut modules = ModuleTable::default();
        let mut processes = ProcessTable::default();
        let mut summary = RecordingSummary::default();
        let mut stack_scratch = Vec::new();
        let mut callchain_scratch = Vec::new();
        let mut lifecycle_actions = Vec::new();
        let mut ctx = EventContext {
            modules: &mut modules,
            processes: &mut processes,
            writer: &mut writer,
            summary: &mut summary,
            stack_scratch: &mut stack_scratch,
            callchain_scratch: &mut callchain_scratch,
            lifecycle_actions: &mut lifecycle_actions,
            inherit_child_processes: false,
        };
        let error = refresh_maps_for_uncovered_user_pc(
            &mut ctx,
            PreparedSampleMeta {
                timestamp_ns: 0,
                pid,
                tid: u64::from(pid_u32),
            },
            Priv::User,
            StackInput {
                code_addr: Some(pc),
                user_regs: None,
                user_stack: None,
            },
        )
        .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::NotFound);
        assert_eq!(error.to_string(), "synthetic missing spool sink");
    }

    #[test]
    fn hypervisor_sample_ip_does_not_refresh_user_maps() {
        let pid_u32 = std::process::id();
        let pid = i32::try_from(pid_u32).unwrap();
        let pc = hypervisor_sample_ip_does_not_refresh_user_maps as *const () as u64;
        let mut modules = ModuleTable::default();
        let mut processes = ProcessTable::default();
        let mut writer = PerfSpoolWriter::from_writer(Vec::new(), 0, 0).unwrap();
        let mut summary = RecordingSummary::default();
        let mut stack_scratch = Vec::new();
        let mut callchain_scratch = Vec::new();
        let mut lifecycle_actions = Vec::new();
        let mut ctx = EventContext {
            modules: &mut modules,
            processes: &mut processes,
            writer: &mut writer,
            summary: &mut summary,
            stack_scratch: &mut stack_scratch,
            callchain_scratch: &mut callchain_scratch,
            lifecycle_actions: &mut lifecycle_actions,
            inherit_child_processes: false,
        };
        refresh_maps_for_uncovered_user_pc(
            &mut ctx,
            PreparedSampleMeta {
                timestamp_ns: 0,
                pid,
                tid: u64::from(pid_u32),
            },
            Priv::Hv,
            StackInput {
                code_addr: Some(pc),
                user_regs: None,
                user_stack: None,
            },
        )
        .unwrap();

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
            owner: ModuleOwner::Process(crate::Pid::new(7).unwrap()),
            start,
            end,
            file_offset: 0,
            inode: 0,
            device_major: 0,
            device_minor: 0,
            inode_generation: 0,
            path: "/tmp/libtest.so".into(),
        }
    }

    #[test]
    fn sample_prepare_defers_unwind_until_finish() {
        let mut modules = ModuleTable::default();
        let mut processes = ProcessTable::default();
        let mut writer = PerfSpoolWriter::from_writer(Vec::new(), 0, 0).expect("spool writer");
        let mut summary = RecordingSummary::default();
        let mut stack_scratch = Vec::new();
        let mut callchain_scratch = Vec::new();
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
                .count(SampleErrorKind::NativeRegisterCapture),
            0
        );

        let mut ctx = EventContext {
            modules: &mut modules,
            processes: &mut processes,
            writer: &mut writer,
            summary: &mut summary,
            stack_scratch: &mut stack_scratch,
            callchain_scratch: &mut callchain_scratch,
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
                .count(SampleErrorKind::NativeRegisterCapture),
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
            let mut summary = RecordingSummary::default();
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
        let mut summary = RecordingSummary::default();

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
        let mut summary = RecordingSummary::default();

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
    fn bench_perf_ring_lifecycle_refills_wrapped_rings() {
        let fixture = live_perf_sample_bench_fixture();
        for ring_count in [1, 4, 64] {
            let consumed = bench_perf_ring_record_lifecycle(&fixture, ring_count, 2)
                .expect("consume synthetic mmap ring records");
            assert_eq!(consumed, fixture.sample_count() * 2);
        }
        for ring_count in [0, fixture.sample_count() + 1] {
            assert_eq!(
                bench_perf_ring_record_lifecycle(&fixture, ring_count, 1)
                    .expect_err("reject invalid ring count")
                    .kind(),
                io::ErrorKind::InvalidInput
            );
        }
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
        let mut summary = RecordingSummary::default();

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
                .count(SampleErrorKind::NativeStackTruncated),
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
        let mut summary = RecordingSummary::default();

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
        let mut summary = RecordingSummary::default();

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
                .count(SampleErrorKind::NativeUserRegistersMissing),
            1
        );
        assert_eq!(
            summary.error_stats.count(SampleErrorKind::NativeStackRead),
            1
        );
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
        let mut summary = RecordingSummary::default();

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
        let mut summary = RecordingSummary::default();

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
        assert_eq!(
            summary.error_stats.count(SampleErrorKind::NativeStackRead),
            1
        );
        assert_eq!(
            summary
                .error_stats
                .count(SampleErrorKind::NativeRegisterCapture),
            0
        );
        assert_eq!(
            summary
                .error_stats
                .count(SampleErrorKind::NativeStackTruncated),
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

        let reader = crate::spool::Snapshot::open(&path).unwrap();
        let _ = std::fs::remove_file(path);
        assert!(processes.states[&8].python_runtime);
        let [runtime] = reader.python_runtime_records() else {
            panic!("expected one Python-runtime record");
        };
        assert_eq!(runtime.timestamp_ns, 456);
        assert_eq!(runtime.process_id.get(), 8);
        assert!(runtime.is_python_runtime);
    }
}
