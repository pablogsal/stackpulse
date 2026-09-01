use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Debug;
use std::os::unix::io::RawFd;
use std::time::Duration;
use std::{fs, io};

use mio::unix::SourceFd;
use mio::{Events, Interest, Poll, Token};
use rustc_hash::FxHashMap;

use super::attach::StoppedProcess;
use super::checked_loss_sum;
use super::cpu::online_cpu_ids;
use super::perf_event::{EventRef, EventSource, OutputRing, Perf, PerfOptions, TaskInheritance};

const MAX_TOTAL_RING_BUFFER_BYTES: u64 = 1024 * 1024 * 1024;

/// Reject pids that would not name a single real process once cast to the
/// signed `pid_t` that `kill` takes: `0` targets the caller's own process
/// group, and any value above `i32::MAX` wraps to a negative broadcast pid
/// (`u32::MAX` becomes `-1`, i.e. "every process we may signal").
fn validate_target_pid(pid: u32) -> io::Result<()> {
    if pid == 0 || i32::try_from(pid).is_err() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid target pid {pid}"),
        ));
    }
    Ok(())
}

struct Member {
    perf: Perf,
    output_fd: RawFd,
    owner_pid: u32,
}

#[derive(Clone, Copy)]
struct TaskTarget {
    tid: u32,
    owner_pid: u32,
}

struct OpenSettings {
    attach_mode: AttachMode,
    inherit: TaskInheritance,
    frequency: u64,
    maximum_ring_bytes: u64,
}

#[derive(Clone, Copy)]
pub(super) struct ThreadFork {
    pub(super) tid: u32,
    pub(super) owner_pid: u32,
    pub(super) parent_tid: u32,
}

#[derive(Clone, Copy)]
pub(super) struct ProcessFork {
    pub(super) pid: u32,
    pub(super) parent_tid: u32,
}

#[derive(Clone, Copy)]
pub(super) struct RecoveredProcessFork {
    pub(super) pid: u32,
    pub(super) parent_pid: u32,
}

struct OutputMember {
    ring: OutputRing,
    // One fd anchors polling for the shared ring. Its token always identifies
    // the output fd, even when a redirected member supplies the poll fd.
    poll_fd: Option<RawFd>,
}

#[derive(Default)]
struct PendingEvents {
    perfs: Vec<Member>,
    outputs: Vec<OutputRing>,
    cpu_outputs: BTreeMap<u32, RawFd>,
    allocated_ring_bytes: u64,
    kernel_excluded: bool,
}

enum OpenedEvent {
    Member {
        member: Member,
        inherit: TaskInheritance,
    },
    Output {
        inherit: TaskInheritance,
        capacity_bytes: u64,
    },
}

impl OpenedEvent {
    fn allocated_capacity_bytes(&self) -> u64 {
        match self {
            Self::Member { .. } => 0,
            Self::Output { capacity_bytes, .. } => *capacity_bytes,
        }
    }
}

#[derive(Debug)]
pub(super) struct OpenTransaction {
    member_fds: Vec<RawFd>,
    output_fds: Vec<RawFd>,
    bookkeeping: Vec<(u32, Option<ThreadTrack>)>,
    previous_include_kernel: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ThreadTrack {
    owner_pid: u32,
    events_inherit: bool,
}

impl ThreadTrack {
    fn new(owner_pid: u32, events_inherit: bool) -> Self {
        Self {
            owner_pid,
            events_inherit,
        }
    }
}

struct ThreadPerfEvents {
    events: Vec<Member>,
    inherits: bool,
}

impl ThreadPerfEvents {
    fn with_capacity(capacity: usize) -> Self {
        Self {
            events: Vec::with_capacity(capacity),
            inherits: false,
        }
    }

    fn push(&mut self, opened: OpenedEvent) {
        match opened {
            OpenedEvent::Member { member, inherit } => {
                self.inherits |= inherit.is_enabled();
                self.events.push(member);
            }
            OpenedEvent::Output { inherit, .. } => {
                self.inherits |= inherit.is_enabled();
            }
        }
    }
}

pub(super) struct PerfGroup {
    members: BTreeMap<RawFd, Member>,
    outputs: BTreeMap<RawFd, OutputMember>,
    cpu_outputs: BTreeMap<u32, RawFd>,
    saw_readable: bool,
    // Closed poll fds cannot become anchors again before their members are removed.
    retired_poll_fds: BTreeSet<RawFd>,
    poll: Poll,
    poll_events: Events,
    frequency: u32,
    stack_size: u32,
    ring_stacks: u32,
    regs_mask: u64,
    event_source: EventSource,
    include_kernel: bool,
    pub(crate) inherit_child_processes: bool,
    tracked_threads: BTreeMap<u32, ThreadTrack>,
    stopped_processes: Vec<StoppedProcess>,
    retired_lost_records: u64,
    reported_lost_records: u64,
}

#[derive(Clone, Copy)]
enum FrequencyMode {
    Requested,
    ClampToKernelMax,
}

pub(crate) trait EventConsumer {
    type Prepared;

    fn begin_group(&mut self, fd: RawFd);

    fn prepare_event(&mut self, event_ref: EventRef) -> Self::Prepared;

    fn queue_event(&mut self, timestamp: u64, prepared: Self::Prepared);

    fn drain_ready_events(&mut self);

    fn advance_round(&mut self);

    fn abort_round(&mut self);

    fn has_queued_events(&self) -> bool;

    fn detach_queued_events(&mut self);

    fn flush_ready_events(&mut self);
}

fn get_threads(pid: u32) -> io::Result<Vec<u32>> {
    let mut tids = Vec::new();
    for entry in fs::read_dir(format!("/proc/{pid}/task"))? {
        let entry = entry?;
        let Some(tid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        else {
            continue;
        };
        if tid != pid {
            tids.push(tid);
        }
    }
    Ok(tids)
}

/// How recording should attach to a process.
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
#[non_exhaustive]
pub enum AttachMode {
    /// Attach to a running process without stopping it.
    ///
    /// Mappings can change while StackPulse opens counters and reads
    /// `/proc/<pid>/maps`, so the initial module snapshot can race with mmap,
    /// munmap, and exec activity. Use [`Self::StopWhileAttaching`] when the
    /// initial mapping boundary must be coherent.
    Running,
    /// Attach before a not-yet-executed child is allowed to run.
    /// Counters remain disabled until the target calls `execve`.
    OnExec,
    /// Briefly stop an already-running process, attach, then resume it.
    StopWhileAttaching,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct PerfGroupOptions {
    pub frequency: u32,
    pub stack_size: u32,
    pub ring_stacks: u32,
    pub event_source: EventSource,
    pub regs_mask: u64,
    pub include_kernel: bool,
    pub inherit_child_processes: bool,
}

impl PerfGroup {
    fn pending_events(&self) -> PendingEvents {
        PendingEvents {
            allocated_ring_bytes: self
                .outputs
                .values()
                .map(|output| output.ring.capacity_bytes())
                .fold(0_u64, u64::saturating_add),
            ..PendingEvents::default()
        }
    }

    pub(super) fn new(options: PerfGroupOptions) -> io::Result<Self> {
        Ok(PerfGroup {
            members: Default::default(),
            outputs: Default::default(),
            cpu_outputs: Default::default(),
            saw_readable: false,
            retired_poll_fds: BTreeSet::new(),
            poll: Poll::new()?,
            poll_events: Events::with_capacity(16),
            frequency: options.frequency,
            stack_size: options.stack_size,
            ring_stacks: options.ring_stacks,
            event_source: options.event_source,
            regs_mask: options.regs_mask,
            include_kernel: options.include_kernel,
            inherit_child_processes: options.inherit_child_processes,
            tracked_threads: BTreeMap::new(),
            stopped_processes: Vec::new(),
            retired_lost_records: 0,
            reported_lost_records: 0,
        })
    }

    pub(super) fn open(
        pid: u32,
        attach_mode: AttachMode,
        options: PerfGroupOptions,
    ) -> io::Result<Self> {
        let mut group = PerfGroup::new(options)?;
        let _ = group.open_process(pid, attach_mode)?;
        Ok(group)
    }

    pub(super) fn open_process(
        &mut self,
        pid: u32,
        attach_mode: AttachMode,
    ) -> io::Result<OpenTransaction> {
        self.open_process_with_frequency_mode(pid, attach_mode, FrequencyMode::Requested)
    }

    fn open_process_with_frequency_mode(
        &mut self,
        pid: u32,
        attach_mode: AttachMode,
        frequency_mode: FrequencyMode,
    ) -> io::Result<OpenTransaction> {
        validate_target_pid(pid)?;
        if attach_mode == AttachMode::StopWhileAttaching && pid == std::process::id() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "cannot stop the recording process while attaching to itself",
            ));
        }
        let frequency = frequency_for_mode(self.frequency, frequency_mode);
        let (stopped_process, threads) = if attach_mode == AttachMode::StopWhileAttaching {
            let (stopped, threads) = StoppedProcess::new(pid)?;
            (Some(stopped), threads)
        } else {
            (None, get_threads(pid)?)
        };
        let result = (|| {
            let cpu_ids = online_cpu_ids()?;
            let cpu_count = cpu_ids.len();
            // Match perf's mmap topology: the first sampling counter on each CPU
            // owns the ring and every other same-CPU counter redirects into it.
            let mut pending = self.pending_events();
            pending
                .perfs
                .reserve(cpu_count.saturating_mul(threads.len().saturating_add(1)));
            let leader_perfs = self.open_task_perfs(
                TaskTarget {
                    tid: pid,
                    owner_pid: pid,
                },
                &cpu_ids,
                attach_mode,
                frequency,
                &mut pending,
            )?;
            let mut new_tracks = Vec::with_capacity(threads.len().saturating_add(1));
            new_tracks.push((pid, ThreadTrack::new(pid, leader_perfs.inherits)));
            pending.perfs.extend(leader_perfs.events);
            for &tid in &threads {
                let mut events_inherit = false;
                if let Some(thread_perfs) = self.try_open_thread_perfs(
                    TaskTarget {
                        tid,
                        owner_pid: pid,
                    },
                    &cpu_ids,
                    attach_mode,
                    frequency,
                    &mut pending,
                )? {
                    events_inherit = thread_perfs.inherits;
                    pending.perfs.extend(thread_perfs.events);
                }
                new_tracks.push((tid, ThreadTrack::new(pid, events_inherit)));
            }

            let mut opened = self.register_pending(pending)?;
            opened.bookkeeping = new_tracks
                .iter()
                .map(|(tid, _)| (*tid, self.tracked_threads.get(tid).copied()))
                .collect();
            for (tid, mut track) in new_tracks {
                track.events_inherit |= self
                    .tracked_threads
                    .get(&tid)
                    .is_some_and(|previous| previous.events_inherit);
                self.tracked_threads.insert(tid, track);
            }
            Ok(opened)
        })();
        match result {
            Ok(opened) => {
                if let Some(stopped_process) = stopped_process {
                    self.stopped_processes.push(stopped_process);
                }
                Ok(opened)
            }
            Err(err) => {
                if let Some(mut stopped_process) = stopped_process {
                    return Err(stopped_process.resume_error_or(err));
                }
                Err(err)
            }
        }
    }

    pub(super) fn refresh_threads(&mut self, pid: u32) -> io::Result<bool> {
        let mut threads = match get_threads(pid) {
            Ok(threads) => threads,
            Err(err) if crate::error::is_target_gone_io(&err) => return Ok(false),
            Err(err) => return Err(err),
        };
        threads.sort_unstable();
        // Only reconcile this process's threads; other attached processes'
        // tids are absent from /proc/<pid>/task and must survive.
        let stale_threads: Vec<_> = self
            .tracked_threads
            .iter()
            .filter_map(|(&tid, track)| {
                (track.owner_pid == pid && tid != pid && threads.binary_search(&tid).is_err())
                    .then_some(tid)
            })
            .collect();
        for tid in stale_threads {
            self.remove_thread(tid)?;
        }
        let new_threads: Vec<_> = threads
            .into_iter()
            .filter(|tid| !self.tracked_threads.contains_key(tid))
            .collect();
        if new_threads.is_empty() {
            return Ok(true);
        }
        let process_inherits = self
            .tracked_threads
            .values()
            .any(|track| track.owner_pid == pid && track.events_inherit);
        if process_inherits {
            for tid in new_threads {
                self.tracked_threads
                    .insert(tid, ThreadTrack::new(pid, true));
            }
            return Ok(true);
        }
        let cpu_ids = online_cpu_ids()?;
        let cpu_count = cpu_ids.len();
        let frequency = frequency_for_mode(self.frequency, FrequencyMode::ClampToKernelMax);
        let mut pending = self.pending_events();
        pending
            .perfs
            .reserve(cpu_count.saturating_mul(new_threads.len()));
        let mut tracked_threads = Vec::with_capacity(new_threads.len());
        for tid in new_threads {
            if let Some(thread_perfs) = self.try_open_thread_perfs(
                TaskTarget {
                    tid,
                    owner_pid: pid,
                },
                &cpu_ids,
                AttachMode::StopWhileAttaching,
                frequency,
                &mut pending,
            )? {
                let events_inherit = thread_perfs.inherits;
                pending.perfs.extend(thread_perfs.events);
                tracked_threads.push((tid, ThreadTrack::new(pid, events_inherit)));
            }
        }
        self.enable_and_register_pending(pending)?;
        self.tracked_threads.extend(tracked_threads);
        Ok(true)
    }

    pub(super) fn open_forked_threads(&mut self, thread_forks: &[ThreadFork]) -> io::Result<()> {
        if thread_forks.is_empty() {
            return Ok(());
        }

        let cpu_ids = online_cpu_ids()?;
        let cpu_count = cpu_ids.len();
        let frequency = frequency_for_mode(self.frequency, FrequencyMode::ClampToKernelMax);
        let mut pending = self.pending_events();
        pending
            .perfs
            .reserve(cpu_count.saturating_mul(thread_forks.len()));
        let mut tracked_threads =
            FxHashMap::with_capacity_and_hasher(thread_forks.len(), Default::default());

        for &ThreadFork {
            tid,
            owner_pid,
            parent_tid,
        } in thread_forks
        {
            if self.tracked_threads.contains_key(&tid) || tracked_threads.contains_key(&tid) {
                continue;
            }
            let parent_events_inherit = self
                .tracked_threads
                .get(&parent_tid)
                .or_else(|| tracked_threads.get(&parent_tid))
                .is_some_and(|track| track.events_inherit);
            if parent_events_inherit {
                tracked_threads.insert(tid, ThreadTrack::new(owner_pid, true));
                continue;
            }

            if let Some(thread_perfs) = self.try_open_thread_perfs(
                TaskTarget { tid, owner_pid },
                &cpu_ids,
                AttachMode::StopWhileAttaching,
                frequency,
                &mut pending,
            )? {
                let events_inherit = thread_perfs.inherits;
                pending.perfs.extend(thread_perfs.events);
                tracked_threads.insert(tid, ThreadTrack::new(owner_pid, events_inherit));
            }
        }

        self.enable_and_register_pending(pending)?;
        self.tracked_threads.extend(tracked_threads);
        Ok(())
    }

    pub(super) fn open_forked_processes(
        &mut self,
        process_forks: &[ProcessFork],
    ) -> io::Result<()> {
        if !self.inherit_child_processes {
            return Ok(());
        }

        for &ProcessFork { pid, parent_tid } in process_forks {
            let parent_events_inherit = self
                .tracked_threads
                .get(&parent_tid)
                .is_some_and(|track| track.events_inherit);
            if parent_events_inherit || self.tracked_threads.contains_key(&pid) {
                let events_inherit = parent_events_inherit
                    || self
                        .tracked_threads
                        .get(&pid)
                        .is_some_and(|track| track.events_inherit);
                self.tracked_threads
                    .insert(pid, ThreadTrack::new(pid, events_inherit));
                continue;
            }
            match self.open_process_with_frequency_mode(
                pid,
                AttachMode::StopWhileAttaching,
                FrequencyMode::ClampToKernelMax,
            ) {
                Ok(opened) => {
                    if let Err(err) = self.enable() {
                        self.rollback_open(opened);
                        return Err(err);
                    }
                }
                Err(err) if crate::error::is_target_gone_io(&err) => {}
                Err(err) => return Err(err),
            }
        }

        Ok(())
    }

    /// Repair process bookkeeping after LOST when only the owning parent
    /// process (not the exact forking TID) can be recovered from /proc.
    pub(super) fn recover_forked_processes(
        &mut self,
        process_forks: &[RecoveredProcessFork],
    ) -> io::Result<()> {
        let mut need_explicit_open = Vec::new();
        for &RecoveredProcessFork { pid, parent_pid } in process_forks {
            let parent_process_inherits = self
                .tracked_threads
                .values()
                .any(|track| track.owner_pid == parent_pid && track.events_inherit);
            if parent_process_inherits {
                self.tracked_threads
                    .insert(pid, ThreadTrack::new(pid, true));
            } else {
                need_explicit_open.push(ProcessFork {
                    pid,
                    parent_tid: parent_pid,
                });
            }
        }
        self.open_forked_processes(&need_explicit_open)
    }

    pub(super) fn remove_thread(&mut self, tid: u32) -> io::Result<()> {
        self.remove_members(|member| {
            member.perf.target() == tid && !member.perf.inherit().is_enabled()
        })?;
        self.tracked_threads.remove(&tid);
        Ok(())
    }

    pub(super) fn remove_process(&mut self, pid: u32) -> io::Result<()> {
        self.remove_members(|member| {
            member.owner_pid == pid && member.perf.inherit() != TaskInheritance::Children
        })?;
        self.tracked_threads.retain(|tid, track| {
            if track.owner_pid == pid {
                return false;
            }
            if *tid == pid {
                track.events_inherit = false;
            }
            true
        });
        Ok(())
    }

    fn remove_members(&mut self, should_remove: impl Fn(&Member) -> bool) -> io::Result<()> {
        let fds_to_remove: Vec<_> = self
            .members
            .iter()
            .filter_map(|(&fd, member)| should_remove(member).then_some(fd))
            .collect();
        for fd in fds_to_remove {
            self.retire_member_fd(fd)?;
        }
        Ok(())
    }

    fn open_task_perfs(
        &self,
        target: TaskTarget,
        cpu_ids: &[u32],
        attach_mode: AttachMode,
        frequency: u64,
        pending: &mut PendingEvents,
    ) -> io::Result<ThreadPerfEvents> {
        let mut perf_events = ThreadPerfEvents::with_capacity(cpu_ids.len());
        let per_cpu_budget =
            MAX_TOTAL_RING_BUFFER_BYTES / u64::try_from(cpu_ids.len().max(1)).unwrap_or(u64::MAX);
        for &cpu in cpu_ids {
            let remaining =
                MAX_TOTAL_RING_BUFFER_BYTES.saturating_sub(pending.allocated_ring_bytes);
            let opened = self.open_perf(
                target,
                cpu,
                OpenSettings {
                    attach_mode,
                    inherit: self.task_inheritance(),
                    frequency,
                    maximum_ring_bytes: per_cpu_budget.min(remaining),
                },
                pending,
            )?;
            pending.allocated_ring_bytes = pending
                .allocated_ring_bytes
                .saturating_add(opened.allocated_capacity_bytes());
            perf_events.push(opened);
        }
        Ok(perf_events)
    }

    fn try_open_thread_perfs(
        &self,
        target: TaskTarget,
        cpu_ids: &[u32],
        attach_mode: AttachMode,
        frequency: u64,
        pending: &mut PendingEvents,
    ) -> io::Result<Option<ThreadPerfEvents>> {
        match self.open_task_perfs(target, cpu_ids, attach_mode, frequency, pending) {
            Ok(perfs) => Ok(Some(perfs)),
            Err(err) if err.raw_os_error() == Some(libc::ESRCH) => Ok(None),
            Err(err) => Err(err),
        }
    }

    fn register_pending(&mut self, pending: PendingEvents) -> io::Result<OpenTransaction> {
        let kernel_excluded = pending.kernel_excluded;
        let previous_include_kernel = self.include_kernel;
        let member_fds = pending
            .perfs
            .iter()
            .map(|member| member.perf.fd())
            .collect();
        let output_fds = pending.outputs.iter().map(OutputRing::fd).collect();
        let mut registered_outputs = Vec::with_capacity(pending.outputs.len());
        for ring in pending.outputs {
            let fd = ring.fd();
            if let Err(err) = self.poll.registry().register(
                &mut SourceFd(&fd),
                Token(fd as usize),
                Interest::READABLE,
            ) {
                for fd in registered_outputs {
                    self.remove_output_fd(fd);
                }
                return Err(err);
            }
            self.cpu_outputs.insert(ring.cpu(), fd);
            self.outputs.insert(
                fd,
                OutputMember {
                    ring,
                    poll_fd: Some(fd),
                },
            );
            self.retired_poll_fds.remove(&fd);
            registered_outputs.push(fd);
        }
        for member in pending.perfs {
            let fd = member.perf.fd();
            self.retired_poll_fds.remove(&fd);
            self.members.insert(fd, member);
        }
        self.include_kernel &= !kernel_excluded;
        Ok(OpenTransaction {
            member_fds,
            output_fds,
            bookkeeping: Vec::new(),
            previous_include_kernel,
        })
    }

    fn enable_and_register_pending(&mut self, pending: PendingEvents) -> io::Result<()> {
        for ring in &pending.outputs {
            ring.enable()?;
        }
        for member in &pending.perfs {
            member.perf.enable()?;
        }
        self.register_pending(pending).map(drop)
    }

    pub(super) fn rollback_open(&mut self, opened: OpenTransaction) {
        self.include_kernel = opened.previous_include_kernel;
        for fd in opened.member_fds {
            self.remove_member_fd(fd);
        }
        for fd in opened.output_fds {
            if !self.members.values().any(|member| member.output_fd == fd) {
                self.remove_output_fd(fd);
            }
        }
        for (tid, previous) in opened.bookkeeping {
            if let Some(previous) = previous {
                self.tracked_threads.insert(tid, previous);
            } else {
                self.tracked_threads.remove(&tid);
            }
        }
    }

    fn remove_member_fd(&mut self, fd: RawFd) {
        let output_fd = self.members.get(&fd).map(|member| member.output_fd);
        if output_fd.is_some_and(|output_fd| {
            self.outputs
                .get(&output_fd)
                .is_some_and(|output| output.poll_fd == Some(fd))
        }) {
            let _ = self.poll.registry().deregister(&mut SourceFd(&fd));
            if let Some(output) = output_fd.and_then(|fd| self.outputs.get_mut(&fd)) {
                output.poll_fd = None;
            }
        }
        self.members.remove(&fd);
        self.retired_poll_fds.remove(&fd);
    }

    fn retire_member_fd(&mut self, fd: RawFd) -> io::Result<()> {
        let Some(member) = self.members.get(&fd) else {
            return Ok(());
        };
        member.perf.disable()?;
        let retired = checked_loss_sum(self.retired_lost_records, member.perf.lost_records()?)?;
        self.remove_member_fd(fd);
        self.retired_lost_records = retired;
        Ok(())
    }

    fn remove_output_fd(&mut self, fd: RawFd) {
        if let Some(member) = self.outputs.remove(&fd) {
            if let Some(poll_fd) = member.poll_fd {
                let _ = self.poll.registry().deregister(&mut SourceFd(&poll_fd));
            }
            self.cpu_outputs.remove(&member.ring.cpu());
        }
        self.retired_poll_fds.remove(&fd);
    }

    fn ensure_poll_anchor(&mut self, output_fd: RawFd) -> io::Result<()> {
        let Some(output) = self.outputs.get(&output_fd) else {
            return Ok(());
        };
        if output.poll_fd.is_some() {
            return Ok(());
        }
        let poll_fd = std::iter::once(output_fd)
            .chain(
                self.members
                    .iter()
                    .filter_map(|(&fd, member)| (member.output_fd == output_fd).then_some(fd)),
            )
            .find(|fd| !self.retired_poll_fds.contains(fd));
        let Some(poll_fd) = poll_fd else {
            return Ok(());
        };
        self.poll.registry().register(
            &mut SourceFd(&poll_fd),
            Token(output_fd as usize),
            Interest::READABLE,
        )?;
        if let Some(output) = self.outputs.get_mut(&output_fd) {
            output.poll_fd = Some(poll_fd);
        }
        Ok(())
    }

    fn replace_closed_poll_anchor(&mut self, output_fd: RawFd) -> io::Result<()> {
        let poll_fd = self
            .outputs
            .get_mut(&output_fd)
            .and_then(|output| output.poll_fd.take());
        if let Some(poll_fd) = poll_fd {
            let _ = self.poll.registry().deregister(&mut SourceFd(&poll_fd));
            self.retired_poll_fds.insert(poll_fd);
        }
        self.ensure_poll_anchor(output_fd)
    }

    fn ensure_poll_anchors(&mut self) -> io::Result<()> {
        let missing: Vec<_> = self
            .outputs
            .iter()
            .filter_map(|(&fd, output)| output.poll_fd.is_none().then_some(fd))
            .collect();
        for fd in missing {
            self.ensure_poll_anchor(fd)?;
        }
        Ok(())
    }

    fn open_perf(
        &self,
        target: TaskTarget,
        cpu: u32,
        settings: OpenSettings,
        pending: &mut PendingEvents,
    ) -> io::Result<OpenedEvent> {
        let OpenSettings {
            attach_mode,
            inherit,
            frequency,
            maximum_ring_bytes,
        } = settings;
        let output_fd = self
            .cpu_outputs
            .get(&cpu)
            .copied()
            .or_else(|| pending.cpu_outputs.get(&cpu).copied());
        let existing_output = output_fd
            .map(|fd| {
                self.outputs
                    .get(&fd)
                    .map(|member| &member.ring)
                    .or_else(|| pending.outputs.iter().find(|output| output.fd() == fd))
                    .ok_or_else(|| io::Error::other("missing perf output ring"))
                    .map(|output| (fd, output))
            })
            .transpose()?;
        let options = PerfOptions {
            pid: target.tid,
            cpu,
            frequency,
            stack_size: self.stack_size,
            ring_stacks: self.ring_stacks,
            maximum_ring_bytes: existing_output
                .map_or(maximum_ring_bytes, |(_, output)| output.capacity_bytes()),
            reg_mask: self.regs_mask,
            event_source: self.event_source,
            inherit,
            enable_on_exec: attach_mode == AttachMode::OnExec,
            include_kernel: self.include_kernel && !pending.kernel_excluded,
            sample_callchain: true,
            exclude_user_callchain: true,
            exclude_kernel_callchain: !self.include_kernel || pending.kernel_excluded,
        };
        if let Some((fd, output)) = existing_output {
            let perf = options.open()?;
            if !perf.includes_kernel() {
                pending.kernel_excluded = true;
            }
            perf.set_output(output)?;
            Ok(OpenedEvent::Member {
                inherit: perf.inherit(),
                member: Member {
                    perf,
                    output_fd: fd,
                    owner_pid: target.owner_pid,
                },
            })
        } else {
            let output = options.open_ring()?;
            if !output.includes_kernel() {
                pending.kernel_excluded = true;
            }
            let fd = output.fd();
            let inherit = output.inherit();
            let capacity_bytes = output.capacity_bytes();
            pending.cpu_outputs.insert(cpu, fd);
            pending.outputs.push(output);
            Ok(OpenedEvent::Output {
                inherit,
                capacity_bytes,
            })
        }
    }

    fn task_inheritance(&self) -> TaskInheritance {
        if self.inherit_child_processes {
            TaskInheritance::Children
        } else {
            TaskInheritance::Threads
        }
    }

    pub(super) fn has_pending_events(&self) -> bool {
        self.saw_readable
    }

    pub(super) fn kernel_enabled(&self) -> bool {
        self.include_kernel
    }

    pub(super) fn ring_capacity_bytes_range(&self) -> Option<(u64, u64)> {
        let mut capacities = self
            .outputs
            .values()
            .map(|output| output.ring.capacity_bytes());
        let first = capacities.next()?;
        Some(
            capacities.fold((first, first), |(minimum, maximum), capacity| {
                (minimum.min(capacity), maximum.max(capacity))
            }),
        )
    }

    pub(super) fn enable(&mut self) -> io::Result<()> {
        let enable_result = (|| {
            for member in self.outputs.values() {
                member.ring.enable()?;
            }
            for member in self.members.values_mut() {
                member.perf.enable()?;
            }
            Ok(())
        })();
        let resume_result = self.resume_stopped_processes();
        crate::error::and_cleanup(enable_result, resume_result)
    }

    pub(super) fn resume_stopped_processes(&mut self) -> io::Result<()> {
        let mut first_error = None;
        for mut process in std::mem::take(&mut self.stopped_processes) {
            if let Err(err) = process.resume() {
                first_error.get_or_insert(err);
            }
        }
        first_error.map_or(Ok(()), Err)
    }

    pub(super) fn resume_error_or(&mut self, original_error: io::Error) -> io::Error {
        match self.resume_stopped_processes() {
            Ok(()) => original_error,
            Err(cleanup_error) => crate::error::with_cleanup_error(original_error, cleanup_error),
        }
    }

    pub(super) fn disable(&mut self) -> io::Result<()> {
        let mut first_error = None;
        for member in self.outputs.values() {
            if let Err(err) = member.ring.disable() {
                first_error.get_or_insert(err);
            }
        }
        for member in self.members.values_mut() {
            if let Err(err) = member.perf.disable() {
                first_error.get_or_insert(err);
            }
        }
        first_error.map_or(Ok(()), Err)
    }

    pub(super) fn take_lost_records(&mut self) -> io::Result<u64> {
        let mut total = self.retired_lost_records;
        for output in self.outputs.values() {
            total = checked_loss_sum(total, output.ring.lost_records()?)?;
        }
        for member in self.members.values() {
            total = checked_loss_sum(total, member.perf.lost_records()?)?;
        }
        let delta = total
            .checked_sub(self.reported_lost_records)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "perf lost-record counter regressed",
                )
            })?;
        self.reported_lost_records = total;
        Ok(delta)
    }

    pub(super) fn wait(&mut self, timeout: Duration) -> io::Result<()> {
        if self.saw_readable {
            return Ok(());
        }
        self.ensure_poll_anchors()?;
        // EINTR is normal (signals: e.g. parent's Ctrl-C handler).
        if let Err(err) = self.poll.poll(&mut self.poll_events, Some(timeout)) {
            return if err.kind() == io::ErrorKind::Interrupted {
                Ok(())
            } else {
                Err(err)
            };
        }
        let mut closed = Vec::new();
        for ev in self.poll_events.iter() {
            let fd = ev.token().0 as RawFd;
            if ev.is_readable() {
                self.saw_readable = true;
            }
            if ev.is_read_closed() {
                closed.push(fd);
            }
        }
        for fd in closed {
            self.replace_closed_poll_anchor(fd)?;
        }
        Ok(())
    }

    pub(super) fn consume_events<C: EventConsumer>(&mut self, consumer: &mut C) -> io::Result<()> {
        self.saw_readable = false;
        // Drain every ring buffer on every pass. Poll readiness is only a wakeup
        // hint; using it as a filter can let older mmap/fork records sit behind
        // newer samples from another fd, which breaks timestamp-ordered unwinding.
        // A real second read round is required when events remain queued. An
        // empty synthetic round could release a newer event from a later ring
        // before an older event published into an earlier ring after that
        // ring's first snapshot. Two rounds still bound work under continuous
        // production; anything held after them is detached for the next call.
        drain_event_round(
            self.outputs
                .iter_mut()
                .map(|(&fd, member)| (fd, &mut member.ring)),
            consumer,
            drain_output_ring,
        )?;
        if consumer.has_queued_events() {
            drain_event_round(
                self.outputs
                    .iter_mut()
                    .map(|(&fd, member)| (fd, &mut member.ring)),
                consumer,
                drain_output_ring,
            )?;
        }
        if consumer.has_queued_events() {
            consumer.detach_queued_events();
        }
        Ok(())
    }

    pub(super) fn flush_events<C: EventConsumer>(&mut self, consumer: &mut C) -> io::Result<()> {
        self.consume_events(consumer)?;
        consumer.flush_ready_events();
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn resource_counts(&self) -> (usize, usize, usize) {
        (
            self.outputs.len(),
            self.members.len(),
            self.tracked_threads.len(),
        )
    }
}

fn drain_event_round<C, R>(
    rings: impl IntoIterator<Item = (RawFd, R)>,
    consumer: &mut C,
    mut drain_ring: impl FnMut(R, &mut C) -> io::Result<()>,
) -> io::Result<()>
where
    C: EventConsumer,
{
    for (fd, ring) in rings {
        consumer.begin_group(fd);
        consumer.drain_ready_events();
        if let Err(err) = drain_ring(ring, consumer) {
            consumer.detach_queued_events();
            consumer.abort_round();
            return Err(err);
        }
        consumer.drain_ready_events();
    }
    consumer.advance_round();
    consumer.drain_ready_events();
    Ok(())
}

fn drain_output_ring<C: EventConsumer>(ring: &mut OutputRing, consumer: &mut C) -> io::Result<()> {
    let mut drain = ring.event_drain();
    while let Some((timestamp, prepared)) = drain.next_event(&mut |event_ref| {
        let timestamp = event_ref.timestamp().unwrap_or(0);
        let prepared = consumer.prepare_event(event_ref);
        (timestamp, prepared)
    })? {
        consumer.queue_event(timestamp, prepared);
    }
    Ok(())
}

fn frequency_for_mode(frequency: u32, mode: FrequencyMode) -> u64 {
    frequency_for_kernel_max(frequency, mode, crate::record::max_sample_rate())
}

fn frequency_for_kernel_max(frequency: u32, mode: FrequencyMode, max_rate: Option<u64>) -> u64 {
    let requested = u64::from(frequency);
    match mode {
        FrequencyMode::Requested => requested,
        FrequencyMode::ClampToKernelMax => max_rate
            .filter(|&max_rate| max_rate > 0 && requested > max_rate)
            .unwrap_or(requested),
    }
}

#[cfg(test)]
mod tests {
    use super::super::cpu::parse_cpu_list;
    use super::super::perf_event::MAX_SAMPLE_USER_STACK;
    use super::*;

    const TEST_OPTIONS: PerfGroupOptions = PerfGroupOptions {
        frequency: 1,
        stack_size: 0,
        ring_stacks: 0,
        event_source: EventSource::SwCpuClock,
        regs_mask: 0,
        include_kernel: false,
        inherit_child_processes: false,
    };

    struct EmptyConsumer {
        calls: Vec<&'static str>,
    }

    impl EventConsumer for EmptyConsumer {
        type Prepared = ();

        fn begin_group(&mut self, _fd: RawFd) {
            self.calls.push("begin_group");
        }

        fn prepare_event(&mut self, _event_ref: EventRef) -> Self::Prepared {
            unreachable!("empty group has no events")
        }

        fn queue_event(&mut self, _timestamp: u64, _prepared: Self::Prepared) {
            self.calls.push("queue_event");
        }

        fn drain_ready_events(&mut self) {
            self.calls.push("drain_ready_events");
        }

        fn advance_round(&mut self) {
            self.calls.push("advance_round");
        }

        fn abort_round(&mut self) {
            self.calls.push("abort_round");
        }

        fn has_queued_events(&self) -> bool {
            false
        }

        fn detach_queued_events(&mut self) {}

        fn flush_ready_events(&mut self) {
            self.calls.push("flush_ready_events");
        }
    }

    #[derive(Default)]
    struct NeverEmptyConsumer {
        rounds: usize,
        detaches: usize,
    }

    impl EventConsumer for NeverEmptyConsumer {
        type Prepared = ();

        fn begin_group(&mut self, _fd: RawFd) {}
        fn prepare_event(&mut self, _event_ref: EventRef) -> Self::Prepared {}
        fn queue_event(&mut self, _timestamp: u64, _prepared: Self::Prepared) {}
        fn drain_ready_events(&mut self) {}
        fn advance_round(&mut self) {
            self.rounds += 1;
        }
        fn abort_round(&mut self) {}
        fn has_queued_events(&self) -> bool {
            true
        }
        fn detach_queued_events(&mut self) {
            self.detaches += 1;
        }
        fn flush_ready_events(&mut self) {}
    }

    struct OrderingConsumer {
        sorter: super::super::sorter::EventSorter<RawFd, u64, &'static str>,
        output: Vec<&'static str>,
    }

    impl OrderingConsumer {
        fn new() -> Self {
            Self {
                sorter: super::super::sorter::EventSorter::new(),
                output: Vec::new(),
            }
        }
    }

    impl EventConsumer for OrderingConsumer {
        type Prepared = &'static str;

        fn begin_group(&mut self, fd: RawFd) {
            self.sorter.begin_group(fd);
        }

        fn prepare_event(&mut self, _event_ref: EventRef) -> Self::Prepared {
            unreachable!("the ordering regression supplies prepared events")
        }

        fn queue_event(&mut self, timestamp: u64, prepared: Self::Prepared) {
            self.sorter.push_current_group(timestamp, prepared);
        }

        fn drain_ready_events(&mut self) {
            while let Some(event) = self.sorter.pop() {
                self.output.push(event);
            }
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

        fn detach_queued_events(&mut self) {}

        fn flush_ready_events(&mut self) {
            while let Some(event) = self.sorter.force_pop() {
                self.output.push(event);
            }
        }
    }

    #[test]
    fn second_ring_snapshot_preserves_inter_round_lifecycle_order() {
        fn queue_events(
            events: &[(u64, &'static str)],
            consumer: &mut OrderingConsumer,
        ) -> io::Result<()> {
            for &(timestamp, event) in events {
                consumer.queue_event(timestamp, event);
            }
            Ok(())
        }

        let empty: &[(u64, &'static str)] = &[];
        let newer_sample = &[(20, "newer sample")][..];
        let older_fork = &[(10, "older fork")][..];
        let mut consumer = OrderingConsumer::new();

        // Ring 10 is snapshotted empty. The older fork is published into it
        // before ring 20's first snapshot observes the newer sample.
        drain_event_round(
            [(10, empty), (20, newer_sample)],
            &mut consumer,
            queue_events,
        )
        .unwrap();
        assert!(consumer.output.is_empty());

        // The bounded second round must really snapshot ring 10. A synthetic
        // empty round would release the newer sample here.
        drain_event_round([(10, older_fork), (20, empty)], &mut consumer, queue_events).unwrap();
        assert!(consumer.output.is_empty());

        // The next consume call can now release both records in timestamp and
        // lifecycle order.
        drain_event_round([(10, empty), (20, empty)], &mut consumer, queue_events).unwrap();
        assert_eq!(consumer.output, ["older fork", "newer sample"]);
    }

    #[test]
    fn saturated_sorter_work_is_bounded_to_two_rounds() {
        let mut group = PerfGroup::new(TEST_OPTIONS).expect("create perf group");
        let mut consumer = NeverEmptyConsumer::default();

        group
            .consume_events(&mut consumer)
            .expect("bounded drain succeeds");

        assert_eq!(consumer.rounds, 2);
        assert_eq!(consumer.detaches, 1);
    }

    #[test]
    fn failed_ring_read_aborts_partial_round_before_retry() {
        fn queue_or_fail(
            events: &[(u64, &'static str)],
            consumer: &mut OrderingConsumer,
        ) -> io::Result<()> {
            if events.first().is_some_and(|event| event.1 == "malformed") {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "malformed"));
            }
            for &(timestamp, event) in events {
                consumer.queue_event(timestamp, event);
            }
            Ok(())
        }

        let mut consumer = OrderingConsumer::new();
        let error = drain_event_round(
            [(10, &[(10, "partial")][..]), (20, &[(0, "malformed")][..])],
            &mut consumer,
            queue_or_fail,
        )
        .expect_err("second ring fails");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(consumer.output.is_empty());

        drain_event_round([(10, &[][..]), (20, &[][..])], &mut consumer, queue_or_fail)
            .expect("retry can begin at the lowest fd");
        assert!(consumer.output.is_empty());
        drain_event_round([(10, &[][..]), (20, &[][..])], &mut consumer, queue_or_fail)
            .expect("later round releases partial result");
        assert_eq!(consumer.output, ["partial"]);
    }

    #[test]
    fn failed_open_process_does_not_track_process() {
        let pid = std::process::id();
        let mut group = PerfGroup::new(PerfGroupOptions {
            stack_size: MAX_SAMPLE_USER_STACK + 1,
            inherit_child_processes: true,
            ..TEST_OPTIONS
        })
        .expect("create perf group");

        let err = group
            .open_process(pid, AttachMode::OnExec)
            .expect_err("invalid stack size should fail before opening perf events");

        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(group.tracked_threads.is_empty());
        assert!(group.members.is_empty());
    }

    #[test]
    fn open_rejects_invalid_pid_before_tracking_process() {
        let err = match PerfGroup::open(0, AttachMode::OnExec, TEST_OPTIONS) {
            Ok(_) => panic!("pid 0 should be rejected"),
            Err(err) => err,
        };

        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn inherited_forked_process_is_tracked_without_opening_new_fds() {
        let mut group = PerfGroup::new(PerfGroupOptions {
            inherit_child_processes: true,
            ..TEST_OPTIONS
        })
        .expect("create perf group");
        group
            .tracked_threads
            .insert(100, ThreadTrack::new(100, true));

        group
            .open_forked_processes(&[ProcessFork {
                pid: 200,
                parent_tid: 100,
            }])
            .expect("track inherited child process");

        assert!(group.tracked_threads.contains_key(&200));
        assert!(group.tracked_threads[&200].events_inherit);
        assert!(group.members.is_empty());
    }

    #[test]
    fn lost_fork_recovery_uses_any_inheriting_thread_owned_by_parent_process() {
        let mut group = PerfGroup::new(PerfGroupOptions {
            inherit_child_processes: true,
            ..TEST_OPTIONS
        })
        .expect("create perf group");
        group
            .tracked_threads
            .insert(100, ThreadTrack::new(100, false));
        group
            .tracked_threads
            .insert(101, ThreadTrack::new(100, true));

        group
            .recover_forked_processes(&[RecoveredProcessFork {
                pid: 200,
                parent_pid: 100,
            }])
            .expect("recover inherited child process");

        assert_eq!(
            group.tracked_threads.get(&200),
            Some(&ThreadTrack::new(200, true))
        );
        assert!(group.members.is_empty());
    }

    #[test]
    fn refresh_threads_drops_stale_inheriting_tids() {
        let pid = std::process::id();
        let stale_tid = u32::MAX;
        let mut group = PerfGroup::new(TEST_OPTIONS).expect("create perf group");
        group
            .tracked_threads
            .insert(pid, ThreadTrack::new(pid, true));
        group
            .tracked_threads
            .insert(stale_tid, ThreadTrack::new(pid, true));

        group
            .refresh_threads(pid)
            .expect("refresh live test process");

        assert!(!group.tracked_threads.contains_key(&stale_tid));
        assert!(group.tracked_threads[&pid].events_inherit);
    }

    #[test]
    fn forked_processes_are_ignored_when_child_inheritance_is_disabled() {
        let mut group = PerfGroup::new(TEST_OPTIONS).expect("create perf group");

        group
            .open_forked_processes(&[ProcessFork {
                pid: 200,
                parent_tid: 100,
            }])
            .expect("ignore forked process");

        assert!(group.tracked_threads.is_empty());
        assert!(group.members.is_empty());
    }

    #[test]
    fn forked_threads_under_inheriting_parent_are_tracked_without_opening_fds() {
        let mut group = PerfGroup::new(TEST_OPTIONS).expect("create perf group");
        group
            .tracked_threads
            .insert(100, ThreadTrack::new(100, true));

        group
            .open_forked_threads(&[
                ThreadFork {
                    tid: 101,
                    owner_pid: 100,
                    parent_tid: 100,
                },
                ThreadFork {
                    tid: 102,
                    owner_pid: 100,
                    parent_tid: 101,
                },
                ThreadFork {
                    tid: 101,
                    owner_pid: 100,
                    parent_tid: 100,
                },
            ])
            .expect("track forked threads");

        assert_eq!(
            group.tracked_threads.get(&101),
            Some(&ThreadTrack::new(100, true))
        );
        assert_eq!(
            group.tracked_threads.get(&102),
            Some(&ThreadTrack::new(100, true))
        );
        assert!(group.members.is_empty());
    }

    #[test]
    fn empty_forked_threads_are_noop() {
        let mut group = PerfGroup::new(TEST_OPTIONS).expect("create perf group");

        group.open_forked_threads(&[]).expect("empty fork list");

        assert!(group.tracked_threads.is_empty());
    }

    #[test]
    fn remove_thread_and_process_clear_bookkeeping() {
        let mut group = PerfGroup::new(TEST_OPTIONS).expect("create perf group");
        group
            .tracked_threads
            .insert(100, ThreadTrack::new(100, false));
        group
            .tracked_threads
            .insert(101, ThreadTrack::new(100, true));
        group
            .tracked_threads
            .insert(200, ThreadTrack::new(200, true));

        group.remove_thread(101).expect("remove thread");
        group.remove_process(100).expect("remove process");

        assert!(!group.tracked_threads.contains_key(&100));
        assert!(!group.tracked_threads.contains_key(&101));
        assert_eq!(
            group.tracked_threads.get(&200),
            Some(&ThreadTrack::new(200, true))
        );
    }

    #[test]
    fn empty_group_control_paths_are_noops() {
        let mut group = PerfGroup::new(TEST_OPTIONS).expect("create perf group");
        let mut consumer = EmptyConsumer { calls: Vec::new() };

        assert!(!group.has_pending_events());
        group.enable().expect("enable empty group");
        group.disable().expect("disable empty group");
        group
            .resume_stopped_processes()
            .expect("resume empty group");
        let original = io::Error::from_raw_os_error(libc::ENOSPC);
        assert_eq!(
            group.resume_error_or(original).raw_os_error(),
            Some(libc::ENOSPC)
        );
        group.flush_events(&mut consumer).unwrap();

        assert_eq!(
            consumer.calls,
            vec!["advance_round", "drain_ready_events", "flush_ready_events"]
        );
    }

    #[test]
    fn lost_record_deltas_include_retired_events_once() {
        let mut group = PerfGroup::new(TEST_OPTIONS).expect("create perf group");
        group.retired_lost_records = 7;

        assert_eq!(group.take_lost_records().unwrap(), 7);
        assert_eq!(group.take_lost_records().unwrap(), 0);

        group.retired_lost_records = 11;
        assert_eq!(group.take_lost_records().unwrap(), 4);
    }

    #[test]
    fn lost_record_accounting_rejects_overflow_and_regression() {
        assert_eq!(
            checked_loss_sum(u64::MAX, 1).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        let mut group = PerfGroup::new(TEST_OPTIONS).expect("create perf group");
        group.reported_lost_records = 1;
        assert_eq!(
            group.take_lost_records().unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn fixed_cpu_events_share_one_output_ring() {
        let Some(cpu) = online_cpu_ids().expect("online CPUs").into_iter().next() else {
            return;
        };
        let group = PerfGroup::new(TEST_OPTIONS).expect("create perf group");
        let pid = std::process::id();
        let Some(pending) = open_fixed_cpu_events(&group, pid, pid, cpu, 2, TaskInheritance::None)
        else {
            return;
        };

        assert_eq!(pending.perfs.len(), 1);
        assert_eq!(pending.outputs.len(), 1);
    }

    #[test]
    fn closed_output_poll_anchor_promotes_a_redirected_member() {
        let Some(cpu) = online_cpu_ids().expect("online CPUs").into_iter().next() else {
            return;
        };
        let mut group = PerfGroup::new(TEST_OPTIONS).expect("create perf group");
        let pid = std::process::id();
        let Some(pending) = open_fixed_cpu_events(&group, pid, pid, cpu, 3, TaskInheritance::None)
        else {
            return;
        };
        let output_fd = pending.outputs[0].fd();
        let mut member_fds: Vec<_> = pending
            .perfs
            .iter()
            .map(|member| member.perf.fd())
            .collect();
        member_fds.sort_unstable();
        let [first_member_fd, second_member_fd] = member_fds[..] else {
            unreachable!("three events create one owner and two members");
        };
        group.register_pending(pending).expect("register events");

        group
            .replace_closed_poll_anchor(output_fd)
            .expect("promote redirected member");
        assert_eq!(group.outputs[&output_fd].poll_fd, Some(first_member_fd));

        group
            .replace_closed_poll_anchor(output_fd)
            .expect("promote another redirected member");
        assert!(group.members.contains_key(&first_member_fd));
        assert_eq!(group.outputs[&output_fd].poll_fd, Some(second_member_fd));

        group.remove_member_fd(second_member_fd);
        group.ensure_poll_anchor(output_fd).expect("no live anchor");

        assert_eq!(group.outputs[&output_fd].poll_fd, None);
    }

    #[test]
    fn process_removal_retires_thread_inheritance_but_preserves_child_inheritance() {
        let Some(cpu) = online_cpu_ids().expect("online CPUs").into_iter().next() else {
            return;
        };
        for (inherit, expected_members) in [
            (TaskInheritance::Threads, 0),
            (TaskInheritance::Children, 1),
        ] {
            let mut group = PerfGroup::new(TEST_OPTIONS).expect("create perf group");
            let pid = std::process::id();
            let Some(pending) = open_fixed_cpu_events(&group, pid, pid, cpu, 2, inherit) else {
                return;
            };
            group.register_pending(pending).expect("register events");
            group
                .remove_process(std::process::id())
                .expect("remove process events");

            assert_eq!(group.members.len(), expected_members);
        }
    }

    #[test]
    fn process_removal_finds_members_after_their_thread_was_removed() {
        let Some(cpu) = online_cpu_ids().expect("online CPUs").into_iter().next() else {
            return;
        };
        let target_tid = std::process::id();
        let owner_pid = u32::MAX - 1;
        let mut group = PerfGroup::new(TEST_OPTIONS).expect("create perf group");
        let Some(pending) = open_fixed_cpu_events(
            &group,
            target_tid,
            owner_pid,
            cpu,
            2,
            TaskInheritance::Threads,
        ) else {
            return;
        };
        group.register_pending(pending).expect("register events");
        group
            .tracked_threads
            .insert(target_tid, ThreadTrack::new(owner_pid, false));

        group.remove_thread(target_tid).expect("remove thread");
        assert_eq!(group.members.len(), 1);
        group.remove_process(owner_pid).expect("remove process");
        assert!(group.members.is_empty());
    }

    fn open_fixed_cpu_events(
        group: &PerfGroup,
        target_tid: u32,
        owner_pid: u32,
        cpu: u32,
        count: usize,
        inherit: TaskInheritance,
    ) -> Option<PendingEvents> {
        let mut pending = group.pending_events();
        for _ in 0..count {
            let opened = match group.open_perf(
                TaskTarget {
                    tid: target_tid,
                    owner_pid,
                },
                cpu,
                OpenSettings {
                    attach_mode: AttachMode::OnExec,
                    inherit,
                    frequency: 1,
                    maximum_ring_bytes: MAX_TOTAL_RING_BUFFER_BYTES,
                },
                &mut pending,
            ) {
                Ok(opened) => opened,
                Err(err) if perf_open_can_be_skipped(&err) => return None,
                Err(err) => panic!("open redirected perf event: {err}"),
            };
            if let OpenedEvent::Member { member, .. } = opened {
                pending.perfs.push(member);
            }
        }
        Some(pending)
    }

    #[test]
    fn rollback_removes_exact_open_transaction() {
        let mut group = PerfGroup::new(TEST_OPTIONS).expect("create perf group");
        let opened = match group.open_process(std::process::id(), AttachMode::OnExec) {
            Ok(opened) => opened,
            Err(err) if perf_open_can_be_skipped(&err) => return,
            Err(err) => panic!("open process: {err}"),
        };
        assert!(!group.outputs.is_empty());

        group.rollback_open(opened);

        assert!(group.members.is_empty());
        assert!(group.outputs.is_empty());
        assert!(group.tracked_threads.is_empty());
    }

    #[test]
    fn rollback_restores_exact_thread_tracking_state() {
        let mut group = PerfGroup::new(TEST_OPTIONS).expect("create perf group");
        let previous = ThreadTrack::new(100, true);
        group
            .tracked_threads
            .insert(100, ThreadTrack::new(200, false));
        group
            .tracked_threads
            .insert(300, ThreadTrack::new(300, true));
        let opened = OpenTransaction {
            member_fds: Vec::new(),
            output_fds: Vec::new(),
            bookkeeping: vec![(100, Some(previous)), (300, None)],
            previous_include_kernel: group.include_kernel,
        };

        group.rollback_open(opened);

        assert_eq!(group.tracked_threads.get(&100), Some(&previous));
        assert!(!group.tracked_threads.contains_key(&300));
    }

    #[test]
    fn rollback_restores_kernel_sampling_state() {
        let mut group = PerfGroup::new(PerfGroupOptions {
            include_kernel: true,
            ..TEST_OPTIONS
        })
        .expect("create perf group");
        let pending = PendingEvents {
            kernel_excluded: true,
            ..PendingEvents::default()
        };

        let opened = group.register_pending(pending).expect("register events");
        assert!(!group.kernel_enabled());

        group.rollback_open(opened);

        assert!(group.kernel_enabled());
    }

    fn perf_open_can_be_skipped(err: &io::Error) -> bool {
        matches!(
            err.kind(),
            io::ErrorKind::PermissionDenied | io::ErrorKind::Unsupported
        ) || matches!(err.raw_os_error(), Some(libc::ENOSYS | libc::EOPNOTSUPP))
    }

    #[test]
    fn task_inheritance_follows_options() {
        let mut group = PerfGroup::new(TEST_OPTIONS).expect("create perf group");

        assert_eq!(group.task_inheritance(), TaskInheritance::Threads);

        group.inherit_child_processes = true;

        assert_eq!(group.task_inheritance(), TaskInheritance::Children);
    }

    #[test]
    fn requested_frequency_mode_preserves_requested_rate() {
        assert_eq!(
            frequency_for_kernel_max(123, FrequencyMode::Requested, Some(50)),
            123
        );
    }

    #[test]
    fn clamp_frequency_mode_uses_lower_live_kernel_cap() {
        assert_eq!(
            frequency_for_kernel_max(123, FrequencyMode::ClampToKernelMax, Some(50)),
            50
        );
        assert_eq!(
            frequency_for_kernel_max(123, FrequencyMode::ClampToKernelMax, Some(0)),
            123
        );
        assert_eq!(
            frequency_for_kernel_max(123, FrequencyMode::ClampToKernelMax, None),
            123
        );
    }

    #[test]
    fn target_pid_validation_rejects_unsafe_pids() {
        assert!(validate_target_pid(0).is_err());
        assert!(validate_target_pid(u32::MAX).is_err());
        assert!(validate_target_pid(std::process::id()).is_ok());
    }

    #[test]
    fn parses_sparse_cpu_list() {
        assert_eq!(parse_cpu_list("31"), Some(vec![31]));
        assert_eq!(
            parse_cpu_list("0-2,8,10-11"),
            Some(vec![0, 1, 2, 8, 10, 11])
        );
        assert_eq!(parse_cpu_list("5-4"), None);
    }
}
