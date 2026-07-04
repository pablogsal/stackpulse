use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Debug;
use std::os::unix::io::RawFd;
use std::time::Duration;
use std::{fs, io};

use mio::unix::SourceFd;
use mio::{Events, Interest, Poll, Token};
use rustc_hash::{FxHashMap, FxHashSet};

use perf_event_open::sample::record::UnsafeParser;

use super::perf_event::{
    EventRef, EventSource, OwnedEventRecord, Perf, PerfOptions, TaskInheritance,
};
use super::process_gone_error;
use super::sorter::EventSorter;

const LARGE_PERF_EVENT_COUNT: usize = 1000;

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

struct StoppedProcess(u32);

impl StoppedProcess {
    fn new(pid: u32) -> io::Result<Self> {
        if unsafe { libc::kill(pid as _, libc::SIGSTOP) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(pid))
    }
}

impl Drop for StoppedProcess {
    fn drop(&mut self) {
        unsafe { libc::kill(self.0 as _, libc::SIGCONT) };
    }
}

struct Member {
    perf: Perf,
    is_closed: bool,
}

struct ThreadPerfEvents {
    events: Vec<Perf>,
    inherits: bool,
}

impl ThreadPerfEvents {
    fn with_capacity(capacity: usize) -> Self {
        Self {
            events: Vec::with_capacity(capacity),
            inherits: false,
        }
    }

    fn push(&mut self, perf: Perf) {
        self.inherits |= perf.inherit().is_enabled();
        self.events.push(perf);
    }
}

pub struct PerfGroup {
    event_sorter: EventSorter<RawFd, u64, OwnedEventRecord>,
    // All members share one parser configuration (they are opened from the
    // same option template), captured when the first member is registered
    // and used to re-read buffered sample records at dispatch.
    parser: Option<UnsafeParser>,
    members: BTreeMap<RawFd, Member>,
    ready_fds: BTreeSet<RawFd>,
    poll: Poll,
    poll_events: Events,
    frequency: u32,
    stack_size: u32,
    regs_mask: u64,
    event_source: EventSource,
    include_kernel: bool,
    pub(crate) inherit_child_processes: bool,
    // tid -> owning pid, so per-process reconciliation (refresh_threads) can
    // tell foreign threads apart from this process's exited ones.
    tracked_threads: BTreeMap<u32, u32>,
    inheriting_threads: BTreeSet<u32>,
    stopped_processes: Vec<StoppedProcess>,
}

fn get_threads(pid: u32) -> io::Result<Vec<u32>> {
    Ok(fs::read_dir(format!("/proc/{pid}/task"))?
        .flatten()
        .filter_map(|e| e.file_name().to_str()?.parse::<u32>().ok())
        .filter(|&tid| tid != pid)
        .collect())
}

/// How recording should attach to a process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttachMode {
    /// Attach before a not-yet-executed child is allowed to run.
    AttachWithEnableOnExec,
    /// Briefly stop an already-running process, attach, then resume it.
    StopAttachEnableResume,
}

#[derive(Debug, Clone, Copy)]
pub struct PerfGroupOptions {
    pub frequency: u32,
    pub stack_size: u32,
    pub event_source: EventSource,
    pub regs_mask: u64,
    pub include_kernel: bool,
    pub inherit_child_processes: bool,
}

impl PerfGroup {
    pub fn new(
        frequency: u32,
        stack_size: u32,
        regs_mask: u64,
        event_source: EventSource,
        include_kernel: bool,
        inherit_child_processes: bool,
    ) -> io::Result<Self> {
        Ok(PerfGroup {
            event_sorter: EventSorter::new(),
            parser: None,
            members: Default::default(),
            ready_fds: BTreeSet::new(),
            poll: Poll::new()?,
            poll_events: Events::with_capacity(16),
            frequency,
            stack_size,
            event_source,
            regs_mask,
            include_kernel,
            inherit_child_processes,
            tracked_threads: BTreeMap::new(),
            inheriting_threads: BTreeSet::new(),
            stopped_processes: Vec::new(),
        })
    }

    pub fn open(pid: u32, attach_mode: AttachMode, options: PerfGroupOptions) -> io::Result<Self> {
        let mut group = PerfGroup::new(
            options.frequency,
            options.stack_size,
            options.regs_mask,
            options.event_source,
            options.include_kernel,
            options.inherit_child_processes,
        )?;
        group.open_process(pid, attach_mode)?;
        Ok(group)
    }

    pub fn open_process(&mut self, pid: u32, attach_mode: AttachMode) -> io::Result<()> {
        validate_target_pid(pid)?;
        let stopped_process = if attach_mode == AttachMode::StopAttachEnableResume {
            Some(StoppedProcess::new(pid)?)
        } else {
            None
        };
        let threads = get_threads(pid)?;
        let cpu_ids = online_cpu_ids();
        let cpu_count = cpu_ids.len();
        let task_count = threads.len().saturating_add(1);
        let per_thread_only = self.use_per_thread_only_events(cpu_count, task_count);
        let leader_inheritance = if per_thread_only {
            TaskInheritance::None
        } else {
            self.task_inheritance()
        };

        // Per-cpu fds on the leader; per-(cpu,tid) on threads unless fan-out explodes.
        let mut perf_events = Vec::with_capacity(cpu_count.saturating_add(
            thread_perf_event_capacity(cpu_count, threads.len(), per_thread_only),
        ));
        let mut inheriting_threads = Vec::new();
        let mut leader_inherits = false;
        for &cpu in &cpu_ids {
            let perf = self.open_perf(pid, Some(cpu), attach_mode, leader_inheritance)?;
            leader_inherits |= perf.inherit().is_enabled();
            perf_events.push(perf);
        }
        if leader_inherits {
            inheriting_threads.push(pid);
        }
        for &tid in &threads {
            if let Some(thread_perfs) = self.open_thread_perfs(tid, per_thread_only, attach_mode)? {
                if thread_perfs.inherits {
                    inheriting_threads.push(tid);
                }
                perf_events.extend(thread_perfs.events);
            }
        }

        self.register_perfs(perf_events)?;
        self.tracked_threads.insert(pid, pid);
        self.tracked_threads
            .extend(threads.into_iter().map(|tid| (tid, pid)));
        self.inheriting_threads.extend(inheriting_threads);
        if let Some(stopped_process) = stopped_process {
            self.stopped_processes.push(stopped_process);
        }
        Ok(())
    }

    pub fn refresh_threads(&mut self, pid: u32) -> io::Result<()> {
        if !self.inheriting_threads.is_empty() {
            return Ok(());
        }
        let mut threads = match get_threads(pid) {
            Ok(threads) => threads,
            Err(err) if process_gone_error(&err) => return Ok(()),
            Err(err) => return Err(err),
        };
        threads.sort_unstable();
        let task_count = threads.len().saturating_add(1);
        // Only reconcile this process's threads; other attached processes'
        // tids are absent from /proc/<pid>/task and must survive.
        self.tracked_threads.retain(|&tid, &mut owner| {
            owner != pid || tid == pid || threads.binary_search(&tid).is_ok()
        });
        let new_threads: Vec<_> = threads
            .into_iter()
            .filter(|tid| !self.tracked_threads.contains_key(tid))
            .collect();
        let cpu_ids = online_cpu_ids();
        let cpu_count = cpu_ids.len();
        let per_thread_only = self.use_per_thread_only_events(cpu_count, task_count);
        let mut perf_events = Vec::with_capacity(thread_perf_event_capacity(
            cpu_count,
            new_threads.len(),
            per_thread_only,
        ));
        let mut tracked_threads = Vec::with_capacity(new_threads.len());
        let mut inheriting_threads = Vec::new();
        for tid in new_threads {
            if let Some(thread_perfs) =
                self.open_thread_perfs(tid, per_thread_only, AttachMode::StopAttachEnableResume)?
            {
                if thread_perfs.inherits {
                    inheriting_threads.push(tid);
                }
                perf_events.extend(thread_perfs.events);
                tracked_threads.push(tid);
            }
        }
        self.enable_and_register_perfs(perf_events)?;
        self.tracked_threads
            .extend(tracked_threads.into_iter().map(|tid| (tid, pid)));
        self.inheriting_threads.extend(inheriting_threads);
        Ok(())
    }

    /// Open counters for freshly forked threads, given as
    /// `(tid, owning pid, parent tid)` triples.
    pub fn open_forked_threads(&mut self, thread_forks: &[(u32, u32, u32)]) -> io::Result<()> {
        if thread_forks.is_empty() {
            return Ok(());
        }

        let cpu_count = online_cpu_ids().len().max(1);
        let task_count = self
            .tracked_threads
            .len()
            .saturating_add(thread_forks.len());
        let per_thread_only = self.use_per_thread_only_events(cpu_count, task_count);
        let mut perf_events = Vec::with_capacity(thread_perf_event_capacity(
            cpu_count,
            thread_forks.len(),
            per_thread_only,
        ));
        let mut tracked_threads =
            FxHashMap::with_capacity_and_hasher(thread_forks.len(), Default::default());
        let mut inheriting_threads =
            FxHashSet::with_capacity_and_hasher(thread_forks.len(), Default::default());

        for &(tid, owner, parent_tid) in thread_forks {
            if self.tracked_threads.contains_key(&tid) || tracked_threads.contains_key(&tid) {
                continue;
            }
            if self.inheriting_threads.contains(&parent_tid)
                || inheriting_threads.contains(&parent_tid)
            {
                tracked_threads.insert(tid, owner);
                inheriting_threads.insert(tid);
                continue;
            }

            if let Some(thread_perfs) =
                self.open_thread_perfs(tid, per_thread_only, AttachMode::StopAttachEnableResume)?
            {
                if thread_perfs.inherits {
                    inheriting_threads.insert(tid);
                }
                perf_events.extend(thread_perfs.events);
                tracked_threads.insert(tid, owner);
            }
        }

        self.enable_and_register_perfs(perf_events)?;
        self.tracked_threads.extend(tracked_threads);
        self.inheriting_threads.extend(inheriting_threads);
        Ok(())
    }

    pub fn open_forked_processes(&mut self, process_forks: &[(u32, u32)]) -> io::Result<()> {
        if !self.inherit_child_processes {
            return Ok(());
        }

        for &(pid, parent_tid) in process_forks {
            if self.inheriting_threads.contains(&parent_tid)
                || self.tracked_threads.contains_key(&pid)
            {
                self.tracked_threads.insert(pid, pid);
                if self.inheriting_threads.contains(&parent_tid) {
                    self.inheriting_threads.insert(pid);
                }
                continue;
            }
            match self.open_process(pid, AttachMode::StopAttachEnableResume) {
                Ok(()) => {
                    if let Err(err) = self.enable() {
                        self.resume_stopped_processes();
                        return Err(err);
                    }
                }
                Err(err) if process_gone_error(&err) => {}
                Err(err) => return Err(err),
            }
        }

        Ok(())
    }

    pub fn remove_thread(&mut self, tid: u32) {
        self.tracked_threads.remove(&tid);
        self.inheriting_threads.remove(&tid);
    }

    fn open_thread_perfs(
        &self,
        tid: u32,
        per_thread_only: bool,
        attach_mode: AttachMode,
    ) -> io::Result<Option<ThreadPerfEvents>> {
        let cpu_ids = online_cpu_ids();
        let mut perf_events = ThreadPerfEvents::with_capacity(thread_perf_event_capacity(
            cpu_ids.len(),
            1,
            per_thread_only,
        ));
        if per_thread_only {
            let Some(perf) =
                self.try_open_thread_perf(tid, None, attach_mode, TaskInheritance::None)?
            else {
                return Ok(None);
            };
            perf_events.push(perf);
        } else {
            for cpu in cpu_ids {
                let Some(perf) = self.try_open_thread_perf(
                    tid,
                    Some(cpu),
                    attach_mode,
                    self.task_inheritance(),
                )?
                else {
                    return Ok(None);
                };
                perf_events.push(perf);
            }
        }
        Ok(Some(perf_events))
    }

    fn try_open_thread_perf(
        &self,
        tid: u32,
        cpu: Option<u32>,
        attach_mode: AttachMode,
        inherit: TaskInheritance,
    ) -> io::Result<Option<Perf>> {
        match self.open_perf(tid, cpu, attach_mode, inherit) {
            Ok(perf) => Ok(Some(perf)),
            Err(err) if process_gone_error(&err) => Ok(None),
            Err(err) => Err(err),
        }
    }

    fn register_perf(&mut self, perf: Perf) -> io::Result<()> {
        let fd = perf.fd();
        self.poll.registry().register(
            &mut SourceFd(&fd),
            Token(fd as usize),
            Interest::READABLE,
        )?;
        if self.parser.is_none() {
            self.parser = Some(perf.parser().clone());
        }
        self.members.insert(
            fd,
            Member {
                perf,
                is_closed: false,
            },
        );
        Ok(())
    }

    fn register_perfs(&mut self, perf_events: Vec<Perf>) -> io::Result<()> {
        let mut registered_fds = Vec::with_capacity(perf_events.len());
        for perf in perf_events {
            let fd = perf.fd();
            if let Err(err) = self.register_perf(perf) {
                for fd in registered_fds {
                    self.remove_member_fd(fd);
                }
                return Err(err);
            }
            registered_fds.push(fd);
        }
        Ok(())
    }

    fn enable_and_register_perfs(&mut self, perf_events: Vec<Perf>) -> io::Result<()> {
        for perf in &perf_events {
            perf.enable()?;
        }
        self.register_perfs(perf_events)
    }

    fn remove_member_fd(&mut self, fd: RawFd) {
        let _ = self.poll.registry().deregister(&mut SourceFd(&fd));
        self.members.remove(&fd);
        self.ready_fds.remove(&fd);
    }

    fn open_perf(
        &self,
        pid: u32,
        cpu: Option<u32>,
        attach_mode: AttachMode,
        inherit: TaskInheritance,
    ) -> io::Result<Perf> {
        PerfOptions {
            pid,
            cpu,
            frequency: self.frequency as u64,
            stack_size: self.stack_size,
            reg_mask: self.regs_mask,
            event_source: self.event_source,
            inherit,
            enable_on_exec: attach_mode == AttachMode::AttachWithEnableOnExec,
            include_kernel: self.include_kernel,
            sample_callchain: true,
            exclude_user_callchain: false,
            exclude_kernel_callchain: !self.include_kernel,
        }
        .open()
    }

    fn task_inheritance(&self) -> TaskInheritance {
        if self.inherit_child_processes {
            TaskInheritance::Children
        } else {
            TaskInheritance::Threads
        }
    }

    #[must_use]
    fn use_per_thread_only_events(&self, cpu_count: usize, task_count: usize) -> bool {
        !self.inherit_child_processes && perf_event_count_is_large(cpu_count, task_count)
    }

    pub fn has_pending_events(&self) -> bool {
        !self.ready_fds.is_empty() || self.event_sorter.has_more()
    }

    pub fn enable(&mut self) -> io::Result<()> {
        for member in self.members.values_mut() {
            member.perf.enable()?;
        }
        self.stopped_processes.clear();
        Ok(())
    }

    pub fn resume_stopped_processes(&mut self) {
        self.stopped_processes.clear();
    }

    pub fn disable(&mut self) {
        for member in self.members.values_mut() {
            let _ = member.perf.disable();
        }
    }

    pub fn wait(&mut self) -> io::Result<()> {
        // EINTR is normal (signals: e.g. parent's Ctrl-C handler).
        if let Err(err) = self
            .poll
            .poll(&mut self.poll_events, Some(Duration::from_millis(100)))
        {
            return if err.kind() == io::ErrorKind::Interrupted {
                Ok(())
            } else {
                Err(err)
            };
        }
        for ev in self.poll_events.iter() {
            let fd = ev.token().0 as RawFd;
            if ev.is_readable() {
                self.ready_fds.insert(fd);
            }
            if ev.is_read_closed() {
                if let Some(member) = self.members.get_mut(&fd) {
                    member.is_closed = true;
                }
            }
        }
        Ok(())
    }

    pub fn consume_events(&mut self, cb: &mut impl FnMut(EventRef)) {
        let mut fds_to_remove = Vec::new();
        self.ready_fds.clear();
        // Destructure so the consume closure can push into the sorter while
        // the member is borrowed.
        let Self {
            event_sorter,
            parser,
            members,
            ..
        } = self;
        // Any buffered event came from a registered member, which captured
        // the parser.
        let parser = parser.as_ref();
        let dispatch_parser = || parser.expect("parser captured at perf registration");
        // Drain every ring buffer on every pass. Poll readiness is only a wakeup
        // hint; using it as a filter can let older mmap/fork records sit behind
        // newer samples from another fd, which breaks timestamp-ordered unwinding.
        for (&fd, member) in members.iter_mut() {
            event_sorter.begin_group(fd);
            let mut consumed_record = false;
            member.perf.consume_owned_events(&mut |event| {
                consumed_record = true;
                event_sorter.push(event.timestamp().unwrap_or(0), event);
            });
            while let Some(event) = event_sorter.pop() {
                event.dispatch(dispatch_parser(), cb);
            }
            if member.is_closed && !consumed_record {
                fds_to_remove.push(fd);
            }
        }
        event_sorter.advance_round();
        while let Some(event) = event_sorter.pop() {
            event.dispatch(dispatch_parser(), cb);
        }
        for fd in fds_to_remove {
            self.remove_member_fd(fd);
        }
    }

    pub fn flush_events(&mut self, cb: &mut impl FnMut(EventRef)) {
        self.consume_events(cb);
        while let Some(event) = self.event_sorter.force_pop() {
            let parser = self
                .parser
                .as_ref()
                .expect("parser captured at perf registration");
            event.dispatch(parser, cb);
        }
    }
}

#[must_use]
fn perf_event_count_is_large(cpu_count: usize, task_count: usize) -> bool {
    cpu_count.saturating_mul(task_count) >= LARGE_PERF_EVENT_COUNT
}

#[must_use]
fn online_cpu_ids() -> Vec<u32> {
    fs::read_to_string("/sys/devices/system/cpu/online")
        .ok()
        .and_then(|list| parse_cpu_list(list.trim()))
        .filter(|ids| !ids.is_empty())
        .unwrap_or_else(fallback_cpu_ids)
}

fn parse_cpu_list(list: &str) -> Option<Vec<u32>> {
    let mut cpus = Vec::new();
    for part in list
        .split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
    {
        if let Some((start, end)) = part.split_once('-') {
            let start = start.parse::<u32>().ok()?;
            let end = end.parse::<u32>().ok()?;
            if start > end {
                return None;
            }
            cpus.extend(start..=end);
        } else {
            cpus.push(part.parse::<u32>().ok()?);
        }
    }
    (!cpus.is_empty()).then_some(cpus)
}

fn fallback_cpu_ids() -> Vec<u32> {
    let cpu_count = std::thread::available_parallelism().map_or(1, usize::from);
    (0..cpu_count as u32).collect()
}

#[must_use]
fn thread_perf_event_capacity(
    cpu_count: usize,
    thread_count: usize,
    per_thread_only: bool,
) -> usize {
    if per_thread_only {
        thread_count
    } else {
        cpu_count.saturating_mul(thread_count)
    }
}

#[cfg(test)]
mod tests {
    use super::super::perf_event::MAX_SAMPLE_USER_STACK;
    use super::*;

    #[test]
    fn failed_open_process_does_not_track_process() {
        let pid = std::process::id();
        let mut group = PerfGroup::new(
            1,
            MAX_SAMPLE_USER_STACK + 1,
            0,
            EventSource::SwCpuClock,
            false,
            true,
        )
        .expect("create perf group");

        let err = group
            .open_process(pid, AttachMode::AttachWithEnableOnExec)
            .expect_err("invalid stack size should fail before opening perf events");

        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(group.tracked_threads.is_empty());
        assert!(group.inheriting_threads.is_empty());
        assert!(group.members.is_empty());
    }

    #[test]
    fn inherited_forked_process_is_tracked_without_opening_new_fds() {
        let mut group = PerfGroup::new(1, 0, 0, EventSource::SwCpuClock, false, true)
            .expect("create perf group");
        group.tracked_threads.insert(100, 100);
        group.inheriting_threads.insert(100);

        group
            .open_forked_processes(&[(200, 100)])
            .expect("track inherited child process");

        assert!(group.tracked_threads.contains_key(&200));
        assert!(group.inheriting_threads.contains(&200));
        assert!(group.members.is_empty());
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
