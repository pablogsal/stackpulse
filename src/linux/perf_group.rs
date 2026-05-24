use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Debug;
use std::os::unix::io::RawFd;
use std::time::Duration;
use std::{fs, io};

use mio::unix::SourceFd;
use mio::{Events, Interest, Poll, Token};

use super::perf_event::{EventRef, EventSource, Perf, PerfOptions, TaskInheritance};
use super::sorter::EventSorter;

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

pub struct PerfGroup {
    event_sorter: EventSorter<RawFd, u64, EventRef>,
    members: BTreeMap<RawFd, Member>,
    ready_fds: BTreeSet<RawFd>,
    poll: Poll,
    poll_events: Events,
    frequency: u32,
    stack_size: u32,
    regs_mask: u64,
    event_source: EventSource,
    include_kernel: bool,
    inherit_child_processes: bool,
    tracked_threads: BTreeSet<u32>,
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

fn task_gone(err: &io::Error) -> bool {
    err.kind() == io::ErrorKind::NotFound || err.raw_os_error() == Some(libc::ESRCH)
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
            tracked_threads: BTreeSet::new(),
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
        let stopped_process = if attach_mode == AttachMode::StopAttachEnableResume {
            Some(StoppedProcess::new(pid)?)
        } else {
            None
        };
        let threads = get_threads(pid)?;
        self.tracked_threads.insert(pid);
        self.tracked_threads.extend(threads.iter().copied());
        let cpu_count = std::thread::available_parallelism().map_or(1, usize::from);
        let per_thread_only =
            !self.inherit_child_processes && cpu_count * (threads.len() + 1) >= 1000;
        let leader_inheritance = if per_thread_only {
            TaskInheritance::None
        } else {
            self.task_inheritance()
        };

        // Per-cpu fds on the leader; per-(cpu,tid) on threads unless fan-out explodes.
        let mut perf_events =
            Vec::with_capacity(cpu_count.saturating_add(cpu_count * threads.len()));
        for cpu in 0..cpu_count as u32 {
            perf_events.push(self.open_perf(pid, Some(cpu), attach_mode, leader_inheritance)?);
        }
        if perf_events
            .iter()
            .any(|perf| perf.inherit() != TaskInheritance::None)
        {
            self.inheriting_threads.insert(pid);
        }
        for &tid in &threads {
            if let Some(thread_events) =
                self.open_thread_perfs(tid, cpu_count, per_thread_only, attach_mode)?
            {
                if thread_events
                    .iter()
                    .any(|perf| perf.inherit() != TaskInheritance::None)
                {
                    self.inheriting_threads.insert(tid);
                }
                perf_events.extend(thread_events);
            }
        }

        for perf in perf_events {
            self.register_perf(perf)?;
        }
        if let Some(stopped_process) = stopped_process {
            self.stopped_processes.push(stopped_process);
        }
        Ok(())
    }

    pub fn refresh_threads(&mut self, pid: u32) -> io::Result<()> {
        if !self.inheriting_threads.is_empty() {
            return Ok(());
        }
        let threads = match get_threads(pid) {
            Ok(threads) => threads,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(err) => return Err(err),
        };
        let live_threads: BTreeSet<_> = threads.iter().copied().collect();
        self.tracked_threads
            .retain(|&tid| tid == pid || live_threads.contains(&tid));
        let cpu_count = std::thread::available_parallelism().map_or(1, usize::from);
        let per_thread_only =
            !self.inherit_child_processes && cpu_count * (threads.len() + 1) >= 1000;
        let mut perf_events = Vec::new();
        for tid in threads {
            if !self.tracked_threads.insert(tid) {
                continue;
            }
            match self.open_thread_perfs(
                tid,
                cpu_count,
                per_thread_only,
                AttachMode::StopAttachEnableResume,
            )? {
                Some(thread_events) => {
                    if thread_events
                        .iter()
                        .any(|perf| perf.inherit() != TaskInheritance::None)
                    {
                        self.inheriting_threads.insert(tid);
                    }
                    perf_events.extend(thread_events);
                }
                None => {
                    self.tracked_threads.remove(&tid);
                }
            }
        }
        for perf in &perf_events {
            perf.enable()?;
        }
        for perf in perf_events {
            self.register_perf(perf)?;
        }
        Ok(())
    }

    pub fn open_forked_threads(&mut self, thread_forks: &[(u32, u32)]) -> io::Result<()> {
        if thread_forks.is_empty() {
            return Ok(());
        }

        let cpu_count = std::thread::available_parallelism().map_or(1, usize::from);
        let per_thread_only = !self.inherit_child_processes
            && cpu_count.saturating_mul(self.tracked_threads.len().saturating_add(1)) >= 1000;
        let mut perf_events = Vec::new();

        for &(tid, parent_tid) in thread_forks {
            if !self.tracked_threads.insert(tid) {
                continue;
            }
            if self.inheriting_threads.contains(&parent_tid) {
                self.inheriting_threads.insert(tid);
                continue;
            }

            match self.open_thread_perfs(
                tid,
                cpu_count,
                per_thread_only,
                AttachMode::StopAttachEnableResume,
            )? {
                Some(thread_events) => {
                    if thread_events
                        .iter()
                        .any(|perf| perf.inherit() != TaskInheritance::None)
                    {
                        self.inheriting_threads.insert(tid);
                    }
                    perf_events.extend(thread_events);
                }
                None => {
                    self.tracked_threads.remove(&tid);
                }
            }
        }

        for perf in &perf_events {
            perf.enable()?;
        }
        for perf in perf_events {
            self.register_perf(perf)?;
        }
        Ok(())
    }

    pub fn open_forked_processes(&mut self, process_forks: &[(u32, u32)]) -> io::Result<()> {
        if !self.inherit_child_processes {
            return Ok(());
        }

        for &(pid, parent_tid) in process_forks {
            if self.inheriting_threads.contains(&parent_tid) || self.tracked_threads.contains(&pid)
            {
                continue;
            }
            match self.open_process(pid, AttachMode::StopAttachEnableResume) {
                Ok(()) => self.enable()?,
                Err(err) if task_gone(&err) => {}
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
        cpu_count: usize,
        per_thread_only: bool,
        attach_mode: AttachMode,
    ) -> io::Result<Option<Vec<Perf>>> {
        let mut perf_events = Vec::new();
        if per_thread_only {
            match self.open_perf(tid, None, attach_mode, TaskInheritance::None) {
                Ok(perf) => perf_events.push(perf),
                Err(err) if task_gone(&err) => return Ok(None),
                Err(err) => return Err(err),
            }
        } else {
            for cpu in 0..cpu_count as u32 {
                match self.open_perf(tid, Some(cpu), attach_mode, self.task_inheritance()) {
                    Ok(perf) => perf_events.push(perf),
                    Err(err) if task_gone(&err) => return Ok(None),
                    Err(err) => return Err(err),
                }
            }
        }
        Ok(Some(perf_events))
    }

    fn register_perf(&mut self, perf: Perf) -> io::Result<()> {
        let fd = perf.fd();
        self.poll.registry().register(
            &mut SourceFd(&fd),
            Token(fd as usize),
            Interest::READABLE,
        )?;
        self.members.insert(
            fd,
            Member {
                perf,
                is_closed: false,
            },
        );
        Ok(())
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
            sample_callchain: self.include_kernel,
            exclude_user_callchain: self.include_kernel,
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

    pub fn has_pending_events(&self) -> bool {
        !self.ready_fds.is_empty()
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
        let ready_fds = std::mem::take(&mut self.ready_fds);
        let consume_all = ready_fds.is_empty();
        loop {
            for (&fd, member) in &mut self.members {
                if !consume_all && !ready_fds.contains(&fd) && !member.is_closed {
                    continue;
                }
                self.event_sorter.begin_group(fd);
                while let Some(ev) = self.event_sorter.pop() {
                    cb(ev);
                }
                let mut consumed_record = false;
                self.event_sorter
                    .extend(member.perf.iter().filter_map(|event| {
                        consumed_record = true;
                        Some((event.timestamp()?, event))
                    }));
                if member.is_closed && !consumed_record {
                    fds_to_remove.push(fd);
                }
            }
            self.event_sorter.advance_round();
            while let Some(ev) = self.event_sorter.pop() {
                cb(ev);
            }
            for fd in fds_to_remove.drain(..) {
                // Deregister can fail on already-closed fds; drop member anyway.
                let _ = self.poll.registry().deregister(&mut SourceFd(&fd));
                self.members.remove(&fd);
            }
            if !self.event_sorter.has_more() {
                break;
            }
        }
    }
}
