use std::fs;
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};

use crate::Pid;

/// A process identity retained by a Linux pidfd.
#[derive(Debug)]
pub struct Process {
    pid: Pid,
    watcher: ProcessExitWatcher,
}

impl Process {
    /// Open a process handle. Signals through this handle cannot target a reused PID.
    pub fn open(pid: Pid) -> crate::Result<Self> {
        Ok(Self {
            pid,
            watcher: ProcessExitWatcher::try_new(pid)?,
        })
    }

    /// Return the PID originally used to open this handle.
    pub fn pid(&self) -> Pid {
        self.pid
    }

    /// Observe whether this process has exited.
    pub fn poll(&mut self) -> crate::Result<ProcessExitState> {
        self.watcher.poll()
    }

    /// Send SIGINT to this process.
    pub fn interrupt(&self) -> crate::Result<()> {
        self.signal(libc::SIGINT)
    }

    /// Send SIGTERM to this process.
    pub fn terminate(&self) -> crate::Result<()> {
        self.signal(libc::SIGTERM)
    }

    /// Send SIGKILL to this process.
    pub fn kill(&self) -> crate::Result<()> {
        self.signal(libc::SIGKILL)
    }

    fn signal(&self, signal: libc::c_int) -> crate::Result<()> {
        send_pidfd_signal(self.watcher.pidfd.as_fd(), signal).map_err(crate::Error::target)
    }
}

/// Exit state observed through a [`Process`] handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessExitState {
    /// The pidfd has not reported process exit.
    Running,
    /// The kernel has confirmed the target has exited; subsequent polls will
    /// keep returning `Exited` without further syscalls.
    Exited,
}

/// Edge-triggered exit watcher built on `pidfd_open` + `poll`.
///
/// Holds an open `pidfd` for a target PID so the recorder can cheaply check
/// whether the target is gone without racing against PID reuse. Cheaper and
/// race-free compared to repeatedly stat-ing `/proc/<pid>`.
#[derive(Debug)]
pub struct ProcessExitWatcher {
    pidfd: OwnedFd,
    exited: bool,
}

impl ProcessExitWatcher {
    /// Open a pidfd for `pid`.
    ///
    /// This fails when `pidfd_open` is denied, for example inside a
    /// restrictive sandbox.
    ///
    /// # Errors
    ///
    /// Returns [`crate::ErrorKind::TargetGone`] when the target has exited,
    /// or the corresponding permission, unsupported, or I/O category.
    pub fn try_new(pid: Pid) -> crate::Result<Self> {
        Ok(Self {
            pidfd: open_pidfd(pid.get_u32()).map_err(crate::Error::target)?,
            exited: false,
        })
    }

    /// Non-blocking check: returns [`ProcessExitState::Exited`] once the
    /// kernel signals the pidfd is readable. Subsequent calls keep returning
    /// `Exited`. Interrupted polls are retried; other inspection failures are
    /// returned to the caller.
    ///
    /// # Errors
    ///
    /// Returns an error when the pidfd cannot be polled reliably.
    pub fn poll(&mut self) -> crate::Result<ProcessExitState> {
        if self.exited {
            return Ok(ProcessExitState::Exited);
        }
        let mut fds = libc::pollfd {
            fd: self.pidfd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let rc = poll_retry(std::slice::from_mut(&mut fds), 0)?;
        if rc > 0 {
            return Ok(self.observe_revents(fds.revents)?);
        }
        Ok(ProcessExitState::Running)
    }

    pub(crate) fn poll_fd(&self) -> Option<i32> {
        (!self.exited).then(|| self.pidfd.as_raw_fd())
    }

    pub(crate) fn observe_revents(&mut self, revents: i16) -> io::Result<ProcessExitState> {
        if (revents & (libc::POLLNVAL | libc::POLLERR)) != 0 {
            return Err(io::Error::from_raw_os_error(libc::EBADF));
        }
        if (revents & (libc::POLLIN | libc::POLLHUP)) != 0 {
            self.exited = true;
            return Ok(ProcessExitState::Exited);
        }
        Ok(ProcessExitState::Running)
    }
}

/// A process tracked by numeric PID, with a pidfd pinning its identity.
///
/// A PID cannot be recycled while its process is alive or unreaped, so a
/// PID-based read confirmed by a pidfd that has not reported exit reached this
/// process. When `pidfd_open` fails (for example `EMFILE` or a seccomp denial)
/// the process is identified by its `/proc` start time instead: exit is read
/// from `/proc`, a different or missing start time counts as exit, and
/// signals go to the numeric PID only while the start time still matches.
/// Start times have clock-tick resolution, so this fallback cannot tell apart
/// a reuse within the same tick.
#[derive(Debug)]
pub(crate) struct ProcessHandle {
    pid: Pid,
    watcher: Option<ProcessExitWatcher>,
    // Without a watcher, the start time read at open; `None` if unreadable.
    start_time: Option<u64>,
}

impl ProcessHandle {
    pub(crate) fn open(pid: Pid) -> Self {
        let watcher = ProcessExitWatcher::try_new(pid).ok();
        let start_time = match watcher {
            Some(_) => None,
            None => crate::linux::read_process_start_time(pid.get_u32()).ok(),
        };
        Self {
            pid,
            watcher,
            start_time,
        }
    }

    pub(crate) fn try_clone(&self) -> io::Result<Self> {
        let watcher = match &self.watcher {
            Some(watcher) => Some(ProcessExitWatcher {
                pidfd: watcher.pidfd.try_clone()?,
                exited: watcher.exited,
            }),
            None => None,
        };
        Ok(Self {
            pid: self.pid,
            watcher,
            start_time: self.start_time,
        })
    }

    pub(crate) fn pid(&self) -> Pid {
        self.pid
    }

    pub(crate) fn has_exited(&mut self) -> crate::Result<bool> {
        if !process_is_alive(&mut self.watcher, self.pid)? {
            return Ok(true);
        }
        Ok(self.watcher.is_none() && !self.start_time_matches()?)
    }

    /// Whether the numeric PID still has the start time read at open.
    fn start_time_matches(&self) -> io::Result<bool> {
        match crate::linux::read_process_start_time(self.pid.get_u32()) {
            Ok(current) => Ok(Some(current) == self.start_time),
            Err(err) if crate::error::is_target_gone_io(&err) => Ok(false),
            Err(err) => Err(err),
        }
    }

    pub(crate) fn signal(&self, signal: libc::c_int) -> io::Result<()> {
        if let Some(watcher) = &self.watcher {
            return send_pidfd_signal(watcher.pidfd.as_fd(), signal);
        }
        if !self.start_time_matches()? {
            return Err(io::Error::from_raw_os_error(libc::ESRCH));
        }
        // SAFETY: kill takes scalar arguments.
        if unsafe { libc::kill(self.pid.get(), signal) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Run a read through the numeric PID, then confirm this process has not
    /// exited. Fails with `ESRCH` if it has: the read may have reached a new
    /// process reusing the PID.
    pub(crate) fn read_checked<T>(
        &mut self,
        read: impl FnOnce(u32) -> io::Result<T>,
    ) -> io::Result<T> {
        let value = read(self.pid.get_u32());
        if self.has_exited()? {
            return Err(io::Error::from_raw_os_error(libc::ESRCH));
        }
        value
    }

    /// The pidfd to include in a batched exit poll, while exit is unseen.
    pub(crate) fn poll_fd(&self) -> Option<i32> {
        self.watcher.as_ref().and_then(ProcessExitWatcher::poll_fd)
    }

    /// Record a batched poll result for [`Self::poll_fd`]; true on exit.
    pub(crate) fn observe_revents(&mut self, revents: i16) -> io::Result<bool> {
        match &mut self.watcher {
            Some(watcher) => Ok(watcher.observe_revents(revents)? == ProcessExitState::Exited),
            None => Ok(false),
        }
    }
}

pub(crate) fn open_pidfd(pid: u32) -> io::Result<OwnedFd> {
    // SAFETY: pidfd_open takes scalar arguments and rejects invalid process IDs.
    let raw_fd = unsafe { libc::syscall(libc::SYS_pidfd_open as libc::c_long, pid, 0) };
    if raw_fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a nonnegative pidfd_open result is a newly owned file descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(raw_fd as i32) })
}

pub(crate) fn send_pidfd_signal(pidfd: BorrowedFd<'_>, signal: libc::c_int) -> io::Result<()> {
    // SAFETY: the borrowed pidfd is live; a null siginfo pointer requests the default signal.
    let result = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal as libc::c_long,
            pidfd.as_raw_fd(),
            signal,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        )
    };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Check process liveness through a pidfd when available, otherwise through
/// `/proc`.
///
/// This function never converts an inspection failure into an alive/dead
/// answer. A pidfd poll failure is returned instead of silently switching to
/// the PID-reuse-prone `/proc` check.
///
/// # Errors
///
/// Returns an error when pidfd or `/proc` inspection fails.
pub fn process_is_alive(watcher: &mut Option<ProcessExitWatcher>, pid: Pid) -> crate::Result<bool> {
    if let Some(active) = watcher.as_mut() {
        match active.poll() {
            Ok(ProcessExitState::Exited) => return Ok(false),
            Ok(ProcessExitState::Running) => return Ok(true),
            Err(error) => return Err(error),
        }
    }
    process_exists(pid)
}

/// Check whether a process is currently observable in `/proc`.
///
/// Returns `true` when the thread-group leader directory is present, or when
/// at least one non-leader thread is still alive (the leader can have exited
/// while siblings remain). `false` on `ENOENT`/`ESRCH`. Subject to PID reuse;
/// prefer a [`ProcessExitWatcher`] when you have a long-lived target.
///
/// # Errors
///
/// Returns an error when `/proc` exists but cannot be inspected reliably.
pub fn process_exists(pid: Pid) -> crate::Result<bool> {
    try_process_exists(pid).map_err(crate::Error::target)
}

pub(crate) fn try_process_exists(pid: Pid) -> io::Result<bool> {
    let pid = pid.get();
    let mut tasks = match fs::read_dir(format!("/proc/{pid}/task")) {
        Ok(tasks) => tasks,
        Err(err) if crate::error::is_target_gone_io(&err) => return Ok(false),
        Err(err) => return Err(err),
    };

    let mut saw_leader = false;
    for entry in &mut tasks {
        let entry = match entry {
            Ok(entry) => entry,
            Err(err) if crate::error::is_target_gone_io(&err) => return Ok(false),
            Err(err) => return Err(err),
        };
        let file_name = entry.file_name();
        let Some(file_name) = file_name.to_str() else {
            continue;
        };
        let Ok(tid) = file_name.parse::<i32>() else {
            continue;
        };
        if tid != pid {
            return Ok(true);
        }
        saw_leader = true;
    }
    Ok(saw_leader)
}

pub(crate) fn poll_retry(fds: &mut [libc::pollfd], timeout: libc::c_int) -> io::Result<i32> {
    loop {
        // SAFETY: the pointer and descriptor count describe the initialized
        // pollfd slice for the duration of the call.
        let result = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, timeout) };
        if result >= 0 {
            return Ok(result);
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EINTR) {
            return Err(error);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::SleepChild;
    use std::os::unix::process::ExitStatusExt;
    use std::time::Duration;

    fn pid(raw: i32) -> Pid {
        Pid::new(raw).expect("positive test pid")
    }

    #[test]
    fn process_handle_retains_identity_after_child_exit() {
        let mut child = SleepChild::spawn();
        let original_pid = pid(child.pid_i32());
        let mut process = Process::open(original_pid).expect("open child pidfd");
        assert_eq!(process.poll().unwrap(), ProcessExitState::Running);
        process.kill().unwrap();
        let status = child.wait_timeout(Duration::from_secs(2)).unwrap().unwrap();
        assert_eq!(status.signal(), Some(libc::SIGKILL));
        assert_eq!(process.pid(), original_pid);
        assert_eq!(process.poll().unwrap(), ProcessExitState::Exited);
        assert_eq!(
            process.kill().unwrap_err().kind(),
            crate::ErrorKind::TargetGone
        );
    }

    #[test]
    fn process_exists_reports_current_and_missing_processes() {
        assert!(process_exists(pid(std::process::id() as i32)).unwrap());
        assert!(!process_exists(pid(i32::MAX)).unwrap());
    }

    #[test]
    fn read_through_a_reusable_pid_is_rejected_once_the_pidfd_exits() {
        let mut child = SleepChild::spawn();
        let mut process = ProcessHandle::open(pid(child.pid_i32()));
        assert_eq!(process.read_checked(|_| Ok(1)).unwrap(), 1);
        process.signal(libc::SIGKILL).unwrap();
        child.wait_timeout(Duration::from_secs(2)).unwrap().unwrap();

        // Reaped, so the PID may now name another process: a read that
        // succeeds through it must not be attributed to this one.
        let error = process.read_checked(|_| Ok(1)).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::ESRCH));
    }

    #[test]
    fn handle_without_pidfd_rejects_a_pid_with_another_start_time() {
        let mut process = ProcessHandle {
            pid: pid(std::process::id() as i32),
            watcher: None,
            start_time: Some(u64::MAX),
        };

        assert!(process.has_exited().unwrap());
        let error = process.signal(0).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::ESRCH));
    }

    #[test]
    fn process_is_alive_uses_proc_fallback_without_watcher() {
        let mut watcher = None;

        assert!(process_is_alive(&mut watcher, pid(std::process::id() as i32)).unwrap());
        assert!(!process_is_alive(&mut watcher, pid(i32::MAX)).unwrap());
    }

    #[test]
    fn process_is_alive_uses_pidfd_watcher_when_available() {
        let pid = pid(std::process::id() as i32);
        let Ok(watcher) = ProcessExitWatcher::try_new(pid) else {
            return;
        };
        let mut watcher = Some(watcher);

        assert!(process_is_alive(&mut watcher, pid).unwrap());
        assert!(watcher.is_some());
    }

    #[test]
    fn pidfd_watcher_observes_child_exit_when_available() {
        let mut child = SleepChild::spawn();
        let pid = pid(child.pid_i32());
        let Ok(mut watcher) = ProcessExitWatcher::try_new(pid) else {
            return;
        };

        assert_eq!(
            watcher.poll().expect("poll live child"),
            ProcessExitState::Running
        );
        Process::open(pid).unwrap().kill().expect("kill child");
        let _ = child
            .wait_timeout(Duration::from_secs(2))
            .expect("wait child")
            .expect("child exited after kill");

        assert_eq!(
            watcher.poll().expect("poll exited child"),
            ProcessExitState::Exited
        );
        assert_eq!(
            watcher.poll().expect("poll cached exited child"),
            ProcessExitState::Exited
        );
        let mut watcher = Some(watcher);
        assert!(!process_is_alive(&mut watcher, pid).unwrap());
    }

    #[test]
    fn pidfd_revents_decode_exit_and_error_states() {
        let pid = pid(std::process::id() as i32);
        let Ok(mut watcher) = ProcessExitWatcher::try_new(pid) else {
            return;
        };

        assert_eq!(
            watcher.observe_revents(0).unwrap(),
            ProcessExitState::Running
        );
        assert_eq!(
            watcher
                .observe_revents(libc::POLLERR)
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EBADF)
        );
        let mut fds = [libc::pollfd {
            fd: i32::MAX,
            events: libc::POLLIN,
            revents: 0,
        }];
        assert_eq!(poll_retry(&mut fds, 0).unwrap(), 1);
        assert_eq!(fds[0].revents, libc::POLLNVAL);
        let error = crate::Error::from(watcher.observe_revents(fds[0].revents).unwrap_err());
        assert_eq!(error.kind(), crate::ErrorKind::Io);
        assert_eq!(error.raw_os_error(), Some(libc::EBADF));
        assert_eq!(watcher.poll().unwrap(), ProcessExitState::Running);
        assert_eq!(
            watcher.observe_revents(libc::POLLHUP).unwrap(),
            ProcessExitState::Exited
        );
        assert_eq!(watcher.poll().unwrap(), ProcessExitState::Exited);
    }

    #[test]
    fn interrupt_process_sends_sigint() {
        let mut child = SleepChild::spawn();

        Process::open(pid(child.pid_i32()))
            .unwrap()
            .interrupt()
            .expect("interrupt child");
        let status = child
            .wait_timeout(Duration::from_secs(2))
            .expect("wait child")
            .expect("child exited after interrupt");

        assert_eq!(status.signal(), Some(libc::SIGINT));
    }

    #[test]
    fn kill_process_sends_sigkill() {
        let mut child = SleepChild::spawn();

        Process::open(pid(child.pid_i32()))
            .unwrap()
            .kill()
            .expect("kill child");
        let status = child
            .wait_timeout(Duration::from_secs(2))
            .expect("wait child")
            .expect("child exited after kill");

        assert_eq!(status.signal(), Some(libc::SIGKILL));
    }

    #[test]
    fn missing_pidfd_target_has_target_gone_error_kind() {
        let error =
            ProcessExitWatcher::try_new(pid(i32::MAX)).expect_err("test PID should not exist");

        assert_eq!(error.kind(), crate::ErrorKind::TargetGone);
        assert!(matches!(
            error.raw_os_error(),
            Some(libc::ENOENT | libc::ESRCH)
        ));
    }
}
