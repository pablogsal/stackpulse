use std::fs;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use crate::Pid;

/// Result of polling a [`ProcessExitWatcher`].
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
        // SAFETY: a validated Pid identifies one process and pidfd_open takes
        // no pointer arguments.
        let raw_fd = unsafe { libc::syscall(libc::SYS_pidfd_open as libc::c_long, pid.get(), 0) };
        if raw_fd < 0 {
            return Err(crate::Error::target(io::Error::last_os_error()));
        }
        Ok(Self {
            // SAFETY: a nonnegative pidfd_open result is a newly owned file descriptor.
            pidfd: unsafe { OwnedFd::from_raw_fd(raw_fd as i32) },
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

    pub(crate) fn is_exited(&self) -> bool {
        self.exited
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

/// Send `SIGINT` to `pid` (graceful interrupt). Fails with the underlying
/// `kill(2)` error, typically `EPERM` or `ESRCH`.
///
/// # Errors
///
/// Returns [`crate::ErrorKind::TargetGone`] for `ESRCH` and preserves the
/// underlying OS error code.
pub fn interrupt_process(pid: Pid) -> crate::Result<()> {
    send_signal(pid, libc::SIGINT).map_err(crate::Error::target)
}

/// Send `SIGKILL` to `pid` (uncatchable termination).
///
/// # Errors
///
/// Returns [`crate::ErrorKind::TargetGone`] for `ESRCH` and preserves the
/// underlying OS error code.
pub fn kill_process(pid: Pid) -> crate::Result<()> {
    send_signal(pid, libc::SIGKILL).map_err(crate::Error::target)
}

fn send_signal(pid: Pid, signal: libc::c_int) -> io::Result<()> {
    // SAFETY: kill takes scalar arguments and a validated Pid cannot invoke
    // process-group or broadcast semantics.
    let rc = unsafe { libc::kill(pid.get(), signal) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
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
    fn process_exists_reports_current_and_missing_processes() {
        assert!(process_exists(pid(std::process::id() as i32)).unwrap());
        assert!(!process_exists(pid(i32::MAX)).unwrap());
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
    fn process_is_alive_propagates_pidfd_poll_failure() {
        let pid = pid(std::process::id() as i32);
        let Ok(watcher) = ProcessExitWatcher::try_new(pid) else {
            return;
        };
        let fd = watcher.pidfd.as_raw_fd();
        // SAFETY: this test deliberately invalidates its owned pidfd to verify
        // that the public liveness API reports POLLNVAL instead of guessing.
        assert_eq!(unsafe { libc::close(fd) }, 0);
        let mut watcher = Some(watcher);

        let error = process_is_alive(&mut watcher, pid).expect_err("closed pidfd must fail");
        let watcher = watcher.take().expect("poll failure retains the watcher");
        std::mem::forget(watcher);

        assert_eq!(error.kind(), crate::ErrorKind::Io);
        assert_eq!(error.raw_os_error(), Some(libc::EBADF));
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
        kill_process(pid).expect("kill child");
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
        assert!(watcher.observe_revents(libc::POLLERR).is_err());
        assert_eq!(
            watcher.observe_revents(libc::POLLHUP).unwrap(),
            ProcessExitState::Exited
        );
        assert!(watcher.is_exited());
    }

    #[test]
    fn interrupt_process_sends_sigint() {
        let mut child = SleepChild::spawn();

        interrupt_process(pid(child.pid_i32())).expect("interrupt child");
        let status = child
            .wait_timeout(Duration::from_secs(2))
            .expect("wait child")
            .expect("child exited after interrupt");

        assert_eq!(status.signal(), Some(libc::SIGINT));
    }

    #[test]
    fn kill_process_sends_sigkill() {
        let mut child = SleepChild::spawn();

        kill_process(pid(child.pid_i32())).expect("kill child");
        let status = child
            .wait_timeout(Duration::from_secs(2))
            .expect("wait child")
            .expect("child exited after kill");

        assert_eq!(status.signal(), Some(libc::SIGKILL));
    }

    #[test]
    fn missing_signal_target_has_target_gone_error_kind() {
        let error = kill_process(pid(i32::MAX)).expect_err("test PID should not exist");

        assert_eq!(error.kind(), crate::ErrorKind::TargetGone);
        assert_eq!(error.raw_os_error(), Some(libc::ESRCH));
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
