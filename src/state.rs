use std::fs;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

/// Result of polling a [`ProcessExitWatcher`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessExitState {
    /// The target is still alive, or its liveness could not be determined
    /// (poll returned no events). Callers should treat this as "keep going".
    RunningOrUnknown,
    /// The kernel has confirmed the target has exited; subsequent polls will
    /// keep returning `Exited` without further syscalls.
    Exited,
}

/// Edge-triggered exit watcher built on `pidfd_open` + `poll`.
///
/// Holds an open `pidfd` for a target PID so the recorder can cheaply check
/// whether the target is gone without racing against PID reuse. Cheaper and
/// race-free compared to repeatedly stat-ing `/proc/<pid>`.
pub struct ProcessExitWatcher {
    pidfd: OwnedFd,
    exited: bool,
}

impl ProcessExitWatcher {
    /// Open a pidfd for `pid`. Fails if `pid` is non-positive or if
    /// `pidfd_open` is unavailable or denied (e.g. older kernels, sandbox).
    pub fn try_new(pid: i32) -> io::Result<Self> {
        if pid <= 0 {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("pid {pid}"),
            ));
        }
        let raw_fd = unsafe { libc::syscall(libc::SYS_pidfd_open as libc::c_long, pid, 0) };
        if raw_fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            pidfd: unsafe { OwnedFd::from_raw_fd(raw_fd as i32) },
            exited: false,
        })
    }

    /// Non-blocking check: returns [`ProcessExitState::Exited`] once the
    /// kernel signals the pidfd is readable. Subsequent calls keep returning
    /// `Exited`; `EINTR` is mapped to `RunningOrUnknown` so callers can retry.
    pub fn poll(&mut self) -> io::Result<ProcessExitState> {
        if self.exited {
            return Ok(ProcessExitState::Exited);
        }
        let mut fds = libc::pollfd {
            fd: self.pidfd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let rc = unsafe { libc::poll(&mut fds, 1, 0) };
        if rc < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                return Ok(ProcessExitState::RunningOrUnknown);
            }
            return Err(err);
        }
        if rc > 0 && (fds.revents & (libc::POLLIN | libc::POLLHUP)) != 0 {
            self.exited = true;
            return Ok(ProcessExitState::Exited);
        }
        Ok(ProcessExitState::RunningOrUnknown)
    }
}

/// Try to build a [`ProcessExitWatcher`], returning `None` on any failure.
/// Convenience wrapper for callers that fall back to `/proc` polling when
/// `pidfd_open` is unavailable.
pub fn try_new_exit_watcher(pid: i32) -> Option<ProcessExitWatcher> {
    ProcessExitWatcher::try_new(pid).ok()
}

/// Combined liveness check: prefers the pidfd watcher (race-free) and falls
/// back to [`process_exists`] when no watcher is available or the poll errors.
pub fn process_is_alive(watcher: &mut Option<ProcessExitWatcher>, pid: i32) -> bool {
    if let Some(active) = watcher.as_mut() {
        match active.poll() {
            Ok(ProcessExitState::Exited) => return false,
            Ok(ProcessExitState::RunningOrUnknown) => return true,
            Err(_) => *watcher = None,
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
pub fn process_exists(pid: i32) -> bool {
    let mut tasks = match fs::read_dir(format!("/proc/{pid}/task")) {
        Ok(tasks) => tasks,
        Err(err) => return !matches!(err.raw_os_error(), Some(libc::ENOENT | libc::ESRCH)),
    };

    let mut saw_leader = false;
    for entry in &mut tasks {
        let Ok(entry) = entry else {
            continue;
        };
        let Some(file_name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let Ok(tid) = file_name.parse::<i32>() else {
            continue;
        };
        if tid != pid {
            return true;
        }
        saw_leader = true;
    }
    saw_leader
}

/// Send `SIGINT` to `pid` (graceful interrupt). Fails with the underlying
/// `kill(2)` error, typically `EPERM` or `ESRCH`.
pub fn interrupt_process(pid: i32) -> io::Result<()> {
    send_signal(pid, libc::SIGINT)
}

/// Send `SIGKILL` to `pid` (uncatchable termination).
pub fn kill_process(pid: i32) -> io::Result<()> {
    send_signal(pid, libc::SIGKILL)
}

fn send_signal(pid: i32, signal: libc::c_int) -> io::Result<()> {
    validate_signal_pid(pid)?;
    let rc = unsafe { libc::kill(pid, signal) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn validate_signal_pid(pid: i32) -> io::Result<()> {
    if pid > 0 {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("pid must identify a single process: {pid}"),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::SleepChild;
    use std::os::unix::process::ExitStatusExt;
    use std::time::Duration;

    #[test]
    fn invalid_pids_are_rejected_for_watchers_and_signals() {
        let err = match ProcessExitWatcher::try_new(0) {
            Ok(_) => panic!("pid 0 should be rejected"),
            Err(err) => err,
        };

        assert_eq!(err.kind(), io::ErrorKind::NotFound);
        assert!(try_new_exit_watcher(0).is_none());
        assert!(ProcessExitWatcher::try_new(i32::MAX).is_err());
        assert_eq!(
            interrupt_process(0).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(
            kill_process(-1).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert!(kill_process(i32::MAX).is_err());
    }

    #[test]
    fn process_exists_reports_current_and_missing_processes() {
        assert!(process_exists(std::process::id() as i32));
        assert!(!process_exists(i32::MAX));
    }

    #[test]
    fn process_is_alive_uses_proc_fallback_without_watcher() {
        let mut watcher = None;

        assert!(process_is_alive(&mut watcher, std::process::id() as i32));
        assert!(!process_is_alive(&mut watcher, i32::MAX));
    }

    #[test]
    fn process_is_alive_uses_pidfd_watcher_when_available() {
        let pid = std::process::id() as i32;
        let Some(watcher) = try_new_exit_watcher(pid) else {
            return;
        };
        let mut watcher = Some(watcher);

        assert!(process_is_alive(&mut watcher, pid));
        assert!(watcher.is_some());
    }

    #[test]
    fn pidfd_watcher_observes_child_exit_when_available() {
        let mut child = SleepChild::spawn();
        let pid = child.pid_i32();
        let Ok(mut watcher) = ProcessExitWatcher::try_new(pid) else {
            return;
        };

        assert_eq!(
            watcher.poll().expect("poll live child"),
            ProcessExitState::RunningOrUnknown
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
        assert!(!process_is_alive(&mut watcher, pid));
    }

    #[test]
    fn interrupt_process_sends_sigint() {
        let mut child = SleepChild::spawn();

        interrupt_process(child.pid_i32()).expect("interrupt child");
        let status = child
            .wait_timeout(Duration::from_secs(2))
            .expect("wait child")
            .expect("child exited after interrupt");

        assert_eq!(status.signal(), Some(libc::SIGINT));
    }

    #[test]
    fn kill_process_sends_sigkill() {
        let mut child = SleepChild::spawn();

        kill_process(child.pid_i32()).expect("kill child");
        let status = child
            .wait_timeout(Duration::from_secs(2))
            .expect("wait child")
            .expect("child exited after kill");

        assert_eq!(status.signal(), Some(libc::SIGKILL));
    }
}
