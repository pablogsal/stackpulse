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
        let file_name = entry.file_name();
        let Some(file_name) = file_name.to_str() else {
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
    let rc = unsafe { libc::kill(pid, signal) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_exists_sees_the_current_process() {
        assert!(process_exists(std::process::id() as i32));
    }

    #[test]
    fn process_exists_rejects_a_pid_past_the_kernel_maximum() {
        // pid_max is at most 2^22 on Linux, so this task directory can
        // never exist and the ENOENT arm is taken.
        assert!(!process_exists(i32::MAX));
    }
}
