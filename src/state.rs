use std::fs;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use crate::Pid;

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
#[derive(Debug)]
pub struct ProcessExitWatcher {
    pidfd: OwnedFd,
    exited: bool,
}

impl ProcessExitWatcher {
    /// Open a pidfd for `pid`.
    ///
    /// This fails when `pidfd_open` is unavailable or denied, for example on
    /// an older kernel or inside a restrictive sandbox.
    pub fn try_new(pid: Pid) -> io::Result<Self> {
        // SAFETY: a validated Pid identifies one process and pidfd_open takes
        // no pointer arguments.
        let raw_fd = unsafe { libc::syscall(libc::SYS_pidfd_open as libc::c_long, pid.get(), 0) };
        if raw_fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            // SAFETY: a nonnegative pidfd_open result is a newly owned file descriptor.
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
        // SAFETY: fds points to one initialized pollfd and the count is one.
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

/// Combined liveness check: prefers the pidfd watcher (race-free) and falls
/// back to [`process_exists`] when no watcher is available or the poll errors.
#[must_use]
pub fn process_is_alive(watcher: &mut Option<ProcessExitWatcher>, pid: Pid) -> bool {
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
#[must_use]
pub fn process_exists(pid: Pid) -> bool {
    try_process_exists(pid).unwrap_or(true)
}

pub(crate) fn try_process_exists(pid: Pid) -> io::Result<bool> {
    let pid = pid.get();
    let mut tasks = match fs::read_dir(format!("/proc/{pid}/task")) {
        Ok(tasks) => tasks,
        Err(err) if matches!(err.raw_os_error(), Some(libc::ENOENT | libc::ESRCH)) => {
            return Ok(false)
        }
        Err(err) => return Err(err),
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
            return Ok(true);
        }
        saw_leader = true;
    }
    Ok(saw_leader)
}

/// Send `SIGINT` to `pid` (graceful interrupt). Fails with the underlying
/// `kill(2)` error, typically `EPERM` or `ESRCH`.
pub fn interrupt_process(pid: Pid) -> io::Result<()> {
    send_signal(pid, libc::SIGINT)
}

/// Send `SIGKILL` to `pid` (uncatchable termination).
pub fn kill_process(pid: Pid) -> io::Result<()> {
    send_signal(pid, libc::SIGKILL)
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
        assert!(process_exists(pid(std::process::id() as i32)));
        assert!(!process_exists(pid(i32::MAX)));
    }

    #[test]
    fn process_is_alive_uses_proc_fallback_without_watcher() {
        let mut watcher = None;

        assert!(process_is_alive(
            &mut watcher,
            pid(std::process::id() as i32)
        ));
        assert!(!process_is_alive(&mut watcher, pid(i32::MAX)));
    }

    #[test]
    fn process_is_alive_uses_pidfd_watcher_when_available() {
        let pid = pid(std::process::id() as i32);
        let Ok(watcher) = ProcessExitWatcher::try_new(pid) else {
            return;
        };
        let mut watcher = Some(watcher);

        assert!(process_is_alive(&mut watcher, pid));
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
}
