use std::fs;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessExitState {
    RunningOrUnknown,
    Exited,
}

pub struct ProcessExitWatcher {
    pidfd: OwnedFd,
    exited: bool,
}

impl ProcessExitWatcher {
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

pub fn try_new_exit_watcher(pid: i32) -> Option<ProcessExitWatcher> {
    ProcessExitWatcher::try_new(pid).ok()
}

pub fn poll_exit_watcher(watcher: &mut Option<ProcessExitWatcher>, _pid: i32) -> bool {
    let Some(active) = watcher.as_mut() else {
        return false;
    };
    match active.poll() {
        Ok(ProcessExitState::Exited) => true,
        Ok(ProcessExitState::RunningOrUnknown) => false,
        Err(_) => {
            *watcher = None;
            false
        }
    }
}

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

pub fn interrupt_process(pid: i32) -> io::Result<()> {
    send_signal(pid, libc::SIGINT)
}

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
