use std::fs;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::time::{Duration, Instant};

const STOP_TIMEOUT: Duration = Duration::from_secs(2);
const STOP_POLL_INTERVAL: Duration = Duration::from_millis(5);

#[derive(Clone, Debug, PartialEq, Eq)]
struct ProcessSnapshot {
    start_time: u64,
    tids: Vec<u32>,
    all_stopped: bool,
}

pub(super) struct StoppedProcess {
    pid: u32,
    start_time: u64,
    pidfd: Option<OwnedFd>,
    resume_on_drop: bool,
}

impl StoppedProcess {
    pub(super) fn new(pid: u32) -> io::Result<(Self, Vec<u32>)> {
        let initial = process_snapshot(pid)?;
        let pidfd = open_pidfd(pid)?;
        let confirmed = process_snapshot(pid)?;
        if confirmed.start_time != initial.start_time {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "target process identity changed while opening pidfd",
            ));
        }
        let mut stopped = Self {
            pid,
            start_time: confirmed.start_time,
            pidfd,
            resume_on_drop: false,
        };

        if confirmed.all_stopped {
            return Ok((stopped, without_leader(confirmed.tids, pid)));
        }

        stopped.send_signal(libc::SIGSTOP)?;
        stopped.resume_on_drop = true;
        let deadline = Instant::now() + STOP_TIMEOUT;
        let mut previous = None;
        loop {
            let snapshot = match process_snapshot(pid) {
                Ok(snapshot) => snapshot,
                Err(err) => return Err(stopped.resume_error_or(err)),
            };
            if snapshot.start_time != stopped.start_time {
                let err = io::Error::new(
                    io::ErrorKind::NotFound,
                    "target process identity changed while stopping",
                );
                return Err(stopped.resume_error_or(err));
            }
            if snapshot.all_stopped && previous.as_ref() == Some(&snapshot) {
                return Ok((stopped, without_leader(snapshot.tids, pid)));
            }
            previous = snapshot.all_stopped.then_some(snapshot);
            if Instant::now() >= deadline {
                let err = io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("timed out waiting for process {pid} to stop"),
                );
                return Err(stopped.resume_error_or(err));
            }
            std::thread::sleep(STOP_POLL_INTERVAL);
        }
    }

    fn send_signal(&self, signal: i32) -> io::Result<()> {
        let result = if let Some(pidfd) = &self.pidfd {
            unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal as libc::c_long,
                    pidfd.as_raw_fd(),
                    signal,
                    std::ptr::null::<libc::siginfo_t>(),
                    0,
                )
            }
        } else {
            unsafe { libc::kill(self.pid as libc::pid_t, signal) as libc::c_long }
        };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    pub(super) fn resume(&mut self) -> io::Result<()> {
        if !self.resume_on_drop {
            return Ok(());
        }

        // A pidfd pins the exact process. The kill fallback must prove that
        // the numeric PID still names the process we stopped.
        if self.pidfd.is_none() {
            match read_process_start_time(self.pid) {
                Ok(start_time) if start_time == self.start_time => {}
                Ok(_) => {
                    self.resume_on_drop = false;
                    return Ok(());
                }
                Err(err) if super::process_gone_error(&err) => {
                    self.resume_on_drop = false;
                    return Ok(());
                }
                Err(err) => return Err(err),
            }
        }

        self.send_signal(libc::SIGCONT)?;
        // Once SIGCONT succeeds, ownership of the stopped state ends. A
        // subsequent stop may belong to another actor and must not be undone
        // by Drop, even if confirmation below fails.
        self.resume_on_drop = false;
        let deadline = Instant::now() + STOP_TIMEOUT;
        loop {
            match process_snapshot(self.pid) {
                Ok(snapshot) if snapshot.start_time != self.start_time || !snapshot.all_stopped => {
                    return Ok(());
                }
                Ok(_) => {}
                Err(err) if super::process_gone_error(&err) => return Ok(()),
                Err(err) => return Err(err),
            }
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("timed out waiting for process {} to resume", self.pid),
                ));
            }
            std::thread::sleep(STOP_POLL_INTERVAL);
        }
    }

    fn resume_error_or(&mut self, original_error: io::Error) -> io::Error {
        self.resume().err().unwrap_or(original_error)
    }
}

impl Drop for StoppedProcess {
    fn drop(&mut self) {
        let _ = self.resume();
    }
}

fn open_pidfd(pid: u32) -> io::Result<Option<OwnedFd>> {
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open as libc::c_long, pid, 0) };
    if fd >= 0 {
        return Ok(Some(unsafe { OwnedFd::from_raw_fd(fd as i32) }));
    }
    let err = io::Error::last_os_error();
    match err.raw_os_error() {
        Some(libc::ENOSYS | libc::EINVAL | libc::EPERM | libc::EACCES) => Ok(None),
        _ => Err(err),
    }
}

fn without_leader(mut tids: Vec<u32>, pid: u32) -> Vec<u32> {
    tids.retain(|&tid| tid != pid);
    tids
}

fn process_snapshot(pid: u32) -> io::Result<ProcessSnapshot> {
    process_snapshot_with(pid, read_proc_stat)
}

fn process_snapshot_with(
    pid: u32,
    mut read_stat: impl FnMut(&str) -> io::Result<ProcStat>,
) -> io::Result<ProcessSnapshot> {
    let leader_path = format!("/proc/{pid}/stat");
    let initial_leader = read_stat(&leader_path)?;
    let mut tids = Vec::new();
    let mut all_stopped = true;
    for entry in fs::read_dir(format!("/proc/{pid}/task"))? {
        let entry = match entry {
            Ok(entry) => entry,
            Err(err) if super::process_gone_error(&err) => continue,
            Err(err) => return Err(err),
        };
        let Some(tid) = entry.file_name().to_str().and_then(|tid| tid.parse().ok()) else {
            continue;
        };
        match read_stat(&format!("/proc/{pid}/task/{tid}/stat")) {
            Ok(stat) => {
                tids.push(tid);
                all_stopped &= matches!(stat.state, 'T' | 't');
            }
            Err(err) if super::process_gone_error(&err) => {}
            Err(err) => return Err(err),
        }
    }
    tids.sort_unstable();
    tids.dedup();
    if !tids.contains(&pid) {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "target process disappeared while enumerating threads",
        ));
    }
    let confirmed_leader = read_stat(&leader_path)?;
    if confirmed_leader.start_time != initial_leader.start_time {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "target process identity changed while enumerating threads",
        ));
    }
    Ok(ProcessSnapshot {
        start_time: confirmed_leader.start_time,
        tids,
        all_stopped,
    })
}

#[derive(Debug)]
struct ProcStat {
    state: char,
    start_time: u64,
}

fn parse_proc_stat(stat: &str) -> io::Result<ProcStat> {
    let after_comm = stat
        .rfind(')')
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "malformed proc stat"))?;
    let mut fields = stat
        .get(after_comm + 2..)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "malformed proc stat"))?
        .split_whitespace();
    let state = fields
        .next()
        .and_then(|value| value.chars().next())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing proc state"))?;
    let start_time = fields
        .nth(18)
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing proc start time"))?;
    Ok(ProcStat { state, start_time })
}

fn read_proc_stat(path: &str) -> io::Result<ProcStat> {
    parse_proc_stat(&fs::read_to_string(path)?)
}

pub(super) fn read_process_start_time(pid: u32) -> io::Result<u64> {
    Ok(read_proc_stat(&format!("/proc/{pid}/stat"))?.start_time)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::SleepChild;

    #[test]
    fn parses_comm_with_parentheses() {
        let stat = parse_proc_stat(
            "42 (a tricky ) name) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 987",
        )
        .expect("parse stat");
        assert_eq!(stat.state, 'S');
        assert_eq!(stat.start_time, 987);
    }

    #[test]
    fn rejects_malformed_stat() {
        assert_eq!(
            parse_proc_stat("42 malformed")
                .expect_err("reject stat")
                .kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn snapshot_rejects_identity_change_during_thread_enumeration() {
        let pid = std::process::id();
        let leader_path = format!("/proc/{pid}/stat");
        let mut leader_reads = 0;

        let err = process_snapshot_with(pid, |path| {
            let mut stat = read_proc_stat(path)?;
            if path == leader_path {
                leader_reads += 1;
                if leader_reads == 2 {
                    stat.start_time = stat.start_time.saturating_add(1);
                }
            }
            Ok(stat)
        })
        .expect_err("reject changed process identity");

        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn running_process_is_stopped_then_resumed() {
        let child = SleepChild::spawn();
        let pid = child.pid_u32();
        let (mut stopped, _) = StoppedProcess::new(pid).expect("stop child");
        assert!(process_snapshot(pid).expect("stopped snapshot").all_stopped);
        stopped.resume().expect("resume child");
        drop(stopped);
        assert!(!process_snapshot(pid).expect("resumed snapshot").all_stopped);
    }

    #[test]
    fn already_stopped_process_stays_stopped() {
        let child = SleepChild::spawn();
        let pid = child.pid_u32();
        assert_eq!(unsafe { libc::kill(pid as _, libc::SIGSTOP) }, 0);
        wait_until(pid, |snapshot| snapshot.all_stopped);

        let (stopped, _) = StoppedProcess::new(pid).expect("observe stopped child");
        drop(stopped);

        assert!(process_snapshot(pid).expect("still stopped").all_stopped);
        assert_eq!(unsafe { libc::kill(pid as _, libc::SIGCONT) }, 0);
    }

    #[test]
    fn pidfd_guard_resumes_without_proc_identity_check() {
        let child = SleepChild::spawn();
        let pid = child.pid_u32();
        let Some(pidfd) = open_pidfd(pid).expect("open pidfd") else {
            return;
        };
        assert_eq!(unsafe { libc::kill(pid as _, libc::SIGSTOP) }, 0);
        wait_until(pid, |snapshot| snapshot.all_stopped);

        drop(StoppedProcess {
            pid,
            start_time: u64::MAX,
            pidfd: Some(pidfd),
            resume_on_drop: true,
        });

        wait_until(pid, |snapshot| !snapshot.all_stopped);
    }

    #[test]
    fn explicit_resume_preserves_the_signal_errno() {
        let file = std::fs::File::open("/dev/null").expect("open non-pidfd");
        let mut stopped = StoppedProcess {
            pid: std::process::id(),
            start_time: u64::MAX,
            pidfd: Some(file.into()),
            resume_on_drop: true,
        };

        let err = stopped
            .resume()
            .expect_err("reject non-pidfd signal target");

        assert!(matches!(
            err.raw_os_error(),
            Some(libc::EBADF | libc::EINVAL)
        ));
        assert!(stopped.resume_on_drop);
    }

    fn wait_until(pid: u32, predicate: impl Fn(&ProcessSnapshot) -> bool) {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if let Ok(snapshot) = process_snapshot(pid) {
                if predicate(&snapshot) {
                    return;
                }
            }
            assert!(Instant::now() < deadline, "process state did not change");
            std::thread::sleep(STOP_POLL_INTERVAL);
        }
    }
}
