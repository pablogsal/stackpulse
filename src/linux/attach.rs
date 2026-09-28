use std::fs;
use std::io;
use std::time::{Duration, Instant};

use crate::state::ProcessHandle;

const STOP_TIMEOUT: Duration = Duration::from_secs(2);
const STOP_POLL_INTERVAL: Duration = Duration::from_millis(5);

#[derive(Clone, Debug, PartialEq, Eq)]
struct ProcessSnapshot {
    tids: Vec<u32>,
    all_stopped: bool,
}

pub(super) struct StoppedProcess {
    process: ProcessHandle,
    resume_on_drop: bool,
}

impl StoppedProcess {
    pub(super) fn new(process: ProcessHandle) -> io::Result<(Self, Vec<u32>)> {
        let pid = process.pid().get_u32();
        let mut stopped = Self {
            process,
            resume_on_drop: false,
        };
        let initial = stopped.process.read_checked(process_snapshot)?;
        if initial.all_stopped {
            return Ok((stopped, without_leader(initial.tids, pid)));
        }

        stopped.process.signal(libc::SIGSTOP).map_err(|err| {
            crate::error::AttachError::wrap(crate::error::AttachStep::StopTarget, pid, err)
        })?;
        stopped.resume_on_drop = true;
        let deadline = Instant::now() + STOP_TIMEOUT;
        let mut previous = None;
        loop {
            let snapshot = match stopped.process.read_checked(process_snapshot) {
                Ok(snapshot) => snapshot,
                Err(err) => return Err(stopped.resume_error_or(err)),
            };
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

    pub(super) fn resume(&mut self) -> io::Result<()> {
        if !self.resume_on_drop {
            return Ok(());
        }

        self.process.signal(libc::SIGCONT)?;
        // Once SIGCONT succeeds, ownership of the stopped state ends. A
        // subsequent stop may belong to another actor and must not be undone
        // by Drop, even if confirmation below fails.
        self.resume_on_drop = false;
        let deadline = Instant::now() + STOP_TIMEOUT;
        loop {
            match self.process.read_checked(process_snapshot) {
                Ok(snapshot) if !snapshot.all_stopped => return Ok(()),
                Ok(_) => {}
                Err(err) if crate::error::is_target_gone_io(&err) => return Ok(()),
                Err(err) => return Err(err),
            }
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!(
                        "timed out waiting for process {} to resume",
                        self.process.pid()
                    ),
                ));
            }
            std::thread::sleep(STOP_POLL_INTERVAL);
        }
    }

    pub(super) fn resume_error_or(&mut self, original_error: io::Error) -> io::Error {
        match self.resume() {
            Ok(()) => original_error,
            Err(cleanup_error) => crate::error::with_cleanup_error(original_error, cleanup_error),
        }
    }
}

impl Drop for StoppedProcess {
    fn drop(&mut self) {
        let _ = self.resume();
    }
}

fn without_leader(mut tids: Vec<u32>, pid: u32) -> Vec<u32> {
    tids.retain(|&tid| tid != pid);
    tids
}

fn process_snapshot(pid: u32) -> io::Result<ProcessSnapshot> {
    let mut tids = Vec::new();
    let mut all_stopped = true;
    for entry in fs::read_dir(format!("/proc/{pid}/task"))? {
        let entry = match entry {
            Ok(entry) => entry,
            Err(err) if crate::error::is_target_gone_io(&err) => continue,
            Err(err) => return Err(err),
        };
        let Some(tid) = entry.file_name().to_str().and_then(|tid| tid.parse().ok()) else {
            continue;
        };
        match read_proc_stat(&format!("/proc/{pid}/task/{tid}/stat")) {
            Ok(stat) => {
                tids.push(tid);
                all_stopped &= matches!(stat.state, 'T' | 't');
            }
            Err(err) if crate::error::is_target_gone_io(&err) => {}
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
    Ok(ProcessSnapshot { tids, all_stopped })
}

#[derive(Debug)]
pub(crate) struct ProcStat {
    pub(crate) state: char,
    pub(crate) num_threads: u64,
    pub(crate) start_time: u64,
}

fn parse_proc_stat(stat: &[u8]) -> io::Result<ProcStat> {
    let mut fields = crate::children::proc_stat_fields(stat)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "malformed proc stat"))?
        .split_whitespace();
    let state = fields
        .next()
        .and_then(|value| value.chars().next())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing proc state"))?;
    let num_threads = fields
        .nth(16)
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing proc thread count"))?;
    let start_time = fields
        .nth(1)
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing proc start time"))?;
    Ok(ProcStat {
        state,
        num_threads,
        start_time,
    })
}

fn read_proc_stat(path: &str) -> io::Result<ProcStat> {
    parse_proc_stat(&fs::read(path)?)
}

/// Parse `Tgid:` from raw `/proc/<pid>/status` bytes; the `Name:` line holds
/// the kernel command name, which need not be UTF-8.
fn parse_thread_group_id(status: &[u8]) -> io::Result<u32> {
    status
        .split(|&byte| byte == b'\n')
        .find_map(|line| line.strip_prefix(b"Tgid:"))
        .and_then(|value| std::str::from_utf8(value).ok())
        .and_then(|value| value.trim().parse().ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing proc tgid"))
}

pub(super) fn read_thread_group_id(pid: u32) -> io::Result<u32> {
    parse_thread_group_id(&fs::read(format!("/proc/{pid}/status"))?)
}

pub(crate) fn read_process_stat(pid: u32) -> io::Result<ProcStat> {
    read_proc_stat(&format!("/proc/{pid}/stat"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{process_handle, SleepChild};

    #[test]
    fn parses_comm_with_parentheses() {
        let stat = parse_proc_stat(
            b"42 (a tricky ) name) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 987",
        )
        .expect("parse stat");
        assert_eq!(stat.state, 'S');
        assert_eq!(stat.start_time, 987);
    }

    #[test]
    fn rejects_malformed_stat() {
        assert_eq!(
            parse_proc_stat(b"42 malformed")
                .expect_err("reject stat")
                .kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn running_process_is_stopped_then_resumed() {
        let child = SleepChild::spawn();
        let pid = child.pid_u32();
        let (mut stopped, _) = StoppedProcess::new(process_handle(pid)).expect("stop child");
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

        let (stopped, _) = StoppedProcess::new(process_handle(pid)).expect("observe stopped child");
        drop(stopped);

        assert!(process_snapshot(pid).expect("still stopped").all_stopped);
        assert_eq!(unsafe { libc::kill(pid as _, libc::SIGCONT) }, 0);
    }

    #[test]
    fn dropping_an_owned_stop_resumes_the_process() {
        let child = SleepChild::spawn();
        let pid = child.pid_u32();
        assert_eq!(unsafe { libc::kill(pid as _, libc::SIGSTOP) }, 0);
        wait_until(pid, |snapshot| snapshot.all_stopped);

        drop(StoppedProcess {
            process: process_handle(pid),
            resume_on_drop: true,
        });

        wait_until(pid, |snapshot| !snapshot.all_stopped);
    }

    #[test]
    fn explicit_resume_preserves_the_signal_errno() {
        let mut child = SleepChild::spawn();
        let process = process_handle(child.pid_u32());
        process.signal(libc::SIGKILL).expect("kill child");
        child
            .wait_timeout(Duration::from_secs(2))
            .expect("wait child")
            .expect("child exited after kill");
        let mut stopped = StoppedProcess {
            process,
            resume_on_drop: true,
        };

        let err = stopped.resume().expect_err("reject exited signal target");

        assert_eq!(err.raw_os_error(), Some(libc::ESRCH));
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
