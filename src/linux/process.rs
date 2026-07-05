use std::cell::Cell;
use std::collections::BTreeMap;
use std::ffi::{CString, OsStr, OsString};
use std::io;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::raw::c_char;
use std::os::unix::prelude::OsStrExt;

use libc::{execvp, execvpe};
use nix::errno::Errno;
use nix::fcntl::OFlag;
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::{fork, pipe2, read, write, ForkResult, Pid};

/// Forks a child that blocks before `execve` so the parent can capture its PID
/// and initialize profiling first.
pub struct SuspendedLaunchedProcess {
    pid: Pid,
    send_end_of_resume_pipe: Option<OwnedFd>,
    recv_end_of_execerr_pipe: Option<OwnedFd>,
}

impl SuspendedLaunchedProcess {
    /// Fork a child process that waits before executing `command_name`.
    ///
    /// This lets the parent attach a recorder before the child starts running.
    pub fn launch_in_suspended_state(
        command_name: &OsStr,
        command_args: &[OsString],
        env_vars: &[(OsString, OsString)],
    ) -> io::Result<Self> {
        let argv_strings: Vec<CString> = std::iter::once(command_name)
            .chain(command_args.iter().map(OsString::as_os_str))
            .map(cstring_from_os_str)
            .collect::<io::Result<_>>()?;
        let argv: Vec<*const c_char> = null_terminated_ptrs(&argv_strings);
        let envp_strings = (!env_vars.is_empty())
            .then(|| build_env(env_vars))
            .transpose()?;
        let envp: Option<Vec<*const c_char>> = envp_strings.as_deref().map(null_terminated_ptrs);
        let (resume_rp, resume_sp) = pipe2(OFlag::O_CLOEXEC)?;
        let (execerr_rp, execerr_sp) = pipe2(OFlag::O_CLOEXEC)?;

        match unsafe { fork() }? {
            ForkResult::Child => {
                drop((resume_sp, execerr_rp));
                Self::run_child(resume_rp, execerr_sp, &argv, envp.as_deref())
            }
            ForkResult::Parent { child } => {
                drop((resume_rp, execerr_sp));
                Ok(Self {
                    pid: child,
                    send_end_of_resume_pipe: Some(resume_sp),
                    recv_end_of_execerr_pipe: Some(execerr_rp),
                })
            }
        }
    }

    /// Return the child process id.
    pub fn pid(&self) -> u32 {
        self.pid.as_raw() as u32
    }

    const EXECERR_MSG_FOOTER: [u8; 4] = *b"NOEX";

    /// Allow the child to execute and return a handle for waiting on it.
    pub fn unsuspend_and_run(mut self) -> io::Result<RunningProcess> {
        let result = self.unsuspend_inner();
        if result.is_err() {
            // Reap the child on any failure after we took ownership of the
            // pipes; Drop's reap path is gated on the pipes still being Some.
            reap(self.pid);
        }
        result
    }

    fn unsuspend_inner(&mut self) -> io::Result<RunningProcess> {
        let send_end_of_resume_pipe = self
            .send_end_of_resume_pipe
            .take()
            .ok_or_else(|| io::Error::other("process was already resumed"))?;
        let recv_end_of_execerr_pipe = self
            .recv_end_of_execerr_pipe
            .take()
            .ok_or_else(|| io::Error::other("process was already resumed"))?;

        // Signal the child to exec.
        write(&send_end_of_resume_pipe, &[0x42])?;
        drop(send_end_of_resume_pipe);

        // Loop to handle EINTR. The child closes execerr on exec success.
        loop {
            let mut bytes = [0; 8];
            match read(recv_end_of_execerr_pipe.as_raw_fd(), &mut bytes) {
                Ok(0) => break, // exec succeeded; pipe closed
                Ok(8) => {
                    let (errno_bytes, footer) = bytes.split_first_chunk::<4>().unwrap();
                    if footer != Self::EXECERR_MSG_FOOTER {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("invalid exec error pipe footer: {bytes:?}"),
                        ));
                    }
                    return Err(io::Error::from_raw_os_error(i32::from_be_bytes(
                        *errno_bytes,
                    )));
                }
                Ok(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "short read on exec error pipe",
                    ));
                }
                Err(Errno::EINTR) => {}
                Err(err) => return Err(err.into()),
            }
        }

        Ok(RunningProcess {
            pid: Cell::new(Some(self.pid)),
        })
    }

    /// Executed in the forked child process. This function never returns.
    fn run_child(
        recv_end_of_resume_pipe: OwnedFd,
        send_end_of_execerr_pipe: OwnedFd,
        argv: &[*const c_char],
        envp: Option<&[*const c_char]>,
    ) -> ! {
        // Wait for the parent to signal us to exec. The loop handles EINTR.
        loop {
            let mut buf = [0];
            match read(recv_end_of_resume_pipe.as_raw_fd(), &mut buf) {
                // Parent gave up (closed pipe without signaling); exit silently.
                // Use _exit: this is a forked child that must not run the
                // parent's atexit handlers or flush its inherited stdio buffers.
                Ok(0) => unsafe { libc::_exit(0) },
                Ok(_) => {
                    let _ = unsafe {
                        match envp {
                            Some(envp) => execvpe(argv[0], argv.as_ptr(), envp.as_ptr()),
                            None => execvp(argv[0], argv.as_ptr()),
                        }
                    };
                    // exec returned, so it failed; report the errno to the parent.
                    let [a, b, c, d] = Errno::last_raw().to_be_bytes();
                    let [e, f, g, h] = Self::EXECERR_MSG_FOOTER;
                    let _ = write(send_end_of_execerr_pipe, &[a, b, c, d, e, f, g, h]);
                    unsafe { libc::_exit(1) } // bypass at_exit destructors
                }
                Err(Errno::EINTR) => {}
                Err(_) => unsafe { libc::_exit(1) },
            }
        }
    }
}

fn waitpid_retry(pid: Pid, flags: Option<WaitPidFlag>) -> nix::Result<WaitStatus> {
    loop {
        match waitpid(pid, flags) {
            Err(Errno::EINTR) => {}
            result => return result,
        }
    }
}

fn reap(pid: Pid) {
    let _ = waitpid_retry(pid, None);
}

impl Drop for SuspendedLaunchedProcess {
    fn drop(&mut self) {
        if self.send_end_of_resume_pipe.take().is_none() {
            return;
        }
        drop(self.recv_end_of_execerr_pipe.take());
        reap(self.pid);
    }
}

fn cstring_from_os_str(os_str: &OsStr) -> io::Result<CString> {
    CString::new(os_str.as_bytes()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "nul byte found in command arguments",
        )
    })
}

/// A launched process that is now running.
#[must_use = "dropping without wait may leave the child running"]
pub struct RunningProcess {
    pid: Cell<Option<Pid>>,
}

impl RunningProcess {
    /// Check whether the process has exited without blocking.
    pub fn try_wait(&self) -> io::Result<Option<WaitStatus>> {
        let Some(pid) = self.pid.get() else {
            return Ok(None);
        };
        match waitpid_retry(pid, Some(WaitPidFlag::WNOHANG)) {
            Ok(WaitStatus::StillAlive) => Ok(None),
            Ok(status) => {
                self.pid.set(None);
                Ok(Some(status))
            }
            Err(err) => Err(err.into()),
        }
    }

    /// Wait until the process exits.
    pub fn wait(self) -> io::Result<WaitStatus> {
        let Some(pid) = self.pid.replace(None) else {
            return Err(io::Error::other("process was already waited"));
        };
        waitpid_retry(pid, None).map_err(Into::into)
    }
}

impl Drop for RunningProcess {
    fn drop(&mut self) {
        if let Some(pid) = self.pid.get() {
            let _ = waitpid_retry(pid, Some(WaitPidFlag::WNOHANG));
        }
    }
}

fn null_terminated_ptrs(strings: &[CString]) -> Vec<*const c_char> {
    strings
        .iter()
        .map(|c| c.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect()
}

fn build_env(env_vars: &[(OsString, OsString)]) -> io::Result<Vec<CString>> {
    use std::os::unix::ffi::OsStringExt;
    let mut vars: BTreeMap<OsString, OsString> = std::env::vars_os().collect();
    for (name, val) in env_vars {
        vars.insert(name.clone(), val.clone());
    }
    vars.into_iter()
        .map(|(mut k, v)| {
            k.reserve_exact(v.len() + 2);
            k.push("=");
            k.push(&v);
            CString::new(k.into_vec()).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "nul byte found in environment variables",
                )
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
    use std::thread;
    use std::time::{Duration, Instant};

    const ENV_HELPER: &str = "linux::process::tests::stackpulse_process_helper_env_probe";
    const EXIT_HELPER: &str = "linux::process::tests::stackpulse_process_helper_exit_7";

    fn current_test_binary() -> OsString {
        std::env::current_exe()
            .expect("current test binary")
            .into_os_string()
    }

    fn ignored_test_args(test_name: &str) -> [OsString; 3] {
        [
            OsString::from("--ignored"),
            OsString::from("--exact"),
            OsString::from(test_name),
        ]
    }

    #[test]
    fn dropping_suspended_launch_reaps_child() {
        let launched =
            SuspendedLaunchedProcess::launch_in_suspended_state(OsStr::new("unused"), &[], &[])
                .expect("launch suspended child");
        let pid = Pid::from_raw(launched.pid() as i32);

        drop(launched);

        assert!(matches!(
            waitpid(pid, Some(WaitPidFlag::WNOHANG)),
            Err(Errno::ECHILD)
        ));
    }

    #[test]
    fn failed_unsuspend_reaps_child() {
        let launched = SuspendedLaunchedProcess::launch_in_suspended_state(
            OsStr::new("/path/that/does/not/exist/stackpulse-bogus"),
            &[],
            &[],
        )
        .expect("launch suspended child");
        let pid = Pid::from_raw(launched.pid() as i32);

        let result = launched.unsuspend_and_run();
        assert!(result.is_err());

        assert!(matches!(
            waitpid(pid, Some(WaitPidFlag::WNOHANG)),
            Err(Errno::ECHILD)
        ));
    }

    #[test]
    fn suspended_launch_runs_command_with_environment_overrides() {
        let command = current_test_binary();
        let args = ignored_test_args(ENV_HELPER);
        let launched = SuspendedLaunchedProcess::launch_in_suspended_state(
            command.as_os_str(),
            &args,
            &[(OsString::from("STACKPULSE_TEST_ENV"), OsString::from("ok"))],
        )
        .expect("launch suspended child");

        let running = launched.unsuspend_and_run().expect("resume child");
        let status = running.wait().expect("wait child");

        assert!(matches!(status, WaitStatus::Exited(_, 0)));
    }

    #[test]
    fn running_process_reports_none_after_it_has_been_waited() {
        let process = RunningProcess {
            pid: Cell::new(None),
        };

        assert!(process.try_wait().expect("try wait without pid").is_none());
        assert_eq!(
            process.wait().unwrap_err().to_string(),
            "process was already waited"
        );
    }

    #[test]
    fn try_wait_records_exited_process_once() {
        let command = current_test_binary();
        let args = ignored_test_args(EXIT_HELPER);
        let launched =
            SuspendedLaunchedProcess::launch_in_suspended_state(command.as_os_str(), &args, &[])
                .expect("launch suspended child");
        let running = launched.unsuspend_and_run().expect("resume child");
        let deadline = Instant::now() + Duration::from_secs(5);

        loop {
            if let Some(status) = running.try_wait().expect("try wait child") {
                assert!(matches!(status, WaitStatus::Exited(_, 7)));
                assert!(running.try_wait().expect("try wait reaped child").is_none());
                return;
            }
            if Instant::now() >= deadline {
                if let Some(pid) = running.pid.get() {
                    unsafe {
                        libc::kill(pid.as_raw(), libc::SIGKILL);
                    }
                }
                let _ = running.wait();
                panic!("child did not exit");
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn cstring_conversions_reject_nul_bytes() {
        assert!(cstring_from_os_str(OsStr::from_bytes(b"abc\0def")).is_err());
        assert!(build_env(&[(
            OsString::from_vec(b"BAD\0NAME".to_vec()),
            OsString::from("x")
        )])
        .is_err());
        assert!(build_env(&[(
            OsString::from("BAD_VALUE"),
            OsString::from_vec(b"x\0y".to_vec())
        )])
        .is_err());
    }

    #[test]
    #[ignore]
    fn stackpulse_process_helper_env_probe() {
        assert_eq!(std::env::var("STACKPULSE_TEST_ENV").as_deref(), Ok("ok"));
    }

    #[test]
    #[ignore]
    fn stackpulse_process_helper_exit_7() {
        std::process::exit(7);
    }
}
