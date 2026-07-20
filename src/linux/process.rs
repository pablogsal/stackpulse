use std::cell::Cell;
use std::collections::BTreeMap;
use std::ffi::{CString, OsStr, OsString};
use std::io;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::raw::c_char;
use std::os::unix::prelude::OsStrExt;

use libc::execvp;
use nix::errno::Errno;
use nix::fcntl::OFlag;
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::{fork, pipe2, read, write, ForkResult, Pid};

unsafe extern "C" {
    static mut environ: *mut *mut c_char;
}

/// Forks a child that blocks before `execve` so the parent can capture its PID
/// and initialize profiling first.
pub struct SuspendedLaunchedProcess {
    pid: Pid,
    pipes: Option<SuspendPipes>,
}

struct SuspendPipes {
    resume_tx: OwnedFd,
    exec_error_rx: OwnedFd,
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
                    pipes: Some(SuspendPipes {
                        resume_tx: resume_sp,
                        exec_error_rx: execerr_rp,
                    }),
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
        let SuspendPipes {
            resume_tx,
            exec_error_rx,
        } = self
            .pipes
            .take()
            .ok_or_else(|| io::Error::other("process was already resumed"))?;

        write(&resume_tx, &[0x42])?;
        drop(resume_tx);

        // Loop to handle EINTR. The child closes execerr on exec success.
        loop {
            let mut bytes = [0; 8];
            match read(exec_error_rx.as_raw_fd(), &mut bytes) {
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
            state: Cell::new(ChildState::Running(self.pid)),
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
                            Some(envp) => {
                                // SAFETY: `envp` is a null-terminated pointer vector whose
                                // C strings remain alive through this call. Only the forked
                                // child changes its private `environ`, then it execs or exits.
                                environ = envp.as_ptr().cast_mut().cast();
                                execvp(argv[0], argv.as_ptr())
                            }
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
        if self.pipes.take().is_none() {
            return;
        }
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
    state: Cell<ChildState>,
}

#[derive(Clone, Copy)]
enum ChildState {
    Running(Pid),
    Exited(WaitStatus),
    Waited,
}

impl RunningProcess {
    /// Check whether the process has exited without blocking.
    pub fn try_wait(&self) -> io::Result<Option<WaitStatus>> {
        let pid = match self.state.get() {
            ChildState::Running(pid) => pid,
            ChildState::Exited(status) => return Ok(Some(status)),
            ChildState::Waited => return Ok(None),
        };
        match waitpid_retry(pid, Some(WaitPidFlag::WNOHANG)) {
            Ok(WaitStatus::StillAlive) => Ok(None),
            Ok(status) => {
                self.state.set(ChildState::Exited(status));
                Ok(Some(status))
            }
            Err(err) => Err(err.into()),
        }
    }

    /// Wait until the process exits.
    pub fn wait(self) -> io::Result<WaitStatus> {
        match self.state.replace(ChildState::Waited) {
            ChildState::Running(pid) => waitpid_retry(pid, None).map_err(Into::into),
            ChildState::Exited(status) => Ok(status),
            ChildState::Waited => Err(io::Error::other("process was already waited")),
        }
    }
}

impl Drop for RunningProcess {
    fn drop(&mut self) {
        if let ChildState::Running(pid) = self.state.get() {
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
    use crate::test_support::TempDir;
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
    use std::os::unix::fs::symlink;
    use std::thread;
    use std::time::{Duration, Instant};

    const ENV_HELPER: &str = "linux::process::tests::stackpulse_process_helper_env_probe";
    const EXIT_HELPER: &str = "linux::process::tests::stackpulse_process_helper_exit_7";
    const PATH_HELPER: &str = "linux::process::tests::stackpulse_process_helper_path_override";
    const CHILD_PATH_ENV: &str = "STACKPULSE_CHILD_PATH";
    const PATH_EXECUTABLE: &str = "stackpulse-child-path-executable";

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
    fn suspended_launch_resolves_commands_with_the_child_path() {
        let caller_path = TempDir::new("process-caller-path");
        let executable_dir = TempDir::new("process-child-path");
        symlink(
            current_test_binary(),
            executable_dir.path().join(PATH_EXECUTABLE),
        )
        .expect("create child PATH executable");
        let args = ignored_test_args(PATH_HELPER);
        let launched = SuspendedLaunchedProcess::launch_in_suspended_state(
            current_test_binary().as_os_str(),
            &args,
            &[
                (
                    OsString::from("PATH"),
                    caller_path.path().as_os_str().to_owned(),
                ),
                (
                    OsString::from(CHILD_PATH_ENV),
                    executable_dir.path().as_os_str().to_owned(),
                ),
            ],
        )
        .expect("launch PATH test helper");

        let status = launched
            .unsuspend_and_run()
            .expect("resume PATH test helper")
            .wait()
            .expect("wait for PATH test helper");

        assert!(matches!(status, WaitStatus::Exited(_, 0)));
    }

    #[test]
    fn running_process_reports_none_after_it_has_been_waited() {
        let process = RunningProcess {
            state: Cell::new(ChildState::Waited),
        };

        assert!(process.try_wait().expect("try wait without pid").is_none());
        assert_eq!(
            process.wait().unwrap_err().to_string(),
            "process was already waited"
        );
    }

    #[test]
    fn try_wait_caches_exited_process_status() {
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
                assert!(matches!(
                    running.try_wait().expect("try wait reaped child"),
                    Some(WaitStatus::Exited(_, 7))
                ));
                assert!(matches!(
                    running.wait().expect("wait reaped child"),
                    WaitStatus::Exited(_, 7)
                ));
                return;
            }
            if Instant::now() >= deadline {
                if let ChildState::Running(pid) = running.state.get() {
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

    #[test]
    #[ignore]
    fn stackpulse_process_helper_path_override() {
        let child_path = std::env::var_os(CHILD_PATH_ENV).expect("child PATH");
        let args = ignored_test_args(EXIT_HELPER);
        let launched = SuspendedLaunchedProcess::launch_in_suspended_state(
            OsStr::new(PATH_EXECUTABLE),
            &args,
            &[(OsString::from("PATH"), child_path)],
        )
        .expect("launch executable from child PATH");
        let status = launched
            .unsuspend_and_run()
            .expect("resume child PATH executable")
            .wait()
            .expect("wait for child PATH executable");

        assert!(matches!(status, WaitStatus::Exited(_, 7)));
    }
}
