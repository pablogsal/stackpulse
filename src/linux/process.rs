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
    send_end_of_resume_pipe: OwnedFd,
    recv_end_of_execerr_pipe: OwnedFd,
}

impl SuspendedLaunchedProcess {
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
                    send_end_of_resume_pipe: resume_sp,
                    recv_end_of_execerr_pipe: execerr_rp,
                })
            }
        }
    }

    pub fn pid(&self) -> u32 {
        self.pid.as_raw() as u32
    }

    const EXECERR_MSG_FOOTER: [u8; 4] = *b"NOEX";

    pub fn unsuspend_and_run(self) -> io::Result<RunningProcess> {
        // Signal the child to exec.
        write(&self.send_end_of_resume_pipe, &[0x42])?;
        drop(self.send_end_of_resume_pipe);

        // Loop to handle EINTR. The child closes execerr on exec success.
        loop {
            let mut bytes = [0; 8];
            match read(self.recv_end_of_execerr_pipe.as_raw_fd(), &mut bytes) {
                Ok(0) => break, // exec succeeded; pipe closed
                Ok(8) => {
                    let _ = waitpid(self.pid, None);
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
                    let _ = waitpid(self.pid, None);
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "short read on exec error pipe",
                    ));
                }
                Err(Errno::EINTR) => {}
                Err(err) => return Err(err.into()),
            }
        }

        Ok(RunningProcess { pid: self.pid })
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
                Ok(0) => std::process::exit(0),
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
                Err(_) => std::process::exit(1),
            }
        }
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

pub struct RunningProcess {
    pid: Pid,
}

impl RunningProcess {
    pub fn try_wait(&self) -> Result<Option<WaitStatus>, Errno> {
        Ok(match waitpid(self.pid, Some(WaitPidFlag::WNOHANG))? {
            WaitStatus::StillAlive => None,
            s => Some(s),
        })
    }

    pub fn wait(self) -> Result<WaitStatus, Errno> {
        waitpid(self.pid, None)
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
