use memmap2::{Mmap, MmapOptions};
use std::fs;
use std::io;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::ExitStatus;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

static NEXT_TEMP_PATH: AtomicU64 = AtomicU64::new(0);

fn temp_path(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "stackpulse-{name}-{}-{}",
        std::process::id(),
        NEXT_TEMP_PATH.fetch_add(1, Ordering::Relaxed)
    ))
}

pub(crate) struct TempDir(PathBuf);

impl TempDir {
    pub(crate) fn new(name: &str) -> Self {
        let path = temp_path(name);
        fs::create_dir_all(&path).expect("create temp dir");
        Self(path)
    }

    pub(crate) fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

pub(crate) fn mmap_from_bytes(bytes: &[u8]) -> Arc<Mmap> {
    let mut mmap = MmapOptions::new()
        .len(bytes.len())
        .map_anon()
        .expect("create anonymous mmap");
    mmap.copy_from_slice(bytes);
    Arc::new(mmap.make_read_only().expect("make mmap read-only"))
}

pub(crate) struct SleepChild {
    pid: Option<libc::pid_t>,
}

impl SleepChild {
    pub(crate) fn spawn() -> Self {
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork test child: {}", io::Error::last_os_error());
        if pid == 0 {
            unsafe {
                reset_signal(libc::SIGINT);
                reset_signal(libc::SIGTERM);
                let mut mask = std::mem::zeroed();
                libc::sigemptyset(&mut mask);
                libc::sigprocmask(libc::SIG_SETMASK, &mask, std::ptr::null_mut());
                loop {
                    libc::pause();
                }
            }
        }
        Self { pid: Some(pid) }
    }

    pub(crate) fn pid_i32(&self) -> i32 {
        self.pid.expect("child still present")
    }

    pub(crate) fn pid_u32(&self) -> u32 {
        self.pid.expect("child still present") as u32
    }

    pub(crate) fn wait_timeout(&mut self, timeout: Duration) -> io::Result<Option<ExitStatus>> {
        let pid = self.pid.expect("child still present");
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(status) = wait_pid(pid, libc::WNOHANG)? {
                self.pid = None;
                return Ok(Some(status));
            }
            if Instant::now() >= deadline {
                return Ok(None);
            }
            thread::sleep(Duration::from_millis(5));
        }
    }
}

impl Drop for SleepChild {
    fn drop(&mut self) {
        if let Some(pid) = self.pid.take() {
            unsafe {
                libc::kill(pid, libc::SIGKILL);
            }
            let _ = wait_pid(pid, 0);
        }
    }
}

fn reset_signal(signum: libc::c_int) {
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = libc::SIG_DFL;
        libc::sigemptyset(&mut action.sa_mask);
        action.sa_flags = 0;
        libc::sigaction(signum, &action, std::ptr::null_mut());
    }
}

fn wait_pid(pid: libc::pid_t, flags: libc::c_int) -> io::Result<Option<ExitStatus>> {
    let mut status = 0;
    loop {
        let rc = unsafe { libc::waitpid(pid, &mut status, flags) };
        if rc == 0 {
            return Ok(None);
        }
        if rc == pid {
            return Ok(Some(ExitStatus::from_raw(status)));
        }
        let err = io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::EINTR) {
            return Err(err);
        }
    }
}
