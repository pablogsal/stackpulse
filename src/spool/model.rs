use std::hash::{Hash, Hasher};
use std::io;
use std::ops::{Deref, Range};
use std::path::Path;
use std::sync::Arc;

use crate::{Pid, Tid};
use memmap2::Mmap;

pub(crate) const VDSO_PATH: &str = "[vdso]";

/// File path or display name for a recorded module.
#[derive(Clone)]
pub struct ModulePath(Arc<str>);

impl ModulePath {
    /// Borrow the path as a `&str`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Borrow the underlying UTF-8 bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.as_str().as_bytes()
    }

    /// Borrow the path as a [`Path`].
    #[must_use]
    pub fn as_path(&self) -> &Path {
        Path::new(self.as_str())
    }

    /// Whether the path string is empty (typical for kernel-marker records).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.as_str().is_empty()
    }

    pub(crate) fn is_bracketed_mapping(&self) -> bool {
        self.as_str().starts_with('[')
    }

    pub(crate) fn is_vdso(&self) -> bool {
        self.as_str() == VDSO_PATH
    }

    pub(super) fn from_mmap(mmap: Arc<Mmap>, range: Range<usize>) -> io::Result<Self> {
        let bytes = mmap
            .get(range)
            .ok_or_else(|| super::invalid_data("module path range is outside the spool"))?;
        let path =
            std::str::from_utf8(bytes).map_err(|err| super::invalid_data(err.to_string()))?;
        Ok(Self(Arc::from(path)))
    }
}

impl Deref for ModulePath {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.as_str()
    }
}

impl AsRef<str> for ModulePath {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl AsRef<std::ffi::OsStr> for ModulePath {
    fn as_ref(&self) -> &std::ffi::OsStr {
        std::ffi::OsStr::new(self.as_str())
    }
}

impl AsRef<Path> for ModulePath {
    fn as_ref(&self) -> &Path {
        Path::new(self.as_str())
    }
}

impl std::borrow::Borrow<str> for ModulePath {
    fn borrow(&self) -> &str {
        self.as_str()
    }
}

impl From<String> for ModulePath {
    fn from(path: String) -> Self {
        Self(Arc::from(path.into_boxed_str()))
    }
}

impl From<&str> for ModulePath {
    fn from(path: &str) -> Self {
        Self(Arc::from(path))
    }
}

impl From<ModulePath> for std::rc::Rc<str> {
    fn from(path: ModulePath) -> Self {
        path.as_str().into()
    }
}

impl std::fmt::Debug for ModulePath {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.as_str().fmt(fmt)
    }
}

impl std::fmt::Display for ModulePath {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fmt.write_str(self.as_str())
    }
}

impl PartialEq for ModulePath {
    fn eq(&self, other: &Self) -> bool {
        self.as_str() == other.as_str()
    }
}

impl Eq for ModulePath {}

impl Hash for ModulePath {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.as_str().hash(state);
    }
}

/// One executable memory mapping recorded in a spool file.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct ModuleRecord {
    /// Stable module id within the spool.
    pub(crate) id: u32,
    /// Process that owned this code area, or the kernel.
    pub(crate) owner: ModuleOwner,
    /// Start address in memory.
    pub(crate) start: u64,
    /// End address in memory.
    pub(crate) end: u64,
    /// File offset backing the start address.
    pub(crate) file_offset: u64,
    /// File inode, when available.
    pub(crate) inode: u64,
    /// Device major number, when available.
    pub(crate) device_major: u32,
    /// Device minor number, when available.
    pub(crate) device_minor: u32,
    /// Inode generation reported by `PERF_RECORD_MMAP2`, when available.
    pub(crate) inode_generation: u64,
    /// File path or display name.
    pub(crate) path: ModulePath,
}

/// Validated owner of an executable mapping.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum ModuleOwner {
    Process(Pid),
    Kernel,
}

impl ModuleOwner {
    pub(super) fn from_wire(process_id: i32, is_kernel: bool) -> io::Result<Self> {
        if is_kernel {
            return Ok(Self::Kernel);
        }
        Pid::try_from(process_id)
            .map(Self::Process)
            .map_err(|error| super::invalid_data(error.to_string()))
    }

    pub(crate) const fn pid(self) -> Option<Pid> {
        match self {
            Self::Process(pid) => Some(pid),
            Self::Kernel => None,
        }
    }

    pub(crate) const fn wire_process_id(self) -> i32 {
        match self {
            Self::Process(pid) => pid.get(),
            Self::Kernel => -1,
        }
    }

    pub(crate) const fn is_kernel(self) -> bool {
        matches!(self, Self::Kernel)
    }
}

impl ModuleRecord {
    /// Return the spool-local mapping id.
    #[must_use]
    pub const fn id(&self) -> u32 {
        self.id
    }

    /// Return the process that owns this mapping, or `None` for kernel code.
    #[must_use]
    pub const fn pid(&self) -> Option<Pid> {
        self.owner.pid()
    }

    /// Return the mapped absolute address range.
    #[must_use]
    pub const fn address_range(&self) -> std::ops::Range<u64> {
        self.start..self.end
    }

    /// Return the file offset backing the mapping start.
    #[must_use]
    pub const fn file_offset(&self) -> u64 {
        self.file_offset
    }

    /// Return the recorded inode, or zero when unavailable.
    #[must_use]
    pub const fn inode(&self) -> u64 {
        self.inode
    }

    /// Return the recorded device major number, or zero when unavailable.
    #[must_use]
    pub const fn device_major(&self) -> u32 {
        self.device_major
    }

    /// Return the recorded device minor number, or zero when unavailable.
    #[must_use]
    pub const fn device_minor(&self) -> u32 {
        self.device_minor
    }

    /// Return the inode generation, or zero when unavailable.
    #[must_use]
    pub const fn inode_generation(&self) -> u64 {
        self.inode_generation
    }

    /// Borrow the recorded path or mapping name.
    #[must_use]
    pub const fn path(&self) -> &ModulePath {
        &self.path
    }

    /// Return whether this mapping contains kernel code.
    #[must_use]
    pub const fn is_kernel(&self) -> bool {
        self.owner.is_kernel()
    }

    pub(crate) const fn wire_process_id(&self) -> i32 {
        self.owner.wire_process_id()
    }

    #[cfg(test)]
    pub(crate) fn set_pid(&mut self, pid: Pid) {
        self.owner = ModuleOwner::Process(pid);
    }

    /// Construct a user-space mapping with unknown file identity.
    ///
    /// # Errors
    ///
    /// Returns an invalid-input error when `addresses` is empty or reversed.
    pub fn new(
        id: u32,
        process_id: Pid,
        addresses: std::ops::Range<u64>,
        file_offset: u64,
        path: impl Into<ModulePath>,
    ) -> crate::Result<Self> {
        if addresses.start >= addresses.end {
            return Err(crate::Error::message(
                crate::ErrorKind::InvalidInput,
                "module address range must be non-empty",
            ));
        }
        Ok(Self {
            id,
            owner: ModuleOwner::Process(process_id),
            start: addresses.start,
            end: addresses.end,
            file_offset,
            inode: 0,
            device_major: 0,
            device_minor: 0,
            inode_generation: 0,
            path: path.into(),
        })
    }

    /// Attach verified filesystem identity to this mapping.
    #[must_use]
    pub fn file_identity(
        mut self,
        device_major: u32,
        device_minor: u32,
        inode: u64,
        inode_generation: u64,
    ) -> Self {
        self.device_major = device_major;
        self.device_minor = device_minor;
        self.inode = inode;
        self.inode_generation = inode_generation;
        self
    }

    /// Construct a kernel mapping.
    ///
    /// # Errors
    ///
    /// Returns an invalid-input error when `addresses` is empty or reversed.
    pub fn kernel(
        id: u32,
        addresses: std::ops::Range<u64>,
        path: impl Into<ModulePath>,
    ) -> crate::Result<Self> {
        if addresses.start >= addresses.end {
            return Err(crate::Error::message(
                crate::ErrorKind::InvalidInput,
                "module address range must be non-empty",
            ));
        }
        Ok(Self {
            id,
            owner: ModuleOwner::Kernel,
            start: addresses.start,
            end: addresses.end,
            file_offset: 0,
            inode: 0,
            device_major: 0,
            device_minor: 0,
            inode_generation: 0,
            path: path.into(),
        })
    }
}

/// Whether a frame came from user code or kernel code.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum FrameMode {
    /// User-space frame.
    User,
    /// Kernel-space frame.
    Kernel,
    /// Marker emitted when native unwinding stopped before reaching the stack root.
    TruncatedStackMarker,
}

/// A raw frame stored in a spool file.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FrameRecord {
    /// Module id when the frame was matched to a module.
    pub module_id: Option<u32>,
    /// Address in the matched module's file-offset coordinate space.
    pub file_relative_ip: u64,
    /// Absolute instruction pointer.
    pub abs_ip: u64,
    /// User/kernel mode for the frame.
    pub mode: FrameMode,
}

impl FrameRecord {
    /// Sentinel frame written when native unwinding stopped before the stack
    /// root (typically because `stack_size` was exhausted). Encoded with a
    /// reserved mode tag so it round-trips through the spool.
    #[must_use]
    pub fn truncated_stack_marker() -> Self {
        Self {
            module_id: None,
            file_relative_ip: 0,
            abs_ip: 0,
            mode: FrameMode::TruncatedStackMarker,
        }
    }

    /// Whether this frame is the [`Self::truncated_stack_marker`] sentinel
    /// rather than a real sampled IP.
    #[must_use]
    pub fn is_truncated_stack_marker(&self) -> bool {
        *self == Self::truncated_stack_marker()
    }
}

/// A sample record loaded from a spool file.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SampleRecord {
    /// Monotonic timestamp in nanoseconds.
    pub timestamp_ns: u64,
    /// Process id for the sample.
    pub process_id: Pid,
    /// Thread id for the sample.
    pub thread_id: Tid,
    /// Stack id used with spool-reader stack accessors.
    pub(crate) stack_id: u32,
}

/// Process and thread identity interned by a spool.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ThreadRecord {
    /// Process that owns the thread.
    pub process_id: Pid,
    /// Linux thread id.
    pub thread_id: Tid,
}

/// Marker for a process's Python-runtime status during recording.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PythonRuntimeRecord {
    /// Monotonic timestamp in nanoseconds.
    pub timestamp_ns: u64,
    /// Process id.
    pub process_id: Pid,
    /// Whether the process looked like a Python runtime.
    pub is_python_runtime: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::mmap_from_bytes;

    #[test]
    fn mmap_module_path_validates_utf8_and_range() {
        let mmap = mmap_from_bytes(b"prefix:/lib/libc.so\xff[vdso]");

        let path = ModulePath::from_mmap(mmap.clone(), 7..19).expect("valid path");
        let vdso = ModulePath::from_mmap(mmap.clone(), 20..26).expect("valid vdso path");

        assert_eq!(path.as_str(), "/lib/libc.so");
        assert_eq!(path.as_path(), Path::new("/lib/libc.so"));
        assert_eq!(path, ModulePath::from("/lib/libc.so"));
        assert!(!path.is_bracketed_mapping());
        assert!(vdso.is_bracketed_mapping());
        assert!(ModulePath::from_mmap(mmap.clone(), 19..20).is_err());
        assert!(ModulePath::from_mmap(mmap, 100..101).is_err());
    }
}
