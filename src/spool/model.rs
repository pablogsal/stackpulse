use std::hash::{Hash, Hasher};
use std::io;
use std::ops::{Deref, Range};
use std::path::Path;
use std::sync::Arc;

use memmap2::Mmap;

/// File path or display name for a recorded module.
#[derive(Clone)]
pub struct ModulePath(ModulePathStorage);

#[derive(Clone)]
enum ModulePathStorage {
    Owned(Arc<str>),
    Mmap {
        mmap: Arc<Mmap>,
        range: Range<usize>,
    },
}

impl ModulePath {
    /// Borrow the path as a `&str`. Free for owned paths; cheap for paths
    /// served directly out of the memory-mapped spool.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match &self.0 {
            ModulePathStorage::Owned(path) => path,
            ModulePathStorage::Mmap { mmap, range } => std::str::from_utf8(&mmap[range.clone()])
                .expect("mmap-backed module path was validated while reading the spool"),
        }
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

    pub(super) fn from_mmap(mmap: Arc<Mmap>, range: Range<usize>) -> io::Result<Self> {
        std::str::from_utf8(&mmap[range.clone()])
            .map_err(|err| super::invalid_data(err.to_string()))?;
        Ok(Self(ModulePathStorage::Mmap { mmap, range }))
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
        Self(ModulePathStorage::Owned(Arc::from(path.into_boxed_str())))
    }
}

impl From<&str> for ModulePath {
    fn from(path: &str) -> Self {
        Self(ModulePathStorage::Owned(Arc::from(path)))
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

/// A code area recorded in a profile file.
#[derive(Clone, Debug)]
pub struct ModuleRecord {
    /// Stable module id within the profile.
    pub id: u32,
    /// Process that owned this code area, or a kernel marker for kernel code.
    pub process_id: i32,
    /// Start address in memory.
    pub start: u64,
    /// End address in memory.
    pub end: u64,
    /// File offset backing the start address.
    pub file_offset: u64,
    /// File inode, when available.
    pub inode: u64,
    /// File path or display name.
    pub path: ModulePath,
    /// Whether this record is kernel code.
    pub is_kernel: bool,
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

/// A raw frame stored in a profile file.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FrameRecord {
    /// Module id when the frame was matched to a module.
    pub module_id: Option<u32>,
    /// Address relative to the matched module.
    pub rel_ip: u64,
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
            rel_ip: 0,
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

/// A sample record loaded from a profile file.
#[derive(Clone, Debug)]
pub struct OwnedSampleRecord {
    /// Monotonic timestamp in nanoseconds.
    pub timestamp_ns: u64,
    /// Process id for the sample.
    pub process_id: i32,
    /// Thread id for the sample.
    pub thread_id: u64,
    /// Stack id used with [`crate::PerfSpoolReader::stack_frames`].
    pub stack_id: u32,
}

/// Marker for a process that executed during recording.
#[derive(Clone, Debug)]
pub struct ProcessExecRecord {
    /// Monotonic timestamp in nanoseconds.
    pub timestamp_ns: u64,
    /// Process id.
    pub process_id: i32,
    /// Whether the process looked like a Python runtime.
    pub is_python_runtime: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::mmap_from_bytes;

    #[test]
    fn mmap_module_path_validates_utf8_and_borrows_range() {
        let mmap = mmap_from_bytes(b"prefix:/lib/libc.so\xff[vdso]");

        let path = ModulePath::from_mmap(mmap.clone(), 7..19).expect("valid path");
        let vdso = ModulePath::from_mmap(mmap.clone(), 20..26).expect("valid vdso path");

        assert_eq!(path.as_str(), "/lib/libc.so");
        assert_eq!(path.as_path(), Path::new("/lib/libc.so"));
        assert_eq!(path, ModulePath::from("/lib/libc.so"));
        assert!(!path.is_bracketed_mapping());
        assert!(vdso.is_bracketed_mapping());
        assert!(ModulePath::from_mmap(mmap, 19..20).is_err());
    }
}
