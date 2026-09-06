use crate::{Pid, Tid};
use std::io;

pub(crate) const VDSO_PATH: &str = "[vdso]";

/// A recorded filesystem path, preserving native operating-system bytes.
pub type ModulePath = std::sync::Arc<std::path::Path>;

/// One executable memory mapping recorded in a spool file.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Module {
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

impl Module {
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
    pub fn path(&self) -> &std::path::Path {
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
    #[cfg(any(test, feature = "bench-support"))]
    pub(crate) fn new(
        id: u32,
        process_id: Pid,
        addresses: std::ops::Range<u64>,
        file_offset: u64,
        path: impl AsRef<std::path::Path>,
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
            path: path.as_ref().into(),
        })
    }

    /// Attach verified filesystem identity to this mapping.
    #[must_use]
    #[cfg(any(test, feature = "bench-support"))]
    pub(crate) fn file_identity(
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
    #[cfg(any(test, feature = "bench-support"))]
    pub(crate) fn kernel(
        id: u32,
        addresses: std::ops::Range<u64>,
        path: impl AsRef<std::path::Path>,
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
            path: path.as_ref().into(),
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
    pub(crate) timestamp_ns: u64,
    /// Process id for the sample.
    pub(crate) process_id: Pid,
    /// Thread id for the sample.
    pub(crate) thread_id: Tid,
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

pub(crate) type ModuleRecord = Module;
