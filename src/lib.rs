#![doc = include_str!("../docs/api.md")]
#![cfg(target_os = "linux")]
#![warn(missing_docs)]
#![warn(rustdoc::broken_intra_doc_links)]

#[cfg(any(test, feature = "bench-support"))]
#[doc(hidden)]
pub mod bench_support;
/// Child-process discovery for recorded targets.
pub mod children;
/// Recording and integration guide.
pub mod docs;
mod elf;
/// Typed errors returned by recording, spool, and symbolization workflows.
pub mod error;
/// Validated Linux process and thread identifiers.
pub mod identity;
mod linux;
mod module_base;
mod native_module;
mod proc_maps;
/// Resolved frames and symbol metadata returned by [`Symbolizer`].
pub mod profile;
/// Spool readers and raw recorded profile types.
pub mod spool;
/// Process liveness checks, exit watching, and signal helpers.
pub mod state;
mod stats;
pub mod symbolize;
mod symbols;
#[cfg(test)]
mod test_support;

pub use error::{Error, ErrorKind, Result};
pub use identity::{Pid, Tid};
pub use linux::{process, AttachMode, Recorder, RecorderOptions, RecordingSummary, SampleRate};
pub use spool::{Replay, Snapshot};
pub use symbolize::{StackCache, Symbolizer, SymbolizerBuilder};

const _: fn() = || {
    fn assert_send<T: Send>() {}
    fn assert_send_sync<T: Send + Sync>() {}

    assert_send::<Recorder>();
    assert_send_sync::<Replay>();
    assert_send_sync::<Snapshot>();
    assert_send_sync::<process::RunningProcess>();
    assert_send_sync::<process::SuspendedLaunchedProcess>();
};

/// Perf recording types and statistics.
pub mod record {
    use std::io;

    pub use crate::linux::perf_event::{PerfFrequencyLimit, MAX_SAMPLE_USER_STACK};
    pub use crate::linux::{
        AttachMode, AttachOutcome, PollSummary, Recorder, RecorderOptions, RecordingSummary,
        RefreshOutcome, SampleRate,
    };
    pub use crate::stats::{SampleErrorKind, SampleErrorStats};

    /// Read the kernel's current maximum perf sample rate.
    #[must_use]
    pub fn max_sample_rate() -> Option<u64> {
        read_max_sample_rate().ok()
    }

    pub(crate) fn read_max_sample_rate() -> io::Result<u64> {
        const PATH: &str = "/proc/sys/kernel/perf_event_max_sample_rate";
        let data = std::fs::read_to_string(PATH).map_err(|source| {
            let kind = source.kind();
            io::Error::new(kind, MaxSampleRateError::Read { source })
        })?;
        data.trim().parse().map_err(|source| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                MaxSampleRateError::Parse { source },
            )
        })
    }

    #[derive(Debug, thiserror::Error)]
    enum MaxSampleRateError {
        #[error("failed to read /proc/sys/kernel/perf_event_max_sample_rate: {source}")]
        Read {
            #[source]
            source: io::Error,
        },
        #[error("/proc/sys/kernel/perf_event_max_sample_rate is not an integer: {source}")]
        Parse {
            #[source]
            source: std::num::ParseIntError,
        },
    }
}

/// Display-friendly basename for a module path.
///
/// Returns the final path component, falling back to the full
/// path when it has no basename and to `"<unknown>"` when the path is not
/// valid UTF-8. Used for grouping and labeling frames by their owning module.
#[must_use]
pub(crate) fn path_name(path: &std::path::Path) -> &str {
    path.file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_else(|| path.to_str().unwrap_or("<unknown>"))
}

/// Heuristic check for whether a module *basename* belongs to a Python runtime.
///
/// Matches `python`, versioned interpreters such as `python3.12`, the `t`/`d`
/// ABI variants (`python3.13t`, `python3.12d`), and the matching shared
/// libraries (`libpython3.12.so`, `libpython3.12.dylib`, with optional minor
/// suffixes after the extension). Returns `false` for extension modules and
/// other libraries that happen to start with `python`.
#[must_use]
pub(crate) fn is_python_module(name: &str) -> bool {
    is_python_executable_name(name) || lib_name_matches_libpython(name)
}

/// Compiles the README examples as doctests without rendering it twice.
#[cfg(doctest)]
#[doc = include_str!("../README.md")]
pub struct ReadmeDoctests;

/// Check if a module path is the Python runtime itself (the `python` binary or
/// `libpythonX.Y.so`), as opposed to extension modules and third-party libs.
pub(crate) fn is_python_runtime_module_path(module_path: impl AsRef<std::path::Path>) -> bool {
    let module_path = module_path.as_ref();
    module_path
        .file_name()
        .unwrap_or(module_path.as_os_str())
        .to_str()
        .is_some_and(is_python_module)
}

#[inline]
fn strip_ascii_prefix<'a>(value: &'a str, prefix: &str) -> Option<&'a str> {
    let head = value.get(..prefix.len())?;
    if head.eq_ignore_ascii_case(prefix) {
        value.get(prefix.len()..)
    } else {
        None
    }
}

#[inline]
fn is_dotted_numeric(value: &str) -> bool {
    !value.is_empty()
        && value
            .split('.')
            .all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()))
}

#[inline]
fn is_supported_python_abi_tag(b: u8) -> bool {
    matches!(b, b'd' | b't')
}

#[inline]
fn is_python_version_with_optional_abi_suffix(value: &str) -> bool {
    let version_end = value
        .find(|c: char| !c.is_ascii_digit() && c != '.')
        .unwrap_or(value.len());
    let (version, abi_suffix) = value.split_at(version_end);

    let version_ok = if version.contains('.') {
        is_dotted_numeric(version)
    } else {
        version.len() == 1 && version.bytes().all(|b| b.is_ascii_digit())
    };

    version_ok && abi_suffix.bytes().all(is_supported_python_abi_tag)
}

#[inline]
fn is_python_executable_name(basename: &str) -> bool {
    match strip_ascii_prefix(basename, "python") {
        Some(rest) => rest.is_empty() || is_python_version_with_optional_abi_suffix(rest),
        None => false,
    }
}

fn lib_name_matches_libpython(lib: &str) -> bool {
    let Some(rest) = strip_ascii_prefix(lib, "libpython") else {
        return false;
    };
    if let Some(pos) = rest.find(".so") {
        let version = &rest[..pos];
        let tail = &rest[pos + 3..];
        if is_python_version_with_optional_abi_suffix(version)
            && (tail.is_empty() || tail.starts_with('.'))
        {
            return true;
        }
    }
    if let Some(pos) = rest.find(".dylib") {
        let version = &rest[..pos];
        let tail = &rest[pos + ".dylib".len()..];
        if is_python_version_with_optional_abi_suffix(version) && tail.is_empty() {
            return true;
        }
    }
    false
}
