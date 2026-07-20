#![doc = include_str!("../docs/api.md")]
#![doc = "\n\n"]
#![doc = include_str!("../docs/tutorials.md")]
#![doc = "\n\n"]
#![doc = include_str!("../docs/how-to.md")]
#![doc = "\n\n"]
#![doc = include_str!("../docs/reference.md")]
#![doc = "\n\n"]
#![doc = include_str!("../docs/explanation.md")]
#![cfg(target_os = "linux")]
#![warn(missing_docs)]
#![warn(rustdoc::broken_intra_doc_links)]

#[cfg(any(test, feature = "bench-support"))]
#[doc(hidden)]
pub mod bench_support;
/// Helpers for discovering and following child processes spawned by a target.
///
/// Used when the caller asks the recorder to capture not just the supplied
/// PID but the descendants it spawns after attach.
pub mod children;
mod elf;
mod error;
mod linux;
mod module_base;
mod native_module;
mod proc_maps;
/// Post-symbolization frame model returned by [`PerfSymbolizer`].
///
/// Each [`ResolvedFrame`] carries either a [`NativeFrame`] or a
/// [`PythonFrame`] plus a [`FrameFlags`] bitset describing how it was
/// recovered. Use these types to build flame graphs, format reports, or
/// feed downstream profile encoders. Consumers that prefer raw IPs can
/// skip symbolization entirely and read [`FrameRecord`]s from the spool.
pub mod profile;
mod spool;
/// Process-state snapshots used by the recorder to translate kernel events.
///
/// Exposes the minimal `/proc` parsing that stackpulse performs on attach so
/// integrators can mirror it (for example, to seed their own module table
/// before replaying a spool).
pub mod state;
mod stats;
mod symbolize;
mod symbols;
#[cfg(test)]
mod test_support;

pub use error::{ElfParseError, Error};
pub use linux::perf_event::PerfFrequencyLimit;
pub use linux::perf_event::MAX_SAMPLE_USER_STACK;
pub use linux::{process, AttachMode, PerfRecorder, PerfRecorderOptions, PerfSummary};
pub use module_base::ModuleImageBase;
pub use profile::{
    FrameFlags, FrameKind, LocationInfo, NativeFrame, NativeSymbol, PythonFrame, ResolvedFrame,
    SourceLocation, SymbolOrigin,
};
pub use spool::{
    FrameContext, FrameMode, FrameModuleRef, FrameRecord, ModulePath, ModuleRecord,
    OwnedSampleRecord, PerfSpoolReader, ProcessExecRecord, SampleStack, SampleStacks,
    StackFrameContexts, StackFrameRefs,
};
pub use stats::{ErrorStatsFormatter, SampleErrorKind, SampleErrorStats};
pub use symbolize::PerfSymbolizer;
pub use symbols::{
    default_native_symbolizer_factory, NativeSymbolizer, NativeSymbolizerFactory, SymModule,
    SymbolsRc,
};

/// Read the kernel's current maximum perf sample rate, in samples per second.
///
/// Reads `/proc/sys/kernel/perf_event_max_sample_rate`, the kernel ceiling
/// the recorder must stay under (otherwise it returns [`PerfFrequencyLimit`]).
/// Returns `None` if the file cannot be read or parsed (older kernels,
/// restricted procfs, sandboxed mounts).
pub fn max_sample_rate() -> Option<u64> {
    let data = std::fs::read_to_string("/proc/sys/kernel/perf_event_max_sample_rate").ok()?;
    data.trim().parse().ok()
}

/// Display-friendly basename for a module path.
///
/// Returns the final path component as a `String`, falling back to the full
/// path when it has no basename and to `"<unknown>"` when the path is not
/// valid UTF-8. Used for grouping and labeling frames by their owning module.
#[must_use]
pub fn path_to_name(path: &std::path::Path) -> String {
    path.file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_else(|| path.to_str().unwrap_or("<unknown>"))
        .to_owned()
}

/// Heuristic check for whether a module *basename* belongs to a Python runtime.
///
/// Matches `python`, versioned interpreters such as `python3.12`, the `t`/`d`
/// ABI variants (`python3.13t`, `python3.12d`), and the matching shared
/// libraries (`libpython3.12.so`, `libpython3.12.dylib`, with optional minor
/// suffixes after the extension). Returns `false` for extension modules and
/// other libraries that happen to start with `python`.
#[must_use]
pub fn is_python_module(name: &str) -> bool {
    is_python_executable_name(name) || lib_name_matches_libpython(name)
}

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
