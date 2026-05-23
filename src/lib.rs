//! Linux `perf_event_open` stack sampling, native unwinding, symbolization,
//! and compact stack spooling.

#![cfg(target_os = "linux")]
#![allow(dead_code)]

pub mod children;
mod elf;
mod error;
mod linux;
mod module_base;
mod module_traits;
mod native_module;
mod proc_maps;
pub mod profile;
mod spool;
pub mod state;
mod stats;
mod symbolize;
mod symbols;

pub use error::{Error, Result};
pub use linux::perf_event::PerfFrequencyLimit;
pub use linux::perf_event::MAX_SAMPLE_USER_STACK;
pub use linux::{process, AttachMode, PerfRecorder, PerfRecorderOptions, PerfSummary};
pub use module_base::ModuleImageBase;
pub use profile::{
    FrameFlags, FrameKind, LocationInfo, NativeFrame, NativeSymbol, PythonFrame, ResolvedFrame,
    ResolvedStack, SourceLocation, StackFrames, SymbolOrigin,
};
pub use spool::{FrameMode, FrameRecord, ModuleRecord, OwnedSampleRecord, PerfSpoolReader};
pub use stats::{ErrorStatsFormatter, SampleErrorKind, SampleErrorStats};
pub use symbolize::PerfSymbolizer;

pub(crate) type FramehopSectionData = linux::elf_types::ElfSectionData;

pub fn max_sample_rate() -> Option<u64> {
    let data = std::fs::read_to_string("/proc/sys/kernel/perf_event_max_sample_rate").ok()?;
    data.trim().parse().ok()
}

#[must_use]
pub fn path_to_name(path: &std::path::Path) -> String {
    path.file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_else(|| path.to_str().unwrap_or("<unknown>"))
        .to_owned()
}

#[must_use]
pub fn is_python_module(name: &str) -> bool {
    is_python_executable_name(name) || lib_name_matches_libpython(name)
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
