//! Linux perf-map parsing and frame conversion.

use std::fs::File;
use std::io::Read;
use std::os::unix::fs::{FileTypeExt, OpenOptionsExt};
use std::path::Path;
use std::rc::Rc;

use rustc_hash::FxHashSet;

use crate::profile::{
    FrameFlags, FrameKind, LocationInfo, NativeFrame, NativeSymbol, PythonFrame, ResolvedFrame,
    SourceLocation, SymbolOrigin,
};
use crate::spool::ModuleRecord;

/// Which processes may use Python perf-map lookups.
pub(super) enum PerfMapProcesses {
    /// Allow perf-map lookup for every process.
    All,
    /// Allow perf-map lookup only for the listed process ids.
    Pids(FxHashSet<crate::Pid>),
}

#[derive(Clone)]
pub(super) struct PerfMapSymbol {
    start: u64,
    end: u64,
    payload: PerfMapPayload,
}

#[derive(Clone)]
enum PerfMapPayload {
    Native(Rc<str>),
    Python { function: Rc<str>, file: Rc<str> },
}

pub(super) struct PerfMap {
    symbols: Vec<PerfMapSymbol>,
    module: Rc<str>,
}

pub(super) fn perf_map_module_allowed(module: &ModuleRecord) -> bool {
    is_perf_map_mapping(&module.path)
}

pub(super) fn find_perf_map_symbol(
    perf_map: &PerfMap,
    address: u64,
) -> Option<(&PerfMapSymbol, &Rc<str>)> {
    let symbol = perf_map.symbols[..perf_map
        .symbols
        .partition_point(|symbol| symbol.start <= address)]
        .iter()
        .rfind(|symbol| address < symbol.end)?;
    Some((symbol, &perf_map.module))
}

pub(super) fn perf_map_symbol_to_frame(
    abs_ip: u64,
    symbol: PerfMapSymbol,
    module: Rc<str>,
) -> ResolvedFrame {
    let PerfMapSymbol { start, payload, .. } = symbol;
    let name = match payload {
        PerfMapPayload::Python { function, file } => {
            return ResolvedFrame::Python(
                PythonFrame::new(file, LocationInfo::default(), function, None, false)
                    .with_flags(FrameFlags::JIT),
            );
        }
        PerfMapPayload::Native(name) => name,
    };
    let native_symbol = NativeSymbol::new(
        name,
        SourceLocation::default(),
        module,
        abs_ip.saturating_sub(start),
    );
    ResolvedFrame::Native(NativeFrame {
        pc: abs_ip,
        symbol: Some(native_symbol),
        kind: FrameKind::Native,
        origin: SymbolOrigin::PerfMap,
        flags: FrameFlags::JIT,
    })
}

pub(super) fn parse_python_perf_map_symbol(name: &str) -> Option<(&str, &str)> {
    let body = name.strip_prefix("py::")?.trim();
    if body.is_empty() {
        return None;
    }

    let colon_index = body.find(':');
    let space_index = body.find(' ');
    let (func, file) = match (colon_index, space_index) {
        (Some(colon), Some(space)) if colon < space => (&body[..colon], &body[colon + 1..]),
        (Some(colon), None) => (&body[..colon], &body[colon + 1..]),
        (_, Some(space)) => (&body[..space], &body[space + 1..]),
        (None, None) => (body, "~"),
    };

    let func = func.trim();
    if func.is_empty() {
        return None;
    }

    let file = strip_python_perf_map_line_suffix(file.trim());
    Some((func, if file.is_empty() { "~" } else { file }))
}

fn strip_python_perf_map_line_suffix(file: &str) -> &str {
    if let Some((path, line)) = file.rsplit_once(':') {
        if !path.is_empty() && line.chars().all(|character| character.is_ascii_digit()) {
            return path;
        }
    }
    file
}

fn is_perf_map_mapping(path: &str) -> bool {
    path == "//anon"
        || path == "[anon]"
        || path.starts_with("[anon:")
        || path == "[heap]"
        || path.starts_with("[stack")
        || path.starts_with("/dev/zero")
        || path.starts_with("/anon_hugepage")
        || path.starts_with("/SYSV")
}

pub(super) fn load_perf_map(directory: &Path, process_id: i32) -> Option<PerfMap> {
    const MAX_PERF_MAP_SIZE: u64 = 64 * 1024 * 1024;
    let path = directory.join(format!("perf-{process_id}.map"));
    let mut file = File::options()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NONBLOCK | libc::O_NOFOLLOW)
        .open(&path)
        .ok()?;
    let metadata = file.metadata().ok()?;
    if !metadata.is_file() || metadata.file_type().is_fifo() || metadata.len() > MAX_PERF_MAP_SIZE {
        return None;
    }
    let mut text = String::with_capacity(usize::try_from(metadata.len()).ok()?);
    file.by_ref()
        .take(MAX_PERF_MAP_SIZE + 1)
        .read_to_string(&mut text)
        .ok()?;
    if text.len() as u64 > MAX_PERF_MAP_SIZE {
        return None;
    }
    let mut symbols: Vec<PerfMapSymbol> = text.lines().filter_map(parse_perf_map_line).collect();
    symbols.sort_by_key(|symbol| symbol.start);
    Some(PerfMap {
        symbols,
        module: path.to_string_lossy().as_ref().into(),
    })
}

fn parse_perf_map_line(line: &str) -> Option<PerfMapSymbol> {
    let (start, rest) = take_ascii_field(line)?;
    let (len, name) = take_ascii_field(rest)?;
    if name.is_empty() {
        return None;
    }
    let start = u64::from_str_radix(start.trim_start_matches("0x"), 16).ok()?;
    let len = u64::from_str_radix(len.trim_start_matches("0x"), 16).ok()?;
    if len == 0 {
        return None;
    }
    let end = start.checked_add(len)?;
    let payload = parse_python_perf_map_symbol(name).map_or_else(
        || PerfMapPayload::Native(name.into()),
        |(function, file)| PerfMapPayload::Python {
            function: function.into(),
            file: file.into(),
        },
    );
    Some(PerfMapSymbol {
        start,
        end,
        payload,
    })
}

fn take_ascii_field(input: &str) -> Option<(&str, &str)> {
    let input = input.trim_start_matches(|character: char| character.is_ascii_whitespace());
    let end = input.find(|character: char| character.is_ascii_whitespace())?;
    Some((&input[..end], &input[end + 1..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overflowing_perf_map_range_does_not_match() {
        assert!(parse_perf_map_line("1000 ffffffffffffffff overflow_symbol").is_none());
    }

    #[test]
    fn perf_map_fields_accept_ascii_whitespace() {
        for (line, expected_name) in [
            ("1000 10 controlled name", "controlled name"),
            ("1000  10 controlled name", "controlled name"),
            ("1000\t10\tcontrolled name", "controlled name"),
            (" \t1000 \t 10 controlled name", "controlled name"),
            ("1000 10  controlled name", " controlled name"),
            ("1000 10\t\tcontrolled name", "\tcontrolled name"),
        ] {
            let symbol = parse_perf_map_line(line).expect("valid perf-map entry");
            let PerfMapPayload::Native(name) = symbol.payload else {
                panic!("expected native perf-map symbol")
            };
            assert_eq!(
                (symbol.start, symbol.end, name.as_ref()),
                (0x1000, 0x1010, expected_name)
            );
        }
    }

    #[test]
    fn malformed_perf_map_fields_are_rejected() {
        for line in [
            "",
            "1000",
            "1000 10",
            "1000 10 ",
            "1000 0 symbol",
            "not-hex 10 symbol",
            "1000 not-hex symbol",
            "1000\u{a0}10 symbol",
        ] {
            assert!(parse_perf_map_line(line).is_none(), "accepted {line:?}");
        }
    }
}
