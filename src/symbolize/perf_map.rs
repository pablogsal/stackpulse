//! Linux perf-map parsing and frame conversion.

use std::fs::File;
use std::io::Read;
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::rc::Rc;

use rustc_hash::FxHashSet;

use crate::profile::{
    AddressSpace, Frame, FrameFlags, NativeFrame, NativeSymbol, PythonFrame, SymbolOrigin,
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

const MAX_PERF_MAP_SIZE: u64 = 64 * 1024 * 1024;

pub(super) struct PerfMap {
    symbols: Vec<PerfMapSymbol>,
    /// Largest `end` among `symbols[..=index]`, so lookups can stop walking back early.
    max_end: Box<[u64]>,
    module: Rc<str>,
    /// Kept only for maps that may be reloaded.
    parsed: Option<ParsedPerfMapText>,
}

/// The complete lines a perf map was parsed from, so a reload can parse only
/// the lines appended after them.
struct ParsedPerfMapText {
    /// Runtimes may rewrite a map in place, so a reload compares these bytes
    /// with the file instead of trusting the length.
    text: Vec<u8>,
    unterminated_start: Option<u64>,
}

impl PerfMap {
    fn new(
        mut symbols: Vec<PerfMapSymbol>,
        module: Rc<str>,
        parsed: Option<ParsedPerfMapText>,
    ) -> Self {
        // On a reload the earlier lines are already sorted, so this stable sort
        // merges in the appended ones after any earlier entries with the same start.
        symbols.sort_by_key(|symbol| symbol.start);
        let mut running_max = 0;
        let max_end = symbols
            .iter()
            .map(|symbol| {
                running_max = symbol.end.max(running_max);
                running_max
            })
            .collect();
        Self {
            symbols,
            max_end,
            module,
            parsed,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct PerfMapFileIdentity {
    device: u64,
    inode: u64,
    size: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}

pub(super) fn perf_map_file_identity(path: &Path) -> Option<PerfMapFileIdentity> {
    let metadata = std::fs::symlink_metadata(path).ok()?;
    metadata
        .file_type()
        .is_file()
        .then_some(PerfMapFileIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
            size: metadata.size(),
            modified: (metadata.mtime(), metadata.mtime_nsec()),
            changed: (metadata.ctime(), metadata.ctime_nsec()),
        })
}

pub(super) fn perf_map_module_allowed(module: &ModuleRecord) -> bool {
    module.path.to_str().is_some_and(is_perf_map_mapping)
}

pub(super) fn find_perf_map_symbol(
    perf_map: &PerfMap,
    address: u64,
) -> Option<(&PerfMapSymbol, &Rc<str>)> {
    let candidates = perf_map
        .symbols
        .partition_point(|symbol| symbol.start <= address);
    let (symbol, _) = perf_map.symbols[..candidates]
        .iter()
        .zip(&perf_map.max_end[..candidates])
        .rev()
        .take_while(|(_, &max_end)| address < max_end)
        .find(|(symbol, _)| address < symbol.end)?;
    Some((symbol, &perf_map.module))
}

pub(super) fn perf_map_symbol_to_frame(
    abs_ip: u64,
    symbol: PerfMapSymbol,
    module: Rc<str>,
) -> Frame {
    let PerfMapSymbol { start, payload, .. } = symbol;
    let name = match payload {
        PerfMapPayload::Python { function, file } => {
            return Frame::Python(PythonFrame::new(file, function).with_flags(FrameFlags::JIT));
        }
        PerfMapPayload::Native(name) => name,
    };
    let native_symbol = NativeSymbol::new(name, module).with_offset(abs_ip.saturating_sub(start));
    Frame::Native(NativeFrame {
        pc: abs_ip,
        symbol: Some(native_symbol),
        address_space: AddressSpace::User,
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
        if !path.is_empty()
            && !line.is_empty()
            && line.chars().all(|character| character.is_ascii_digit())
        {
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

/// Loads the perf map at `path`. When `previous` was loaded from the same file
/// with `reloadable` set and its parsed lines are unchanged, only the lines
/// appended since are parsed. Only a `reloadable` map keeps its parsed text.
pub(super) fn load_perf_map(
    path: &Path,
    previous: Option<PerfMap>,
    reloadable: bool,
) -> Option<PerfMap> {
    let mut file = File::options()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NONBLOCK | libc::O_NOFOLLOW)
        .open(path)
        .ok()?;
    let metadata = file.metadata().ok()?;
    if !metadata.is_file() || metadata.file_type().is_fifo() || metadata.len() > MAX_PERF_MAP_SIZE {
        return None;
    }
    let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).ok()?);
    file.by_ref()
        .take(MAX_PERF_MAP_SIZE + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    if bytes.len() as u64 > MAX_PERF_MAP_SIZE {
        return None;
    }
    let (mut symbols, offset) = match previous {
        Some(PerfMap {
            mut symbols,
            parsed: Some(parsed),
            ..
        }) if bytes.starts_with(&parsed.text) => {
            if let Some(start) = parsed.unterminated_start {
                // The unterminated last line is parsed again below. Sorting is
                // stable, so it is the last entry with its start.
                symbols.remove(symbols.partition_point(|symbol| symbol.start <= start) - 1);
            }
            (symbols, parsed.text.len())
        }
        _ => (Vec::new(), 0),
    };
    let appended = &bytes[offset..];
    let (complete, unterminated) = appended.split_at(
        appended
            .iter()
            .rposition(|&byte| byte == b'\n')
            .map_or(0, |index| index + 1),
    );
    // Perf-map names are raw bytes, so one invalid name must not discard the
    // whole map. Both parts end at a line boundary or at the end of the file,
    // so this matches converting the whole file at once.
    symbols.extend(
        String::from_utf8_lossy(complete)
            .lines()
            .filter_map(parse_perf_map_line),
    );
    let unterminated = String::from_utf8_lossy(unterminated)
        .lines()
        .find_map(parse_perf_map_line);
    let unterminated_start = unterminated.as_ref().map(|symbol| symbol.start);
    symbols.extend(unterminated);
    bytes.truncate(offset + complete.len());
    Some(PerfMap::new(
        symbols,
        path.to_string_lossy().as_ref().into(),
        reloadable.then_some(ParsedPerfMapText {
            text: bytes,
            unterminated_start,
        }),
    ))
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
    use crate::test_support::TempDir;

    fn native_name(perf_map: &PerfMap, address: u64) -> Rc<str> {
        match &find_perf_map_symbol(perf_map, address).unwrap().0.payload {
            PerfMapPayload::Native(name) => Rc::clone(name),
            PerfMapPayload::Python { .. } => panic!("expected native perf-map symbol"),
        }
    }

    #[test]
    fn completed_unterminated_lines_replace_their_partial_entry() {
        let directory = TempDir::new("perf-map-unterminated");
        let path = directory.path().join("perf-1.map");
        std::fs::write(&path, "1000 10 a\n2000 10 na").unwrap();
        let perf_map = load_perf_map(&path, None, true);
        std::fs::write(&path, "1000 10 a\n2000 10 name\n").unwrap();

        let perf_map = load_perf_map(&path, perf_map, true).unwrap();
        assert_eq!(perf_map.symbols.len(), 2);
        assert_eq!(&*native_name(&perf_map, 0x2000), "name");
    }

    #[test]
    fn lookups_walk_back_past_shorter_nested_entries() {
        let directory = TempDir::new("perf-map-nested");
        let path = directory.path().join("perf-1.map");
        std::fs::write(&path, "1000 100 outer\n1010 8 inner\n").unwrap();

        let perf_map = load_perf_map(&path, None, true).unwrap();
        assert_eq!(&*native_name(&perf_map, 0x1050), "outer");
        assert!(find_perf_map_symbol(&perf_map, 0x1100).is_none());
    }

    #[test]
    fn python_source_suffix_requires_a_line_number() {
        for (name, expected_file) in [
            ("py::work:/tmp/file:", "/tmp/file:"),
            ("py::work:/tmp/file:123", "/tmp/file"),
            ("py::work:/tmp/file:version", "/tmp/file:version"),
            ("py::work:/tmp/file:version:123", "/tmp/file:version"),
        ] {
            assert_eq!(
                parse_python_perf_map_symbol(name),
                Some(("work", expected_file))
            );
        }
    }

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

    #[test]
    fn invalid_utf8_names_do_not_discard_the_perf_map() {
        let temp = TempDir::new("perf-map-invalid-utf8");
        let path = temp.path().join("perf-1.map");
        std::fs::write(&path, b"1000 10 good\n2000 10 bad_\xff\n").unwrap();

        let perf_map = load_perf_map(&path, None, true).expect("perf map with invalid UTF-8 names");
        assert_eq!(&*native_name(&perf_map, 0x1000), "good");
        assert_eq!(&*native_name(&perf_map, 0x2000), "bad_\u{fffd}");
    }
}
