//! `/proc/kallsyms` loader and parser.
//!
//! `kallsyms` is the live kernel's symbol table. When readable, it is the best
//! source for kernel frames because addresses already include the current KASLR
//! slide and loaded module symbols. Spool symbolization usually needs only the
//! program counters (PCs) that appeared in samples, so this module can stream
//! the file once and keep only the nearest preceding symbol for each requested
//! PC. Module symbols are not listed in address order, so the sparse scan does
//! not depend on it.
//!
//! Zero addresses are ignored because kernels commonly expose symbol names but
//! replace addresses with `0` when symbol addresses are restricted.

use std::fs;
use std::io::{self, BufRead};

use memchr::memchr;
use rustc_hash::FxHashMap;

use super::{is_kernel_text_symbol, FullKernelSymbol, FullKernelSymbols, KernelSymbol};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct KernelSymbolMetadata<'a> {
    symbol_type: u8,
    name: &'a [u8],
    module: Option<&'a [u8]>,
}

const PERF_KERNEL_SYMBOL_TYPES: &[u8] = b"TWDB";

pub(super) fn load_kernel_symbols() -> io::Result<FullKernelSymbols> {
    let file = fs::File::open("/proc/kallsyms")?;
    parse_full_kernel_symbols(&mut io::BufReader::with_capacity(1024 * 1024, file))
}

pub(super) fn parse_full_kernel_symbols(
    reader: &mut impl BufRead,
) -> io::Result<FullKernelSymbols> {
    let mut builder = FullKernelSymbolsBuilder::default();
    let mut text_addr = None;
    let mut line = Vec::new();
    while reader.read_until(b'\n', &mut line)? != 0 {
        if let Some((address, name)) = parse_kernel_symbol_line_bytes(&line) {
            if should_include_kernel_symbol(&mut text_addr, address, name) {
                builder.push(address, name.name, name.module)?;
            }
        }
        line.clear();
    }
    Ok(builder.finish())
}

#[derive(Default)]
pub(super) struct FullKernelSymbolsBuilder {
    symbols: Vec<FullKernelSymbol>,
    names: String,
    modules: Vec<Box<str>>,
    module_ids: FxHashMap<Box<[u8]>, u32>,
}

impl FullKernelSymbolsBuilder {
    pub(super) fn push(
        &mut self,
        address: u64,
        name: &[u8],
        module: Option<&[u8]>,
    ) -> io::Result<()> {
        let name_start = self.names.len();
        self.names.push_str(&String::from_utf8_lossy(name));
        let symbol = FullKernelSymbol {
            address,
            name_start: kernel_symbol_table_index(name_start)?,
            name_len: kernel_symbol_table_index(self.names.len() - name_start)?,
            module: module.map(|module| self.module_id(module)).transpose()?,
        };
        self.symbols.push(symbol);
        Ok(())
    }

    fn module_id(&mut self, module: &[u8]) -> io::Result<u32> {
        if let Some(&id) = self.module_ids.get(module) {
            return Ok(id);
        }
        let id = kernel_symbol_table_index(self.modules.len())?;
        self.modules
            .push(kernel_symbol_module_to_string(module).into_boxed_str());
        self.module_ids.insert(module.into(), id);
        Ok(id)
    }

    pub(super) fn finish(mut self) -> FullKernelSymbols {
        sort_and_keep_last_alias(&mut self.symbols, |s| s.address);
        FullKernelSymbols {
            symbols: self.symbols.into_boxed_slice(),
            names: self.names.into_boxed_str(),
            modules: self.modules.into_boxed_slice(),
        }
    }
}

fn kernel_symbol_table_index(value: usize) -> io::Result<u32> {
    u32::try_from(value).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "kernel symbol names exceed 4 GiB",
        )
    })
}

pub(super) fn parse_kernel_symbols(data: &[u8]) -> Vec<KernelSymbol> {
    let mut symbols = Vec::new();
    let mut text_addr = None;

    for (address, name) in KallSymIter::new(data) {
        if should_include_kernel_symbol(&mut text_addr, address, name) {
            symbols.push(kernel_symbol_from_name(address, name));
        }
    }
    sort_and_keep_last_alias(&mut symbols, |s| s.address);
    symbols
}

fn sort_and_keep_last_alias<T>(symbols: &mut Vec<T>, address: impl Fn(&T) -> u64) {
    symbols.sort_by_key(&address);
    symbols.dedup_by(|later, earlier| {
        if address(later) != address(earlier) {
            return false;
        }
        std::mem::swap(later, earlier);
        true
    });
}

pub(super) fn load_sparse_kernel_symbols_from_file(
    requested_addresses: &[u64],
) -> io::Result<Vec<(u64, KernelSymbol)>> {
    let file = fs::File::open("/proc/kallsyms")?;
    let mut reader = io::BufReader::with_capacity(1024 * 1024, file);
    parse_sparse_kernel_symbols_streaming(&mut reader, requested_addresses)
}

#[cfg(any(test, feature = "bench-support"))]
fn parse_sparse_kernel_symbols(
    data: &[u8],
    requested_addresses: &[u64],
) -> Vec<(u64, KernelSymbol)> {
    parse_sparse_kernel_symbols_streaming(&mut io::Cursor::new(data), requested_addresses)
        .unwrap_or_default()
}

#[cfg(any(test, feature = "bench-support"))]
pub(crate) fn bench_parse_sparse_kernel_symbols(
    data: &[u8],
    requested_addresses: &[u64],
    rounds: u64,
) -> usize {
    let mut checksum = 0usize;
    for _ in 0..rounds {
        let symbols = parse_sparse_kernel_symbols(data, requested_addresses);
        for (requested, symbol) in symbols {
            checksum = checksum
                .wrapping_add(requested as usize)
                .wrapping_add(symbol.address as usize)
                .wrapping_add(symbol.name.len());
        }
    }
    checksum
}

fn parse_sparse_kernel_symbols_streaming(
    reader: &mut impl BufRead,
    requested_addresses: &[u64],
) -> io::Result<Vec<(u64, KernelSymbol)>> {
    let mut scan = SparseKernelSymbolScan::new(requested_addresses);
    let mut carry = Vec::new();

    loop {
        let buffer = reader.fill_buf()?;
        if buffer.is_empty() {
            if !carry.is_empty() {
                scan.process_line(&carry);
            }
            return Ok(scan.finish());
        }

        let mut consumed = 0;
        while consumed < buffer.len() {
            let tail = &buffer[consumed..];
            let Some(newline) = memchr(b'\n', tail) else {
                carry.extend_from_slice(tail);
                consumed = buffer.len();
                break;
            };
            let line_end = consumed + newline + 1;
            if carry.is_empty() {
                scan.process_line(&buffer[consumed..line_end]);
            } else {
                carry.extend_from_slice(&buffer[consumed..line_end]);
                scan.process_line(&carry);
                carry.clear();
            }
            consumed = line_end;
        }
        reader.consume(consumed);
    }
}

/// Finds the nearest preceding symbol for each requested PC in one pass over
/// kallsyms, whatever the file order.
///
/// Requests split the address space into buckets: bucket `i` holds addresses
/// above request `i - 1` and at or below request `i`. Each bucket keeps only its
/// highest included symbol, as a copy of the raw line, and `finish` carries the
/// last non-empty bucket forward. Names are decoded only for those winners.
struct SparseKernelSymbolScan<'a> {
    requested_addresses: &'a [u64],
    best_lines: Vec<Option<(u64, Vec<u8>)>>,
    text_addr: Option<u64>,
}

impl<'a> SparseKernelSymbolScan<'a> {
    fn new(requested_addresses: &'a [u64]) -> Self {
        Self {
            requested_addresses,
            best_lines: vec![None; requested_addresses.len()],
            text_addr: None,
        }
    }

    fn process_line(&mut self, line: &[u8]) {
        let Some((address, name)) = parse_kernel_symbol_line_bytes(line) else {
            return;
        };
        // The filter must see every line in file order: `_text` anchors which
        // core symbols are kept.
        if !should_include_kernel_symbol(&mut self.text_addr, address, name) {
            return;
        }
        let bucket = self
            .requested_addresses
            .partition_point(|&requested| requested < address);
        let Some(best) = self.best_lines.get_mut(bucket) else {
            return;
        };
        match best {
            // `>=` keeps the last alias at an address, like the full table.
            Some((best_address, best_line)) if address >= *best_address => {
                *best_address = address;
                best_line.clear();
                best_line.extend_from_slice(line);
            }
            Some(_) => {}
            None => *best = Some((address, line.to_vec())),
        }
    }

    fn finish(self) -> Vec<(u64, KernelSymbol)> {
        let mut result = Vec::with_capacity(self.requested_addresses.len());
        let mut symbol = None;
        for (&requested, best) in self.requested_addresses.iter().zip(self.best_lines) {
            if let Some((_, line)) = best {
                symbol = parse_kernel_symbol_line_bytes(&line)
                    .map(|(address, name)| kernel_symbol_from_name(address, name));
            }
            if let Some(symbol) = &symbol {
                result.push((requested, symbol.clone()));
            }
        }
        result
    }
}

fn parse_kernel_symbol_line_bytes(line: &[u8]) -> Option<(u64, KernelSymbolMetadata<'_>)> {
    let (address, address_len) = parse_hex_u64(line)?;
    let symbol_type = *line.get(address_len.checked_add(1)?)?;
    let name_start = address_len.checked_add(3)?;
    let name_and_rest = line.get(name_start..)?;
    let line_len = memchr(b'\n', name_and_rest).unwrap_or(name_and_rest.len());
    let line = &name_and_rest[..line_len];
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    Some((address, parse_kernel_symbol_name(symbol_type, line)))
}

struct KallSymIter<'a> {
    remaining: &'a [u8],
}

impl<'a> KallSymIter<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { remaining: data }
    }
}

impl<'a> Iterator for KallSymIter<'a> {
    type Item = (u64, KernelSymbolMetadata<'a>);

    fn next(&mut self) -> Option<Self::Item> {
        // Skip unparsable lines rather than ending iteration: one malformed
        // line must not drop every symbol after it.
        while !self.remaining.is_empty() {
            let line_len = memchr(b'\n', self.remaining)
                .map(|idx| idx + 1)
                .unwrap_or(self.remaining.len());
            let line = &self.remaining[..line_len];
            self.remaining = self.remaining.get(line_len..).unwrap_or_default();
            if let Some((address, name)) = parse_kernel_symbol_line_bytes(line) {
                return Some((address, name));
            }
        }
        None
    }
}

fn parse_hex_u64(input: &[u8]) -> Option<(u64, usize)> {
    let mut value = 0_u64;
    let mut len = 0;
    for &byte in input.iter().take(16) {
        let digit = match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            b'A'..=b'F' => byte - b'A' + 10,
            _ => break,
        };
        value = (value << 4) | u64::from(digit);
        len += 1;
    }
    (len != 0).then_some((value, len))
}

fn should_include_kernel_symbol(
    text_addr: &mut Option<u64>,
    address: u64,
    name: KernelSymbolMetadata<'_>,
) -> bool {
    if address == 0
        || !PERF_KERNEL_SYMBOL_TYPES.contains(&name.symbol_type.to_ascii_uppercase())
        || name.name.starts_with(b"$")
        || name.name.starts_with(b".L")
        || name.name.starts_with(b"L0")
    {
        return false;
    }
    if text_addr.is_none() && is_kernel_text_symbol(name.name) {
        *text_addr = Some(address);
    }
    name.module.is_some() || text_addr.is_some_and(|anchor| address >= anchor)
}

fn parse_kernel_symbol_name(symbol_type: u8, name: &[u8]) -> KernelSymbolMetadata<'_> {
    if name.last() == Some(&b']') {
        if let Some(bracket_start) = name.iter().rposition(|&byte| byte == b'[') {
            let module = &name[bracket_start + 1..name.len() - 1];
            if !module.is_empty() {
                return KernelSymbolMetadata {
                    symbol_type,
                    name: trim_ascii_end(&name[..bracket_start]),
                    module: Some(module),
                };
            }
        }
    }
    KernelSymbolMetadata {
        symbol_type,
        name,
        module: None,
    }
}

fn trim_ascii_end(mut data: &[u8]) -> &[u8] {
    while data.last().is_some_and(|byte| matches!(byte, b' ' | b'\t')) {
        data = &data[..data.len() - 1];
    }
    data
}

fn kernel_symbol_from_name(address: u64, name: KernelSymbolMetadata<'_>) -> KernelSymbol {
    KernelSymbol {
        address,
        name: kernel_symbol_name_to_string(name.name),
        module: name.module.map(kernel_symbol_module_to_string),
    }
}

fn kernel_symbol_name_to_string(name: &[u8]) -> String {
    String::from_utf8_lossy(name).into_owned()
}

fn kernel_symbol_module_to_string(module: &[u8]) -> String {
    format!("[{}]", String::from_utf8_lossy(module))
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn sparse_kernel_symbols_scan_module_symbols_out_of_order() {
        // Module symbols follow the core kernel without continuing its order.
        let kallsyms = b"ffffffff81000000 T _text\n\
                         ffffffff81000100 T core_symbol\n\
                         ffffffffc0100000 t second\t[module_1]\n\
                         ffffffffc0000000 t first\t[module_0]\n";
        let requested = [0xffff_ffff_8100_0104, 0xffff_ffff_c010_0004];

        let symbols = parse_sparse_kernel_symbols(kallsyms, &requested);
        let names = symbols.iter().map(|(_, symbol)| symbol.name.as_str());
        assert!(names.eq(["core_symbol", "second"]));
    }

    #[test]
    fn parses_kernel_symbol_lines() {
        let mut iter = KallSymIter::new(
            b"ffffffff89800000 T _text\nffffffff89800137 t syscall_return [kernel]\n",
        );

        let (address, name) = iter.next().expect("_text symbol");
        assert_eq!(address, 0xffff_ffff_8980_0000);
        assert_eq!(name.symbol_type, b'T');
        assert_eq!(name.name, b"_text");
        assert_eq!(name.module, None);

        let (address, name) = iter.next().expect("module symbol");
        assert_eq!(address, 0xffff_ffff_8980_0137);
        assert_eq!(name.symbol_type, b't');
        assert_eq!(name.name, b"syscall_return");
        assert_eq!(name.module, Some(b"kernel".as_slice()));
        assert_eq!(KallSymIter::new(b"not-an-address T broken\n").next(), None);
    }

    #[test]
    fn kernel_symbol_iterator_skips_unparsable_lines() {
        let mut iter = KallSymIter::new(
            b"ffffffff89800000 T _text\nnot-an-address T broken\nffffffff89800137 t syscall_return\n",
        );

        assert_eq!(iter.next().expect("_text symbol").0, 0xffff_ffff_8980_0000);
        assert_eq!(
            iter.next().expect("symbol after bad line").0,
            0xffff_ffff_8980_0137
        );
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn zeroed_kernel_symbols_are_ignored() {
        let kallsyms = b"0000000000000000 T _text\n\
                         0000000000000000 t schedule\n\
                         0000000000000000 t module_symbol [module]\n";

        assert!(parse_kernel_symbols(kallsyms).is_empty());
        assert!(parse_sparse_kernel_symbols(kallsyms, &[0xffff_ffff_8000_1234]).is_empty());
    }

    #[test]
    fn kernel_symbols_keep_module_symbols_before_text() {
        let kallsyms = b"ffff800001717020 t tls_update  [tls]\n\
                         ffff8000081e0000 T _text\n\
                         ffff8000081f0000 t core_symbol\n";
        let symbols = parse_kernel_symbols(kallsyms);

        assert_eq!(symbols.len(), 3);
        assert_eq!(symbols[0].name, "tls_update");
        assert_eq!(symbols[0].module.as_deref(), Some("[tls]"));
        assert_eq!(symbols[1].name, "_text");
        assert_eq!(symbols[1].module, None);
    }

    #[test]
    fn sparse_kernel_symbols_keep_only_requested_addresses() {
        let kallsyms = b"ffffffff89800000 T _text\n\
                         ffffffff89800100 T first\n\
                         ffffffff89800100 t duplicate\n\
                         ffffffff89800200 t second [kernel]\n";
        let symbols = parse_sparse_kernel_symbols(
            kallsyms,
            &[
                0xffff_ffff_8980_0000,
                0xffff_ffff_8980_0101,
                0xffff_ffff_8980_01ff,
                0xffff_ffff_8980_0204,
            ],
        );

        assert_eq!(symbols.len(), 4);
        assert_eq!(symbols[0].1.name, "_text");
        assert_eq!(symbols[1].1.name, "duplicate");
        assert_eq!(symbols[2].1.name, "duplicate");
        assert_eq!(symbols[3].1.name, "second");
        assert_eq!(symbols[3].1.module.as_deref(), Some("[kernel]"));
        assert_eq!(symbols[1].1.address, 0xffff_ffff_8980_0100);
    }

    #[test]
    fn mapping_labels_never_displace_kernel_functions() {
        for ignored in ["$x", "$d", ".Ltmp0", "L0tmp"] {
            for aliases in [
                format!("ffffffff89800100 t {ignored}\nffffffff89800100 t real_function\n"),
                format!("ffffffff89800100 t real_function\nffffffff89800100 t {ignored}\n"),
            ] {
                let kallsyms = format!("ffffffff89800000 T _text\n{aliases}");
                let symbols = parse_kernel_symbols(kallsyms.as_bytes());
                assert_eq!(symbols.last().unwrap().name, "real_function");

                let sparse =
                    parse_sparse_kernel_symbols(kallsyms.as_bytes(), &[0xffff_ffff_8980_0104]);
                assert_eq!(sparse[0].1.name, "real_function");
            }
        }
    }

    #[test]
    fn non_perf_kernel_symbol_types_are_filtered() {
        let kallsyms = b"ffffffff89800000 T _text\n\
                         ffffffff89800100 t text_control\n\
                         ffffffff89800200 r excluded_rodata\n\
                         ffffffff89800300 W weak_control\n\
                         ffffffff89800400 A excluded_absolute\n\
                         ffffffff89800500 d data_control\n\
                         ffffffff89800600 n excluded_debug\n\
                         ffffffff89800700 B bss_control\n";
        let symbols = parse_kernel_symbols(kallsyms);
        assert_eq!(
            symbols
                .iter()
                .map(|symbol| symbol.name.as_str())
                .collect::<Vec<_>>(),
            [
                "_text",
                "text_control",
                "weak_control",
                "data_control",
                "bss_control",
            ]
        );

        let sparse = parse_sparse_kernel_symbols(
            kallsyms,
            &[
                0xffff_ffff_8980_0204,
                0xffff_ffff_8980_0304,
                0xffff_ffff_8980_0404,
                0xffff_ffff_8980_0504,
                0xffff_ffff_8980_0604,
                0xffff_ffff_8980_0704,
            ],
        );
        assert_eq!(
            sparse
                .iter()
                .map(|(_, symbol)| symbol.name.as_str())
                .collect::<Vec<_>>(),
            [
                "text_control",
                "weak_control",
                "weak_control",
                "data_control",
                "data_control",
                "bss_control",
            ]
        );
    }

    #[test]
    fn same_address_aliases_match_perf_last_wins() {
        for (aliases, expected) in [
            (
                "ffffffff89800100 t short\nffffffff89800100 t much_longer_function\n",
                "much_longer_function",
            ),
            (
                "ffffffff89800100 t much_longer_function\nffffffff89800100 t short\n",
                "short",
            ),
            (
                "ffffffff89800100 t first\nffffffff89800100 t second\nffffffff89800100 t last [module]\n",
                "last",
            ),
        ] {
            let kallsyms = format!("ffffffff89800000 T _text\n{aliases}");
            let symbols = parse_kernel_symbols(kallsyms.as_bytes());
            assert_eq!(symbols.last().unwrap().name, expected);

            let sparse = parse_sparse_kernel_symbols(kallsyms.as_bytes(), &[0xffff_ffff_8980_0104]);
            assert_eq!(sparse[0].1.name, expected);
        }
    }

    #[test]
    fn sparse_kernel_symbols_keep_module_symbols_before_text() {
        let kallsyms = b"ffff800001717020 t tls_update [tls]\n\
                         ffff8000081e0000 T _text\n\
                         ffff8000081f0000 t core_symbol\n";
        let symbols =
            parse_sparse_kernel_symbols(kallsyms, &[0xffff_8000_0171_7024, 0xffff_8000_081e_0004]);

        assert_eq!(symbols.len(), 2);
        assert_eq!(symbols[0].1.name, "tls_update");
        assert_eq!(symbols[0].1.module.as_deref(), Some("[tls]"));
        assert_eq!(symbols[1].1.name, "_text");
        assert_eq!(symbols[1].1.module, None);
    }

    #[test]
    fn sparse_kernel_symbols_handle_unsorted_kallsyms() {
        let kallsyms = b"ffffffff89800000 T _text\n\
                         ffffffff89803000 T late\n\
                         ffffffff89802000 T middle\n";
        let symbols = parse_sparse_kernel_symbols(kallsyms, &[0xffff_ffff_8980_2500]);

        assert_eq!(symbols.len(), 1);
        assert_eq!(symbols[0].1.name, "middle");
    }
}
