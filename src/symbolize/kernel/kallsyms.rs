//! `/proc/kallsyms` loader and parser.
//!
//! `kallsyms` is the live kernel's symbol table. When readable, it is the best
//! source for kernel frames because addresses already include the current KASLR
//! slide and loaded module symbols. Spool symbolization usually needs only the
//! program counters (PCs) that appeared in samples, so this module can stream
//! the sorted file and keep only the nearest preceding symbol for each requested
//! PC. If the file is not sorted, the code falls back to an in-memory parse.
//!
//! Zero addresses are ignored because kernels commonly expose symbol names but
//! replace addresses with `0` when symbol addresses are restricted.

use std::fs;
use std::io::{self, BufRead};

use memchr::memchr;

use super::{find_kernel_symbol, is_kernel_text_symbol, KernelSymbol};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct KernelSymbolMetadata<'a> {
    symbol_type: u8,
    name: &'a [u8],
    module: Option<&'a [u8]>,
}

const PERF_KERNEL_SYMBOL_TYPES: &[u8] = b"TWDB";

pub(super) fn load_kernel_symbols() -> io::Result<Vec<KernelSymbol>> {
    let data = fs::read("/proc/kallsyms")?;
    Ok(parse_kernel_symbols(&data))
}

pub(super) fn parse_kernel_symbols(data: &[u8]) -> Vec<KernelSymbol> {
    let mut symbols = Vec::new();
    let mut text_addr = None;

    for (address, name) in KallSymIter::new(data) {
        if should_include_kernel_symbol(&mut text_addr, address, name) {
            symbols.push(kernel_symbol_from_name(address, name));
        }
    }
    symbols.sort_by_key(|s| s.address);
    let mut deduplicated = Vec::with_capacity(symbols.len());
    for symbol in symbols {
        if deduplicated
            .last()
            .is_some_and(|previous: &KernelSymbol| previous.address == symbol.address)
        {
            *deduplicated.last_mut().unwrap() = symbol;
        } else {
            deduplicated.push(symbol);
        }
    }
    deduplicated
}

pub(super) fn load_sparse_kernel_symbols_from_file(
    requested_addresses: &[u64],
) -> io::Result<Vec<(u64, KernelSymbol)>> {
    let file = fs::File::open("/proc/kallsyms")?;
    let mut reader = io::BufReader::with_capacity(1024 * 1024, file);
    match parse_sparse_kernel_symbols_sorted_streaming(&mut reader, requested_addresses)? {
        Some(symbols) => Ok(symbols),
        None => fs::read("/proc/kallsyms")
            .map(|data| parse_sparse_kernel_symbols_unsorted(&data, requested_addresses)),
    }
}

fn parse_sparse_kernel_symbols(
    data: &[u8],
    requested_addresses: &[u64],
) -> Vec<(u64, KernelSymbol)> {
    match parse_sparse_kernel_symbols_sorted_streaming(
        &mut io::Cursor::new(data),
        requested_addresses,
    ) {
        Ok(Some(symbols)) => symbols,
        _ => parse_sparse_kernel_symbols_unsorted(data, requested_addresses),
    }
}

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

fn parse_sparse_kernel_symbols_unsorted(
    data: &[u8],
    requested_addresses: &[u64],
) -> Vec<(u64, KernelSymbol)> {
    let symbols = parse_kernel_symbols(data);
    requested_addresses
        .iter()
        .filter_map(|&address| {
            find_kernel_symbol(&symbols, address).map(|symbol| (address, symbol.clone()))
        })
        .collect()
}

fn parse_sparse_kernel_symbols_sorted_streaming(
    reader: &mut impl BufRead,
    requested_addresses: &[u64],
) -> io::Result<Option<Vec<(u64, KernelSymbol)>>> {
    let mut scan = SparseKernelSymbolScan::new(requested_addresses);
    let mut carry = Vec::new();

    loop {
        let mut consumed = 0;
        let mut unsorted = false;
        {
            let buffer = reader.fill_buf()?;
            if buffer.is_empty() {
                if !carry.is_empty() {
                    match scan.process_line(&carry) {
                        SparseScanState::Continue => {}
                        SparseScanState::Unsorted => return Ok(None),
                    }
                }
                return Ok(Some(scan.finish()));
            }

            while consumed < buffer.len() {
                let tail = &buffer[consumed..];
                let Some(newline) = memchr(b'\n', tail) else {
                    carry.extend_from_slice(tail);
                    consumed = buffer.len();
                    break;
                };
                let line_end = consumed + newline + 1;
                let state = if carry.is_empty() {
                    scan.process_line(&buffer[consumed..line_end])
                } else {
                    carry.extend_from_slice(&buffer[consumed..line_end]);
                    let state = scan.process_line(&carry);
                    carry.clear();
                    state
                };
                consumed = line_end;
                if let SparseScanState::Unsorted = state {
                    unsorted = true;
                    break;
                }
            }
        }
        reader.consume(consumed);
        if unsorted {
            return Ok(None);
        }
    }
}

struct SparseKernelSymbolScan<'a> {
    requested_addresses: &'a [u64],
    result: Vec<(u64, KernelSymbol)>,
    request_idx: usize,
    text_addr: Option<u64>,
    last_address: Option<u64>,
    last_symbol: Option<KernelSymbol>,
}

enum SparseScanState {
    Continue,
    Unsorted,
}

impl<'a> SparseKernelSymbolScan<'a> {
    fn new(requested_addresses: &'a [u64]) -> Self {
        Self {
            requested_addresses,
            result: Vec::with_capacity(requested_addresses.len()),
            request_idx: 0,
            text_addr: None,
            last_address: None,
            last_symbol: None,
        }
    }

    fn process_line(&mut self, line: &[u8]) -> SparseScanState {
        let Some((address, name)) = parse_kernel_symbol_line_bytes(line) else {
            return SparseScanState::Continue;
        };
        if !should_include_kernel_symbol(&mut self.text_addr, address, name) {
            return SparseScanState::Continue;
        }
        if self.last_address.is_some_and(|last| address < last) {
            return SparseScanState::Unsorted;
        }
        self.last_address = Some(address);

        while self.request_idx < self.requested_addresses.len()
            && self.requested_addresses[self.request_idx] < address
        {
            if let Some(symbol) = &self.last_symbol {
                self.result
                    .push((self.requested_addresses[self.request_idx], symbol.clone()));
            }
            self.request_idx += 1;
        }
        if self.request_idx >= self.requested_addresses.len() {
            return SparseScanState::Continue;
        }
        self.last_symbol = Some(kernel_symbol_from_name(address, name));
        SparseScanState::Continue
    }

    fn finish(mut self) -> Vec<(u64, KernelSymbol)> {
        while self.request_idx < self.requested_addresses.len() {
            if let Some(symbol) = &self.last_symbol {
                self.result
                    .push((self.requested_addresses[self.request_idx], symbol.clone()));
            }
            self.request_idx += 1;
        }
        self.result
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
    use std::io;

    use super::*;

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

        let mut reader = io::Cursor::new(kallsyms);
        let sparse =
            parse_sparse_kernel_symbols_sorted_streaming(&mut reader, &[0xffff_ffff_8000_1234])
                .unwrap()
                .unwrap();
        assert!(sparse.is_empty());
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
    fn streaming_sparse_kernel_symbols_detects_late_unsorted_lines() {
        let kallsyms = b"ffffffff89800000 T _text\n\
                         ffffffff89803000 T late\n\
                         ffffffff89802000 T middle\n";
        let mut reader = io::Cursor::new(kallsyms);
        let symbols =
            parse_sparse_kernel_symbols_sorted_streaming(&mut reader, &[0xffff_ffff_8980_2500])
                .unwrap();

        assert!(symbols.is_none());
        assert_eq!(reader.position() as usize, kallsyms.len());
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
