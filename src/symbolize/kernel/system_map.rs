//! System.map fallback for core kernel symbolization.
//!
//! A System.map file is a static symbol table installed with a kernel build. It
//! is useful when `/proc/kallsyms` is unreadable or zeroed, but its addresses are
//! usually build-time addresses before Kernel Address Space Layout Randomization
//! (KASLR) is applied. This module finds candidate System.map files for the
//! running release, computes possible KASLR slides from kernel text mappings
//! recorded in the spool or from sampled kernel PCs, and chooses the table and
//! slide that best explain the requested addresses.
//!
//! System.map comes from the vmlinux/core-kernel build and does not cover
//! dynamically loaded kernel modules, so live kallsyms remains the preferred
//! source when it is available.
//!
//! Matches are bounded so a stale System.map does not turn arbitrary kernel PCs
//! into plausible but wrong far-away symbols.

use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};

use crate::spool::ModuleRecord;

#[cfg(test)]
use super::format_symbol;
use super::kallsyms::parse_kernel_symbols;
use super::{find_kernel_symbol, is_kernel_text_symbol, KernelSymbol};

pub(super) fn load_sparse_kernel_symbols_from_system_map(
    requested_addresses: &[u64],
    rebase_anchors: &[u64],
) -> Option<Vec<(u64, KernelSymbol)>> {
    let symbol_tables = load_system_map_symbol_tables();
    sparse_kernel_symbols_from_system_map_tables(
        &symbol_tables,
        requested_addresses,
        rebase_anchors,
    )
}

fn sparse_kernel_symbols_from_system_map_tables(
    symbol_tables: &[Arc<[KernelSymbol]>],
    requested_addresses: &[u64],
    rebase_anchors: &[u64],
) -> Option<Vec<(u64, KernelSymbol)>> {
    let mut best_symbol_table = None;
    let mut best_slide = 0;
    let mut best_matched_symbols = 0;
    let mut best_total_offset = u64::MAX;
    for symbol_table in symbol_tables.iter() {
        let candidates =
            system_map_rebase_slides(symbol_table, rebase_anchors, requested_addresses);
        for candidate in candidates {
            if candidate.inferred
                && requested_addresses.len() < MIN_INFERRED_SYSTEM_MAP_SLIDE_MATCHES
            {
                continue;
            }
            let score =
                system_map_symbol_match_score(symbol_table, requested_addresses, candidate.slide);
            if score.matched_symbols == 0 {
                continue;
            }
            if !system_map_slide_has_enough_confidence(
                candidate,
                score.matched_symbols,
                requested_addresses.len(),
            ) {
                continue;
            }
            if score.matched_symbols > best_matched_symbols
                || (score.matched_symbols == best_matched_symbols
                    && score.total_offset < best_total_offset)
            {
                best_symbol_table = Some(symbol_table.as_ref());
                best_slide = candidate.slide;
                best_matched_symbols = score.matched_symbols;
                best_total_offset = score.total_offset;
                if best_matched_symbols == requested_addresses.len() && best_total_offset == 0 {
                    return Some(bounded_system_map_symbols_from_parsed_symbols_rebased(
                        symbol_table,
                        requested_addresses,
                        candidate.slide,
                    ));
                }
            }
        }
    }
    best_symbol_table.map(|symbol_table| {
        bounded_system_map_symbols_from_parsed_symbols_rebased(
            symbol_table,
            requested_addresses,
            best_slide,
        )
    })
}

fn load_system_map_symbol_tables() -> Arc<[Arc<[KernelSymbol]>]> {
    static SYSTEM_MAP_SYMBOLS: OnceLock<Arc<[Arc<[KernelSymbol]>]>> = OnceLock::new();
    Arc::clone(SYSTEM_MAP_SYMBOLS.get_or_init(|| {
        let mut tables = Vec::new();
        let mut paths = Vec::new();
        for path in system_map_candidates() {
            let Ok(path) = fs::canonicalize(path) else {
                continue;
            };
            if paths.iter().any(|seen| seen == &path) {
                continue;
            }
            let Ok(data) = fs::read(&path) else {
                continue;
            };
            let symbols = parse_kernel_symbols(&data);
            if !symbols.is_empty() {
                paths.push(path);
                tables.push(Arc::from(symbols.into_boxed_slice()));
            }
        }
        Arc::from(tables.into_boxed_slice())
    }))
}

const SYSTEM_MAP_SYMBOL_MAX_OFFSET: u64 = 1024 * 1024;
const MIN_INFERRED_SYSTEM_MAP_SLIDE_MATCHES: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SystemMapSlideCandidate {
    slide: u64,
    inferred: bool,
}

fn system_map_slide_has_enough_confidence(
    candidate: SystemMapSlideCandidate,
    matched_symbols: usize,
    requested_addresses: usize,
) -> bool {
    !candidate.inferred
        || (requested_addresses >= MIN_INFERRED_SYSTEM_MAP_SLIDE_MATCHES
            && matched_symbols >= MIN_INFERRED_SYSTEM_MAP_SLIDE_MATCHES)
}

fn system_map_symbol_match_is_bounded(
    requested_address: u64,
    symbol: &KernelSymbol,
    slide: u64,
) -> bool {
    system_map_symbol_match_offset(requested_address, symbol, slide)
        .is_some_and(|offset| offset <= SYSTEM_MAP_SYMBOL_MAX_OFFSET)
}

fn system_map_symbol_match_offset(
    requested_address: u64,
    symbol: &KernelSymbol,
    slide: u64,
) -> Option<u64> {
    requested_address.checked_sub(symbol.address.wrapping_add(slide))
}

#[derive(Default)]
struct SystemMapSymbolMatchScore {
    matched_symbols: usize,
    total_offset: u64,
}

fn system_map_symbol_match_score(
    symbols: &[KernelSymbol],
    requested_addresses: &[u64],
    slide: u64,
) -> SystemMapSymbolMatchScore {
    let mut score = SystemMapSymbolMatchScore::default();
    for &address in requested_addresses {
        let Some(symbol) = find_kernel_symbol(symbols, address.wrapping_sub(slide)) else {
            continue;
        };
        let Some(offset) = system_map_symbol_match_offset(address, symbol, slide) else {
            continue;
        };
        if offset > SYSTEM_MAP_SYMBOL_MAX_OFFSET {
            continue;
        }
        score.matched_symbols += 1;
        score.total_offset = score.total_offset.saturating_add(offset);
    }
    score
}

fn bounded_system_map_symbols_from_parsed_symbols_rebased(
    symbols: &[KernelSymbol],
    requested_addresses: &[u64],
    slide: u64,
) -> Vec<(u64, KernelSymbol)> {
    requested_addresses
        .iter()
        .filter_map(|&address| {
            let symbol = find_kernel_symbol(symbols, address.wrapping_sub(slide))?;
            system_map_symbol_match_is_bounded(address, symbol, slide)
                .then(|| (address, kernel_symbol_rebased(symbol, slide)))
        })
        .collect()
}

#[cfg(test)]
fn sparse_kernel_symbols_from_parsed_symbols_rebased(
    symbols: &[KernelSymbol],
    requested_addresses: &[u64],
    slide: u64,
) -> Vec<(u64, KernelSymbol)> {
    requested_addresses
        .iter()
        .filter_map(|&address| {
            find_kernel_symbol(symbols, address.wrapping_sub(slide))
                .map(|symbol| (address, kernel_symbol_rebased(symbol, slide)))
        })
        .collect()
}

fn kernel_symbol_rebased(symbol: &KernelSymbol, slide: u64) -> KernelSymbol {
    let mut symbol = symbol.clone();
    symbol.address = symbol.address.wrapping_add(slide);
    symbol
}

fn system_map_rebase_slides(
    symbols: &[KernelSymbol],
    rebase_anchors: &[u64],
    requested_addresses: &[u64],
) -> Vec<SystemMapSlideCandidate> {
    let mut slides = vec![SystemMapSlideCandidate {
        slide: 0,
        inferred: false,
    }];
    let text_addresses = system_map_text_addresses(symbols);
    for &anchor in rebase_anchors {
        for &text_address in &text_addresses {
            slides.push(SystemMapSlideCandidate {
                slide: anchor.wrapping_sub(text_address),
                inferred: false,
            });
        }
    }
    if let Some(&lowest_address) = requested_addresses.iter().min() {
        for &text_address in &text_addresses {
            slides.push(SystemMapSlideCandidate {
                slide: kernel_text_aligned_address(lowest_address).wrapping_sub(text_address),
                inferred: true,
            });
        }
    }
    slides.sort_unstable_by_key(|candidate| (candidate.slide, candidate.inferred));
    slides.dedup_by_key(|candidate| candidate.slide);
    slides
}

const KERNEL_TEXT_REBASE_ALIGNMENT: u64 = 2 * 1024 * 1024;

fn kernel_text_aligned_address(address: u64) -> u64 {
    address & !(KERNEL_TEXT_REBASE_ALIGNMENT - 1)
}

fn system_map_text_addresses(symbols: &[KernelSymbol]) -> Vec<u64> {
    let mut addresses = Vec::new();
    for symbol in symbols {
        if symbol.address != 0
            && symbol.module.is_none()
            && is_kernel_text_symbol(symbol.name.as_bytes())
        {
            addresses.push(symbol.address);
        }
    }
    addresses.sort_unstable();
    addresses.dedup();
    addresses
}

pub(super) fn kernel_rebase_anchors(modules: &[ModuleRecord]) -> Arc<[u64]> {
    let mut anchors = Vec::new();
    for module in modules.iter().filter(|module| kernel_text_module(module)) {
        anchors.push(module.start);
        if module.file_offset != 0 {
            anchors.push(module.start.saturating_sub(module.file_offset));
        }
    }
    anchors.retain(|&address| address != 0);
    anchors.sort_unstable();
    anchors.dedup();
    Arc::from(anchors.into_boxed_slice())
}

fn kernel_text_module(module: &ModuleRecord) -> bool {
    if !module.is_kernel {
        return false;
    }
    let path = module.path.as_str();
    path.contains("kernel.kallsyms")
        || path.contains("_text")
        || path == "[kernel]"
        || path.ends_with("/vmlinux")
}

fn system_map_candidates() -> Vec<PathBuf> {
    let Some(release) = running_kernel_release() else {
        return Vec::new();
    };
    vec![
        PathBuf::from(format!("/boot/System.map-{release}")),
        PathBuf::from(format!("/usr/lib/debug/boot/System.map-{release}")),
        PathBuf::from(format!("/lib/modules/{release}/build/System.map")),
        PathBuf::from(format!("/usr/lib/modules/{release}/build/System.map")),
        PathBuf::from(format!("/lib/modules/{release}/System.map")),
        PathBuf::from(format!("/usr/lib/modules/{release}/System.map")),
    ]
}

fn running_kernel_release() -> Option<String> {
    fs::read_to_string("/proc/sys/kernel/osrelease")
        .ok()
        .map(|release| release.trim().to_owned())
        .filter(|release| !release.is_empty())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    #[test]
    fn system_map_symbols_can_be_rebased_to_spool_kernel_text_mapping() {
        let system_map = b"ffffffff81000000 T _text\n\
                           ffffffff81000100 T do_syscall_64\n\
                           ffffffff81000200 T entry_SYSCALL_64_after_hwframe\n";
        let module = ModuleRecord {
            id: 0,
            process_id: -1,
            start: 0xffff_ffff_8c80_0000,
            end: 0xffff_ffff_8d00_0000,
            file_offset: 0,
            inode: 0,
            device_major: 0,
            device_minor: 0,
            inode_generation: 0,
            path: "[kernel.kallsyms]_text".into(),
            is_kernel: true,
        };

        let anchors = kernel_rebase_anchors(&[module]);
        let slide = 0xffff_ffff_8c80_0000_u64.wrapping_sub(0xffff_ffff_8100_0000);
        let system_map_symbols = parse_kernel_symbols(system_map);
        assert_eq!(&*anchors, &[0xffff_ffff_8c80_0000]);
        assert_eq!(
            system_map_rebase_slides(&system_map_symbols, &anchors, &[0xffff_ffff_8c80_016d]),
            vec![
                SystemMapSlideCandidate {
                    slide: 0,
                    inferred: false,
                },
                SystemMapSlideCandidate {
                    slide,
                    inferred: false,
                },
            ]
        );

        let symbols = sparse_kernel_symbols_from_parsed_symbols_rebased(
            &system_map_symbols,
            &[0xffff_ffff_8c80_016d],
            slide,
        );

        assert_eq!(symbols.len(), 1);
        assert_eq!(symbols[0].0, 0xffff_ffff_8c80_016d);
        assert_eq!(symbols[0].1.address, 0xffff_ffff_8c80_0100);
        assert_eq!(symbols[0].1.name, "do_syscall_64");
        assert_eq!(
            format_symbol(&symbols[0].1.name, symbols[0].0 - symbols[0].1.address),
            "do_syscall_64+0x6d"
        );
    }

    #[test]
    fn system_map_symbols_can_use_stext_as_text_anchor() {
        let system_map = b"ffffffff81000000 T _stext\n\
                           ffffffff81000100 T do_syscall_64\n";
        let slide = 0xffff_ffff_8c80_0000_u64.wrapping_sub(0xffff_ffff_8100_0000);
        let system_map_symbols = parse_kernel_symbols(system_map);

        assert_eq!(system_map_symbols.len(), 2);
        assert_eq!(system_map_symbols[0].name, "_stext");
        assert_eq!(
            system_map_rebase_slides(&system_map_symbols, &[], &[0xffff_ffff_8c80_016d]),
            vec![
                SystemMapSlideCandidate {
                    slide: 0,
                    inferred: false,
                },
                SystemMapSlideCandidate {
                    slide,
                    inferred: true,
                },
            ]
        );

        let symbols = sparse_kernel_symbols_from_parsed_symbols_rebased(
            &system_map_symbols,
            &[0xffff_ffff_8c80_016d],
            slide,
        );

        assert_eq!(symbols.len(), 1);
        assert_eq!(symbols[0].1.address, 0xffff_ffff_8c80_0100);
        assert_eq!(symbols[0].1.name, "do_syscall_64");
    }

    #[test]
    fn system_map_symbol_tables_prefer_tighter_matches() {
        let stale: Arc<[KernelSymbol]> =
            Arc::from(parse_kernel_symbols(b"ffffffff81000000 T _text\n").into_boxed_slice());
        let fresh: Arc<[KernelSymbol]> = Arc::from(
            parse_kernel_symbols(
                b"ffffffff81000000 T _text\n\
                  ffffffff81000100 T do_syscall_64\n\
                  ffffffff81000200 T entry_SYSCALL_64_after_hwframe\n",
            )
            .into_boxed_slice(),
        );
        let requested_addresses = [0xffff_ffff_8c80_016d, 0xffff_ffff_8c80_026d];

        let symbols = sparse_kernel_symbols_from_system_map_tables(
            &[stale, fresh],
            &requested_addresses,
            &[0xffff_ffff_8c80_0000],
        )
        .expect("system map symbols");

        assert_eq!(symbols.len(), 2);
        assert_eq!(symbols[0].1.name, "do_syscall_64");
        assert_eq!(symbols[1].1.name, "entry_SYSCALL_64_after_hwframe");
    }

    #[test]
    fn system_map_symbol_tables_ignore_empty_matches() {
        let symbols: Arc<[KernelSymbol]> =
            Arc::from(parse_kernel_symbols(b"ffffffff81000000 T _text\n").into_boxed_slice());

        assert!(sparse_kernel_symbols_from_system_map_tables(
            &[symbols],
            &[0xffff_ffff_8000_0000],
            &[]
        )
        .is_none());
    }

    #[test]
    fn system_map_slide_can_be_inferred_from_sampled_kernel_text_addresses() {
        let system_map = b"ffffffff81000000 T _text\n\
                           ffffffff81000100 T do_syscall_64\n";
        let slide = 0xffff_ffff_8c80_0000_u64.wrapping_sub(0xffff_ffff_8100_0000);
        let system_map_symbols = parse_kernel_symbols(system_map);

        assert_eq!(
            system_map_rebase_slides(
                &system_map_symbols,
                &[],
                &[0xffff_ffff_8ca0_016d, 0xffff_ffff_8c80_016d]
            ),
            vec![
                SystemMapSlideCandidate {
                    slide: 0,
                    inferred: false,
                },
                SystemMapSlideCandidate {
                    slide,
                    inferred: true,
                },
            ]
        );
    }

    #[test]
    fn inferred_system_map_slides_use_lowest_sampled_kernel_page_and_need_confidence() {
        let system_map_symbols = parse_kernel_symbols(b"ffffffff81000000 T _text\n");
        let requested_addresses: Vec<_> = (0..256)
            .map(|idx| 0xffff_ffff_8c80_0000 + idx * KERNEL_TEXT_REBASE_ALIGNMENT)
            .collect();

        let candidates = system_map_rebase_slides(&system_map_symbols, &[], &requested_addresses);
        let inferred: Vec<_> = candidates
            .iter()
            .filter(|candidate| candidate.inferred)
            .map(|candidate| candidate.slide)
            .collect();

        assert_eq!(
            inferred,
            [0xffff_ffff_8c80_0000_u64.wrapping_sub(0xffff_ffff_8100_0000)]
        );
        assert!(!system_map_slide_has_enough_confidence(
            SystemMapSlideCandidate {
                slide: 0,
                inferred: true,
            },
            1,
            requested_addresses.len(),
        ));
        assert!(system_map_slide_has_enough_confidence(
            SystemMapSlideCandidate {
                slide: 0,
                inferred: true,
            },
            MIN_INFERRED_SYSTEM_MAP_SLIDE_MATCHES,
            requested_addresses.len(),
        ));
    }

    #[test]
    fn system_map_matches_reject_unrebased_tail_offsets() {
        let system_map = b"ffffffff81000000 T _text\n\
                           ffffffff81000100 T do_syscall_64\n";
        let system_map_symbols = parse_kernel_symbols(system_map);

        let symbols = sparse_kernel_symbols_from_parsed_symbols_rebased(
            &system_map_symbols,
            &[0xffff_ffff_8c80_016d],
            0,
        );

        assert_eq!(symbols.len(), 1);
        assert_eq!(symbols[0].1.name, "do_syscall_64");
        assert!(!system_map_symbol_match_is_bounded(
            symbols[0].0,
            &symbols[0].1,
            0
        ));
    }
}
