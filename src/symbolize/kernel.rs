//! Kernel symbolization support for Linux perf frames.
//!
//! Kernel stack samples arrive as absolute kernel instruction pointers. Unlike
//! user-space frames, there is no per-process ELF mapping we can hand to the
//! native symbolizer, and many machines hide `/proc/kallsyms` addresses behind
//! `kptr_restrict` or `perf_event_paranoid`. This module keeps the shared table,
//! sparse lookup cache, and resolver facade used by `PerfSymbolizer`. For
//! spool-backed sparse symbolization, it asks `kallsyms` for live symbols, then
//! falls back to `system_map` when kallsyms is unavailable or zeroed; the shared
//! full-table path uses live kallsyms only.
//!
//! The sparse cache is keyed by boot id, requested PCs, and rebase anchors
//! (known kernel text addresses used to line up static System.map addresses with
//! the running kernel's KASLR slide) because sparse symbolization is only
//! reusable for the same running kernel and the same sampled address set.

use std::collections::VecDeque;
use std::fs;
use std::io;
use std::sync::{Arc, Mutex, OnceLock};

use rustc_hash::FxHashMap;

use crate::spool::ModuleRecord;

mod kallsyms;
mod system_map;

#[cfg(any(test, feature = "bench-support"))]
pub(crate) use kallsyms::bench_parse_sparse_kernel_symbols;
use kallsyms::{load_kernel_symbols, load_sparse_kernel_symbols_from_file};
use system_map::{kernel_rebase_anchors, load_sparse_kernel_symbols_from_system_map};

#[derive(Clone)]
pub(super) struct KernelSymbol {
    pub(super) address: u64,
    pub(super) name: String,
    pub(super) module: Option<String>,
}

pub(super) struct ResolvedKernelSymbol {
    pub(super) name: String,
    pub(super) module: String,
    pub(super) offset: u64,
}

#[derive(Clone)]
pub(super) enum KernelSymbolTable {
    Full(Arc<[KernelSymbol]>),
    Sparse(Arc<[(u64, KernelSymbol)]>),
}

#[derive(Clone, PartialEq, Eq, Hash)]
struct SparseKernelSymbolCacheKey {
    kernel_id: Arc<str>,
    addresses: Arc<[u64]>,
    rebase_anchors: Arc<[u64]>,
}

/// Process-global cache of sparse kernel symbol lookups, bounded FIFO. Hits
/// only happen for byte-identical kernel address sets (same spool reopened),
/// so a small capacity covers the useful cases while keeping long-running
/// services that open many distinct profiles from accumulating dead entries.
#[derive(Default)]
struct SparseKernelSymbolCache {
    entries: FxHashMap<SparseKernelSymbolCacheKey, Arc<[(u64, KernelSymbol)]>>,
    insertion_order: VecDeque<SparseKernelSymbolCacheKey>,
}

const SPARSE_KERNEL_SYMBOL_CACHE_CAP: usize = 16;

impl SparseKernelSymbolCache {
    fn get(&self, key: &SparseKernelSymbolCacheKey) -> Option<Arc<[(u64, KernelSymbol)]>> {
        self.entries.get(key).cloned()
    }

    fn insert(&mut self, key: SparseKernelSymbolCacheKey, value: Arc<[(u64, KernelSymbol)]>) {
        if self.entries.insert(key.clone(), value).is_none() {
            self.insertion_order.push_back(key);
            if self.insertion_order.len() > SPARSE_KERNEL_SYMBOL_CACHE_CAP {
                if let Some(oldest) = self.insertion_order.pop_front() {
                    self.entries.remove(&oldest);
                }
            }
        }
    }
}

pub(super) fn resolve_kernel_symbol(
    symbols: &KernelSymbolTable,
    abs_ip: u64,
) -> Option<ResolvedKernelSymbol> {
    let symbol = find_kernel_symbol_in_table(symbols, abs_ip)?;
    let offset = abs_ip.saturating_sub(symbol.address);
    Some(ResolvedKernelSymbol {
        name: format_symbol(&symbol.name, offset),
        module: symbol
            .module
            .clone()
            .unwrap_or_else(|| "[kernel]".to_owned()),
        offset,
    })
}

fn format_symbol(name: &str, offset: u64) -> String {
    if offset == 0 {
        name.to_owned()
    } else {
        format!("{name}+0x{offset:x}")
    }
}

fn find_kernel_symbol(symbols: &[KernelSymbol], address: u64) -> Option<&KernelSymbol> {
    symbols[..symbols.partition_point(|s| s.address <= address)].last()
}

fn find_kernel_symbol_in_table(symbols: &KernelSymbolTable, address: u64) -> Option<&KernelSymbol> {
    match symbols {
        KernelSymbolTable::Full(symbols) => find_kernel_symbol(symbols, address),
        KernelSymbolTable::Sparse(symbols) => symbols
            .binary_search_by_key(&address, |(address, _)| *address)
            .ok()
            .map(|idx| &symbols[idx].1),
    }
}

fn is_kernel_text_symbol(name: &[u8]) -> bool {
    matches!(name, b"_text" | b"_stext")
}

#[cfg(test)]
fn load_sparse_kernel_symbols(addresses: impl IntoIterator<Item = u64>) -> KernelSymbolTable {
    load_sparse_kernel_symbols_with_rebase_anchors(addresses, Arc::from([]))
}

pub(super) fn load_sparse_kernel_symbols_for_spool(
    addresses: impl IntoIterator<Item = u64>,
    modules: &[ModuleRecord],
) -> KernelSymbolTable {
    load_sparse_kernel_symbols_with_rebase_anchors(addresses, kernel_rebase_anchors(modules))
}

fn load_sparse_kernel_symbols_with_rebase_anchors(
    addresses: impl IntoIterator<Item = u64>,
    rebase_anchors: Arc<[u64]>,
) -> KernelSymbolTable {
    let mut addresses: Vec<_> = addresses.into_iter().collect();
    addresses.sort_unstable();
    addresses.dedup();
    if addresses.is_empty() {
        return KernelSymbolTable::Sparse(Arc::from([]));
    }
    let addresses: Arc<[u64]> = Arc::from(addresses.into_boxed_slice());

    let cache_key = SparseKernelSymbolCacheKey {
        kernel_id: running_kernel_cache_id(),
        addresses: Arc::clone(&addresses),
        rebase_anchors: Arc::clone(&rebase_anchors),
    };
    if let Ok(cache) = sparse_kernel_symbol_cache().lock() {
        if let Some(symbols) = cache.get(&cache_key) {
            return KernelSymbolTable::Sparse(symbols);
        }
    }

    let symbols = match load_sparse_kernel_symbols_from_file(&addresses) {
        Ok(symbols) if !symbols.is_empty() => symbols,
        Ok(_) => load_sparse_kernel_symbols_from_system_map(&addresses, &rebase_anchors)
            .unwrap_or_default(),
        Err(err) => match load_sparse_kernel_symbols_from_system_map(&addresses, &rebase_anchors) {
            Some(symbols) if !symbols.is_empty() => symbols,
            _ => {
                warn_kallsyms_unusable(Some(&err));
                return KernelSymbolTable::Sparse(Arc::from([]));
            }
        },
    };
    if symbols.is_empty() {
        warn_kallsyms_unusable(None);
    }
    let symbols = Arc::from(symbols.into_boxed_slice());
    if let Ok(mut cache) = sparse_kernel_symbol_cache().lock() {
        cache.insert(cache_key, Arc::clone(&symbols));
    }
    KernelSymbolTable::Sparse(symbols)
}

fn sparse_kernel_symbol_cache() -> &'static Mutex<SparseKernelSymbolCache> {
    static CACHE: OnceLock<Mutex<SparseKernelSymbolCache>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(SparseKernelSymbolCache::default()))
}

fn running_kernel_cache_id() -> Arc<str> {
    static CACHE_ID: OnceLock<Arc<str>> = OnceLock::new();
    Arc::clone(CACHE_ID.get_or_init(|| {
        fs::read_to_string("/proc/sys/kernel/random/boot_id")
            .ok()
            .map(|id| id.trim().to_owned())
            .filter(|id| !id.is_empty())
            .unwrap_or_else(|| "unknown".to_owned())
            .into()
    }))
}

/// Warn once, process-wide, when kernel symbolization is unavailable, from
/// whichever kallsyms load path (full or sparse) hits the problem first.
fn warn_kallsyms_unusable(err: Option<&io::Error>) {
    static WARNED: std::sync::Once = std::sync::Once::new();
    WARNED.call_once(|| match err {
        Some(err) => tracing::warn!(
            "Failed to read /proc/kallsyms: {err}; kernel frames will not be symbolized"
        ),
        None => tracing::warn!(
            "No usable kernel symbols in /proc/kallsyms (kptr_restrict or perf_event_paranoid may hide addresses); kernel frames will not be symbolized"
        ),
    });
}

pub(super) fn load_shared_kernel_symbols() -> KernelSymbolTable {
    static KERNEL_SYMBOLS: OnceLock<Arc<[KernelSymbol]>> = OnceLock::new();
    KernelSymbolTable::Full(Arc::clone(KERNEL_SYMBOLS.get_or_init(|| {
        let symbols = match load_kernel_symbols() {
            Ok(symbols) => symbols,
            Err(err) => {
                warn_kallsyms_unusable(Some(&err));
                Vec::new()
            }
        };
        if symbols.is_empty() {
            warn_kallsyms_unusable(None);
        }
        Arc::from(symbols.into_boxed_slice())
    })))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    #[test]
    fn sparse_kernel_symbol_cache_is_bounded_and_evicts_fifo() {
        let mut cache = SparseKernelSymbolCache::default();
        let value: Arc<[(u64, KernelSymbol)]> = Arc::from([]);
        let key = |i: u64| SparseKernelSymbolCacheKey {
            kernel_id: Arc::from("boot"),
            addresses: Arc::from(vec![i].into_boxed_slice()),
            rebase_anchors: Arc::from([]),
        };

        for i in 0..=SPARSE_KERNEL_SYMBOL_CACHE_CAP as u64 {
            cache.insert(key(i), Arc::clone(&value));
        }

        assert_eq!(cache.entries.len(), SPARSE_KERNEL_SYMBOL_CACHE_CAP);
        assert!(cache.get(&key(0)).is_none(), "oldest entry must be evicted");
        assert!(cache.get(&key(1)).is_some());

        // Re-inserting an existing key must not duplicate its queue slot.
        cache.insert(key(1), value);
        assert_eq!(cache.insertion_order.len(), SPARSE_KERNEL_SYMBOL_CACHE_CAP);
    }

    #[test]
    fn sparse_kernel_symbol_loads_are_cached_per_address_set() {
        let addresses = [0xffff_ffff_9990_0000_u64, 0xffff_ffff_9990_1234];

        let first = load_sparse_kernel_symbols(addresses);
        let second = load_sparse_kernel_symbols(addresses);

        let (KernelSymbolTable::Sparse(first), KernelSymbolTable::Sparse(second)) = (first, second)
        else {
            panic!("sparse loads must produce sparse tables");
        };
        assert!(
            Arc::ptr_eq(&first, &second),
            "identical address sets must hit the cache"
        );
    }
}
