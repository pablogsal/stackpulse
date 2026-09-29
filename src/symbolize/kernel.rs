//! Kernel symbolization support for Linux perf frames.
//!
//! Kernel stack samples arrive as absolute kernel instruction pointers. Unlike
//! user-space frames, there is no per-process ELF mapping we can hand to the
//! native symbolizer, and many machines hide `/proc/kallsyms` addresses behind
//! `kptr_restrict` or `perf_event_paranoid`. This module keeps the shared table,
//! sparse lookup cache, and resolver facade used by `Symbolizer`. For
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
use std::io::{self, Read};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
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
    Full(Arc<FullKernelSymbols>),
    Sparse(Arc<[(u64, KernelSymbol)]>),
}

impl KernelSymbolTable {
    pub(super) fn empty() -> Self {
        Self::Sparse(Arc::from([]))
    }

    #[cfg(test)]
    pub(super) fn full(symbols: &[KernelSymbol]) -> Self {
        let mut builder = kallsyms::FullKernelSymbolsBuilder::default();
        for symbol in symbols {
            let module = symbol.module.as_deref().map(|module| {
                module
                    .trim_start_matches('[')
                    .trim_end_matches(']')
                    .as_bytes()
            });
            builder
                .push(symbol.address, symbol.name.as_bytes(), module)
                .unwrap();
        }
        Self::Full(Arc::new(builder.finish()))
    }

    pub(super) fn is_empty(&self) -> bool {
        match self {
            Self::Full(symbols) => symbols.symbols.is_empty(),
            Self::Sparse(symbols) => symbols.is_empty(),
        }
    }
}

/// Every symbol from one kallsyms read, sorted by address. Names share one
/// arena and module names are interned, so the table costs a handful of
/// allocations instead of one or two per symbol; the host table lives for the
/// rest of the process.
#[derive(Default)]
pub(super) struct FullKernelSymbols {
    symbols: Box<[FullKernelSymbol]>,
    names: Box<str>,
    modules: Box<[Box<str>]>,
}

#[derive(Clone, Copy)]
struct FullKernelSymbol {
    address: u64,
    name_start: u32,
    name_len: u32,
    module: Option<u32>,
}

impl FullKernelSymbols {
    fn find(&self, address: u64) -> Option<(u64, &str, Option<&str>)> {
        let symbol = *find_by_address(&self.symbols, address, |s| s.address)?;
        let name_start = symbol.name_start as usize;
        let name = &self.names[name_start..name_start + symbol.name_len as usize];
        let module = symbol.module.map(|module| &*self.modules[module as usize]);
        Some((symbol.address, name, module))
    }
}

const MAX_KERNEL_SYMBOL_FILE_SIZE: u64 = 64 * 1024 * 1024;

pub(super) fn load_kernel_symbols_from_path(path: &Path) -> io::Result<KernelSymbolTable> {
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NONBLOCK | libc::O_NOFOLLOW)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "kernel symbol source is not a regular file",
        ));
    }
    if metadata.len() > MAX_KERNEL_SYMBOL_FILE_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "kernel symbol source exceeds 64 MiB",
        ));
    }
    let mut reader = io::BufReader::new(file.take(MAX_KERNEL_SYMBOL_FILE_SIZE + 1));
    let symbols = kallsyms::parse_full_kernel_symbols(&mut reader)?;
    if reader.into_inner().limit() == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "kernel symbol source exceeds 64 MiB",
        ));
    }
    Ok(KernelSymbolTable::Full(Arc::new(symbols)))
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
    let (address, name, module) = match symbols {
        KernelSymbolTable::Full(symbols) => symbols.find(abs_ip)?,
        KernelSymbolTable::Sparse(symbols) => {
            let idx = symbols
                .binary_search_by_key(&abs_ip, |(address, _)| *address)
                .ok()?;
            let symbol = &symbols[idx].1;
            (
                symbol.address,
                symbol.name.as_str(),
                symbol.module.as_deref(),
            )
        }
    };
    let offset = abs_ip.saturating_sub(address);
    Some(ResolvedKernelSymbol {
        name: format_symbol(name, offset),
        module: module.unwrap_or("[kernel]").to_owned(),
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
    find_by_address(symbols, address, |s| s.address)
}

fn find_by_address<T>(symbols: &[T], address: u64, key: impl Fn(&T) -> u64) -> Option<&T> {
    symbols[..symbols.partition_point(|s| key(s) <= address)].last()
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

pub(super) fn extend_sparse_kernel_symbols_for_spool(
    table: &mut KernelSymbolTable,
    addresses: impl IntoIterator<Item = u64>,
    modules: &[ModuleRecord],
) {
    let KernelSymbolTable::Sparse(existing) = table else {
        return;
    };
    let mut addresses = addresses.into_iter().peekable();
    if addresses.peek().is_none() {
        return;
    }
    let KernelSymbolTable::Sparse(added) = load_sparse_kernel_symbols_for_spool(addresses, modules)
    else {
        return;
    };
    if added.is_empty() {
        return;
    }
    let mut combined = Vec::with_capacity(existing.len() + added.len());
    combined.extend(existing.iter().cloned());
    combined.extend(added.iter().cloned());
    combined.sort_unstable_by_key(|(address, _)| *address);
    combined.dedup_by_key(|(address, _)| *address);
    *existing = Arc::from(combined.into_boxed_slice());
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
    static KERNEL_SYMBOLS: OnceLock<Arc<FullKernelSymbols>> = OnceLock::new();
    KernelSymbolTable::Full(Arc::clone(KERNEL_SYMBOLS.get_or_init(|| {
        let symbols = match load_kernel_symbols() {
            Ok(symbols) => symbols,
            Err(err) => {
                warn_kallsyms_unusable(Some(&err));
                FullKernelSymbols::default()
            }
        };
        if symbols.symbols.is_empty() {
            warn_kallsyms_unusable(None);
        }
        Arc::new(symbols)
    })))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::test_support::TempDir;

    #[test]
    fn full_kernel_symbol_table_keeps_the_last_alias_and_its_module() {
        let dir = TempDir::new("full-kernel-symbols");
        let path = dir.path().join("kallsyms");
        let kallsyms = "ffffffff81000000 T _text\n\
                        ffffffff81000100 t first\n\
                        ffffffff81000100 t last\t[module]\n";
        fs::write(&path, kallsyms).unwrap();

        let table = load_kernel_symbols_from_path(&path).unwrap();
        let symbol = resolve_kernel_symbol(&table, 0xffff_ffff_8100_0104).unwrap();
        assert_eq!(
            (symbol.name.as_str(), symbol.module.as_str()),
            ("last+0x4", "[module]")
        );
    }

    #[test]
    fn extending_sparse_kernel_symbols_without_addresses_allocates_nothing() {
        let existing: Arc<[(u64, KernelSymbol)]> = Arc::from([(
            0xffff_ffff_8100_0108,
            KernelSymbol {
                address: 0xffff_ffff_8100_0100,
                name: "do_syscall_64".into(),
                module: None,
            },
        )]);
        let mut table = KernelSymbolTable::Sparse(Arc::clone(&existing));

        let allocations = allocation_counter::measure(|| {
            extend_sparse_kernel_symbols_for_spool(&mut table, [], &[]);
        });

        assert_eq!(allocations.count_total, 0);
        let KernelSymbolTable::Sparse(actual) = table else {
            panic!("sparse table changed representation");
        };
        assert!(Arc::ptr_eq(&existing, &actual));
    }

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
