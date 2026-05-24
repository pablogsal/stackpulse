//! Common traits for module sources used by native unwinding.

use std::ops::Range;

/// Minimal interface for module records consumed by generic module lookup.
pub trait ModuleInfoRecord {
    /// Runtime address range of the module.
    fn avma_range(&self) -> &Range<u64>;

    /// Whether the module is a Python runtime module.
    fn is_python(&self) -> bool;
}

/// Trait for sources of loaded module information.
pub trait ModuleSource {
    /// Concrete module record type.
    type Module: ModuleInfoRecord;

    /// Get all loaded modules.
    fn modules(&self) -> &[Self::Module];

    /// Find the module containing the given address.
    fn find_module(&self, addr: u64) -> Option<&Self::Module> {
        self.modules()
            .iter()
            .find(|m| m.avma_range().contains(&addr))
    }

    /// Check if an address is in a Python runtime module.
    fn is_python_address(&self, addr: u64) -> bool {
        self.find_module(addr)
            .is_some_and(ModuleInfoRecord::is_python)
    }
}

/// Find an address in a slice sorted by non-overlapping `avma_range.start`.
#[cfg(target_os = "linux")]
pub(crate) fn find_module_by_address_sorted<T: ModuleInfoRecord>(
    modules: &[T],
    addr: u64,
) -> Option<&T> {
    let idx = modules.partition_point(|module| module.avma_range().start <= addr);
    let module = modules.get(idx.checked_sub(1)?)?;
    module.avma_range().contains(&addr).then_some(module)
}

/// Sort modules in place by their `avma_range.start`, the canonical layout
/// expected by `find_module_by_address_sorted`. Asserts the resulting layout
/// is non-overlapping in debug builds so the per-lookup hot path stays cheap.
#[cfg(target_os = "linux")]
pub(crate) fn sort_modules_by_avma_start<T: ModuleInfoRecord>(modules: &mut [T]) {
    modules.sort_by_key(|module| module.avma_range().start);
    debug_assert!(
        modules
            .windows(2)
            .all(|w| w[0].avma_range().end <= w[1].avma_range().start),
        "sorted modules must be non-overlapping for binary search",
    );
}
