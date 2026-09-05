use alloc::boxed::Box;

use crate::{unwind_rule::UnwindRule, FramePointerFallbackReason};

const CACHE_ENTRY_COUNT: usize = 509;
const CACHE_FLAG_WORD_COUNT: usize = CACHE_ENTRY_COUNT.div_ceil(u64::BITS as usize);

pub struct RuleCache<R: UnwindRule> {
    entries: Box<[Option<CacheEntry<R>>; CACHE_ENTRY_COUNT]>,
    fallbacks: Box<[Option<FramePointerFallbackReason>; CACHE_ENTRY_COUNT]>,
    dwarf_register_defaults: [u64; CACHE_FLAG_WORD_COUNT],
    stats: CacheStats,
}

impl<R: UnwindRule> RuleCache<R> {
    pub fn new() -> Self {
        Self {
            entries: Box::new([None; CACHE_ENTRY_COUNT]),
            fallbacks: Box::new([None; CACHE_ENTRY_COUNT]),
            dwarf_register_defaults: [0; CACHE_FLAG_WORD_COUNT],
            stats: CacheStats::new(),
        }
    }

    pub fn lookup(
        &mut self,
        address: u64,
        modules_generation: u16,
        is_first_frame: bool,
    ) -> CacheResult<R> {
        let slot = ((address % CACHE_ENTRY_COUNT as u64) * 2 + u64::from(is_first_frame))
            % CACHE_ENTRY_COUNT as u64;
        let slot = slot as u16;
        match &self.entries[slot as usize] {
            None => {
                self.stats.miss_empty_slot_count += 1;
            }
            Some(entry) => {
                if entry.modules_generation == modules_generation {
                    if entry.address == address {
                        self.stats.hit_count += 1;
                        return CacheResult::Hit(
                            entry.unwind_rule,
                            self.fallbacks[slot as usize],
                            self.uses_dwarf_register_defaults(slot),
                        );
                    } else {
                        self.stats.miss_wrong_address_count += 1;
                    }
                } else {
                    self.stats.miss_wrong_modules_count += 1;
                }
            }
        }
        CacheResult::Miss(CacheHandle {
            slot,
            address,
            modules_generation,
        })
    }

    pub fn insert(
        &mut self,
        handle: CacheHandle,
        unwind_rule: R,
        fallback: Option<FramePointerFallbackReason>,
        uses_dwarf_register_defaults: bool,
    ) {
        let CacheHandle {
            slot,
            address,
            modules_generation,
        } = handle;
        self.entries[slot as usize] = Some(CacheEntry {
            address,
            modules_generation,
            unwind_rule,
        });
        self.fallbacks[slot as usize] = fallback;
        self.set_uses_dwarf_register_defaults(slot, uses_dwarf_register_defaults);
    }

    /// Returns a snapshot of the cache usage statistics.
    pub fn stats(&self) -> CacheStats {
        self.stats
    }

    fn uses_dwarf_register_defaults(&self, slot: u16) -> bool {
        let slot = usize::from(slot);
        self.dwarf_register_defaults[slot / u64::BITS as usize] & (1 << (slot % u64::BITS as usize))
            != 0
    }

    fn set_uses_dwarf_register_defaults(&mut self, slot: u16, value: bool) {
        let slot = usize::from(slot);
        let word = &mut self.dwarf_register_defaults[slot / u64::BITS as usize];
        let mask = 1 << (slot % u64::BITS as usize);
        if value {
            *word |= mask;
        } else {
            *word &= !mask;
        }
    }
}

pub enum CacheResult<R: UnwindRule> {
    Miss(CacheHandle),
    Hit(R, Option<FramePointerFallbackReason>, bool),
}

pub struct CacheHandle {
    slot: u16,
    address: u64,
    modules_generation: u16,
}

const _: () = assert!(
    CACHE_ENTRY_COUNT as u64 <= u16::MAX as u64,
    "u16 should be sufficient to store the cache slot index"
);

#[derive(Clone, Copy, Debug)]
struct CacheEntry<R: UnwindRule> {
    address: u64,
    modules_generation: u16,
    unwind_rule: R,
}

/// Statistics about the effectiveness of the rule cache.
#[derive(Default, Debug, Clone, Copy)]
pub struct CacheStats {
    /// The number of successful cache hits.
    pub hit_count: u64,
    /// The number of cache misses that were due to an empty slot.
    pub miss_empty_slot_count: u64,
    /// The number of cache misses that were due to a filled slot whose module
    /// generation didn't match the unwinder's current module generation.
    /// (This means that either the unwinder's modules have changed since the
    /// rule in this slot was stored, or the same cache is used with multiple
    /// unwinders and the unwinders are stomping on each other's cache slots.)
    pub miss_wrong_modules_count: u64,
    /// The number of cache misses that were due to cache slot collisions of
    /// different addresses.
    pub miss_wrong_address_count: u64,
}

impl CacheStats {
    /// Create a new instance.
    pub fn new() -> Self {
        Default::default()
    }

    /// The number of total lookups.
    pub fn total(&self) -> u64 {
        self.hits() + self.misses()
    }

    /// The number of total hits.
    pub fn hits(&self) -> u64 {
        self.hit_count
    }

    /// The number of total misses.
    pub fn misses(&self) -> u64 {
        self.miss_empty_slot_count + self.miss_wrong_modules_count + self.miss_wrong_address_count
    }
}

#[cfg(test)]
mod tests {
    use crate::{aarch64::UnwindRuleAarch64, x86_64::UnwindRuleX86_64};

    use super::*;

    // Ensure that the size of Option<CacheEntry<UnwindRuleX86_64>> doesn't change by accident.
    #[test]
    fn test_cache_entry_size() {
        assert_eq!(
            core::mem::size_of::<Option<CacheEntry<UnwindRuleX86_64>>>(),
            16
        );
        assert_eq!(
            core::mem::size_of::<Option<CacheEntry<UnwindRuleAarch64>>>(),
            24 // <-- larger than we'd like
        );
    }
}
