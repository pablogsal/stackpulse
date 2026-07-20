//! Shared module image-base representation.

/// The image-wide base addresses for one loaded object.
///
/// `avma` is the runtime address that corresponds to the object's `svma`.
/// Every mapping of the same loaded image shares this pair when correlation
/// against the object file succeeds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModuleImageBase {
    /// Process-absolute virtual memory address (AVMA) where the image's
    /// base SVMA is mapped.
    pub avma: u64,
    /// Static virtual memory address (SVMA) from the object file that
    /// corresponds to [`Self::avma`] at runtime.
    pub svma: u64,
}

impl ModuleImageBase {
    /// Build a base anchor from a matched (AVMA, SVMA) pair.
    #[must_use]
    pub const fn new(avma: u64, svma: u64) -> Self {
        Self { avma, svma }
    }

    /// Returns `None` when `avma` lies below the image base.
    #[must_use]
    pub const fn relative_address(self, avma: u64) -> Option<u64> {
        avma.checked_sub(self.avma)
    }

    /// Translate a runtime AVMA into the SVMA used by the object's symbol
    /// tables, debug info, and unwind sections.
    /// Returns `None` when the AVMA is below the image base or when adding the
    /// image-relative offset to the static base would overflow.
    #[must_use]
    pub const fn svma_for_avma(self, avma: u64) -> Option<u64> {
        let relative = match self.relative_address(avma) {
            Some(relative) => relative,
            None => return None,
        };
        self.svma.checked_add(relative)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checked_translation_rejects_avma_below_base() {
        let base = ModuleImageBase::new(0x2000, 0x1000);
        assert_eq!(base.relative_address(0x1fff), None);
        assert_eq!(base.svma_for_avma(0x1fff), None);
    }

    #[test]
    fn checked_translation_rejects_svma_overflow() {
        let base = ModuleImageBase::new(0x1000, u64::MAX - 1);
        assert_eq!(base.svma_for_avma(0x1002), None);
    }

    #[test]
    fn checked_translation_preserves_valid_addresses() {
        let base = ModuleImageBase::new(0x2000, 0x1000);
        assert_eq!(base.relative_address(0x2123), Some(0x123));
        assert_eq!(base.svma_for_avma(0x2123), Some(0x1123));
    }
}
