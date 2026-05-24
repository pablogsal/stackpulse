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

    /// Distance of `avma` from the image base, i.e. an image-relative offset.
    ///
    /// Saturates to `0` if `avma` lies below the base; a debug build also
    /// asserts that this never happens for legitimate samples.
    #[must_use]
    pub fn relative_address(self, avma: u64) -> u64 {
        debug_assert!(
            avma >= self.avma,
            "module address {avma:#x} must not be below base {:#x}",
            self.avma
        );
        avma.saturating_sub(self.avma)
    }

    /// Translate a runtime AVMA into the SVMA used by the object's symbol
    /// tables, debug info, and unwind sections.
    #[must_use]
    pub fn svma_for_avma(self, avma: u64) -> u64 {
        self.relative_address(avma) + self.svma
    }
}
