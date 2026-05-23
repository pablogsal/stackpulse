//! Shared module image-base representation.

/// The image-wide base addresses for one loaded object.
///
/// `avma` is the runtime address that corresponds to the object's `svma`.
/// Every mapping of the same loaded image shares this pair when correlation
/// against the object file succeeds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModuleImageBase {
    pub avma: u64,
    pub svma: u64,
}

impl ModuleImageBase {
    #[must_use]
    pub const fn new(avma: u64, svma: u64) -> Self {
        Self { avma, svma }
    }

    #[must_use]
    pub fn relative_address(self, avma: u64) -> u64 {
        debug_assert!(
            avma >= self.avma,
            "module address {avma:#x} must not be below base {:#x}",
            self.avma
        );
        avma.saturating_sub(self.avma)
    }

    #[must_use]
    pub fn svma_for_avma(self, avma: u64) -> u64 {
        self.relative_address(avma) + self.svma
    }
}
