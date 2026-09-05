/// Reason framehop used frame-pointer unwinding instead of module unwind data.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
#[non_exhaustive]
pub enum UnwindFallbackKind {
    /// The instruction address did not belong to a known module.
    NoModule = 0,
    /// The module had no usable unwind data.
    NoModuleUnwindData = 1,
    /// The `.eh_frame_hdr` lookup did not cover the address.
    EhFrameHdrLookup = 2,
    /// The fallback DWARF CFI index did not cover the address.
    DwarfCfiIndexLookup = 3,
    /// Reading an FDE from its recorded offset failed.
    DwarfFdeRead = 4,
    /// Computing unwind information for the address failed.
    DwarfUnwindInfo = 5,
    /// The DWARF rule moved the stack pointer backwards.
    DwarfStackPointerMovedBackwards = 6,
    /// The DWARF rule did not advance to another frame.
    DwarfDidNotAdvance = 7,
    /// The DWARF rule could not recover the canonical frame address.
    DwarfCouldNotRecoverCfa = 8,
    /// The DWARF rule could not recover the return address.
    DwarfCouldNotRecoverReturnAddress = 9,
    /// The DWARF rule could not recover the frame pointer.
    DwarfCouldNotRecoverFramePointer = 10,
    /// An unwind format that the Linux recorder does not use reported a failure.
    OtherUnwindFormat = 11,
}

impl UnwindFallbackKind {
    /// All fallback reasons in counter order.
    pub const ALL: &'static [Self] = &[
        Self::NoModule,
        Self::NoModuleUnwindData,
        Self::EhFrameHdrLookup,
        Self::DwarfCfiIndexLookup,
        Self::DwarfFdeRead,
        Self::DwarfUnwindInfo,
        Self::DwarfStackPointerMovedBackwards,
        Self::DwarfDidNotAdvance,
        Self::DwarfCouldNotRecoverCfa,
        Self::DwarfCouldNotRecoverReturnAddress,
        Self::DwarfCouldNotRecoverFramePointer,
        Self::OtherUnwindFormat,
    ];
}

const UNWIND_FALLBACK_KIND_COUNT: usize = UnwindFallbackKind::ALL.len();

const _: () = {
    let mut index = 0;
    while index < UnwindFallbackKind::ALL.len() {
        assert!(UnwindFallbackKind::ALL[index] as usize == index);
        index += 1;
    }
};

/// Counts successful unwind steps that had to use frame pointers.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct UnwindFallbackStats {
    counts: [u64; UNWIND_FALLBACK_KIND_COUNT],
}

impl UnwindFallbackStats {
    pub(crate) fn record(&mut self, kind: UnwindFallbackKind) {
        let count = &mut self.counts[kind as usize];
        *count = count.saturating_add(1);
    }

    /// Return the number of fallbacks with the given reason.
    #[must_use]
    pub fn count(&self, kind: UnwindFallbackKind) -> u64 {
        self.counts[kind as usize]
    }

    /// Return the total number of frame-pointer fallback steps.
    #[must_use]
    pub fn total(&self) -> u64 {
        self.counts.iter().sum()
    }

    /// Iterate over reasons that occurred at least once.
    pub fn nonzero_counts(&self) -> impl Iterator<Item = (UnwindFallbackKind, u64)> + '_ {
        UnwindFallbackKind::ALL.iter().filter_map(|&kind| {
            let count = self.count(kind);
            (count != 0).then_some((kind, count))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_reasons_separate() {
        let mut stats = UnwindFallbackStats::default();
        stats.record(UnwindFallbackKind::NoModule);
        stats.record(UnwindFallbackKind::DwarfCouldNotRecoverCfa);
        stats.record(UnwindFallbackKind::DwarfCouldNotRecoverCfa);

        assert_eq!(stats.total(), 3);
        assert_eq!(stats.count(UnwindFallbackKind::NoModule), 1);
        assert_eq!(stats.count(UnwindFallbackKind::DwarfCouldNotRecoverCfa), 2);
        assert_eq!(stats.nonzero_counts().count(), 2);
    }
}
