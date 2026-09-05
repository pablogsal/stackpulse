use crate::{error::UnwinderError, FrameAddress};

/// Why framehop used frame-pointer unwinding for a frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FramePointerFallbackReason {
    /// No registered module contains the instruction address.
    NoModule,
    /// The module's unwind information could not produce an unwind rule.
    UnwindInfo(UnwinderError),
}

/// Result of unwinding one frame, including any frame-pointer fallback.
///
/// A fallback reason is diagnostic information. If `return_address` is
/// present, frame-pointer unwinding recovered the caller successfully.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnwindFrameOutcome {
    return_address: Option<u64>,
    fallback_reason: Option<FramePointerFallbackReason>,
}

impl UnwindFrameOutcome {
    /// Create an outcome for a return address and its optional fallback reason.
    pub const fn new(
        return_address: Option<u64>,
        fallback_reason: Option<FramePointerFallbackReason>,
    ) -> Self {
        Self {
            return_address,
            fallback_reason,
        }
    }

    /// Return the caller's return address, or `None` at the end of the stack.
    pub const fn return_address(self) -> Option<u64> {
        self.return_address
    }

    /// Return why this step used frame-pointer unwinding, if it did.
    pub const fn fallback_reason(self) -> Option<FramePointerFallbackReason> {
        self.fallback_reason
    }
}

/// A frame yielded by detailed stack iteration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnwindFrame {
    address: FrameAddress,
    fallback_reason: Option<FramePointerFallbackReason>,
}

impl UnwindFrame {
    pub(crate) const fn new(
        address: FrameAddress,
        fallback_reason: Option<FramePointerFallbackReason>,
    ) -> Self {
        Self {
            address,
            fallback_reason,
        }
    }

    /// Return this frame's instruction or return address.
    pub const fn address(self) -> FrameAddress {
        self.address
    }

    /// Return why this frame was recovered with frame pointers, if applicable.
    pub const fn fallback_reason(self) -> Option<FramePointerFallbackReason> {
        self.fallback_reason
    }
}
