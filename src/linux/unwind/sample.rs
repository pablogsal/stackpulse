//! Build sampled stacks, retrying registered runtime frames after a metadata refresh.

use std::io;

use framehop::{
    DwarfUnwinderError, Error as FramehopError, FrameAddress, FramePointerFallbackReason,
    UnwindRegsNative, UnwinderError, UnwinderWithDetails,
};
use perf_event_open::sample::record::Priv;

use super::{NativeUnwinder, ProcessUnwinder};
use crate::linux::convert_regs::ConvertRegs;
use crate::linux::types::{StackFrame, StackMode};
use crate::linux::{is_kernel_mode, RecordingSummary};
use crate::stats::SampleErrorKind;
use crate::unwind_stats::{UnwindFallbackKind, UnwindFallbackStats};

/// Captured perf data borrowed for stack construction and any metadata retry.
#[derive(Clone, Copy)]
pub(in crate::linux) struct StackInput<'a> {
    /// Sampled instruction address used when no stack frame can be recovered.
    pub(in crate::linux) code_addr: Option<u64>,
    /// User registers in perf's capture order; `None` means no register state was supplied.
    pub(in crate::linux) user_regs: Option<&'a [u64]>,
    /// Captured user-stack bytes. `None` means missing data; an empty slice records
    /// a zero-byte capture and is diagnosed separately.
    pub(in crate::linux) user_stack: Option<&'a [u8]>,
}

/// Validated capture retained unchanged while each unwind attempt advances its own registers.
struct CapturedUserStack<'a> {
    /// Original user instruction pointer, where each unwind attempt starts.
    pc: u64,
    /// Original user stack pointer, the target address corresponding to `bytes[0]`.
    sp: u64,
    /// Original register state, copied before each attempt so unwinding cannot alter it.
    regs: UnwindRegsNative,
    /// Stack snapshot starting at `sp`; retries reuse it without rereading the target stack.
    bytes: &'a [u8],
}

impl<'a> StackInput<'a> {
    /// Validate capture data once; refreshing metadata cannot repair missing registers or bytes.
    fn prepare<C: ConvertRegs<UnwindRegs = UnwindRegsNative>>(
        self,
        privilege: Priv,
        summary: &mut RecordingSummary,
    ) -> Option<CapturedUserStack<'a>> {
        let user_stack = self.user_stack.filter(|stack| !stack.is_empty());
        if self.user_stack.is_some() && user_stack.is_none() {
            record_unwind_error(summary, SampleErrorKind::NativeStackRead, || {
                "perf sample reported zero user stack bytes".to_string()
            });
        }
        match (self.user_regs, user_stack) {
            (Some(raw_regs), Some(bytes)) => {
                if let Some((pc, sp, regs)) = C::convert_regs(raw_regs) {
                    return Some(CapturedUserStack {
                        pc,
                        sp,
                        regs,
                        bytes,
                    });
                }
                record_unwind_error(summary, SampleErrorKind::NativeRegisterCapture, || {
                    "perf sample contained incomplete user register state".to_string()
                });
            }
            _ if !is_kernel_mode(privilege) => {
                if self.user_regs.is_none() {
                    record_unwind_error(
                        summary,
                        SampleErrorKind::NativeUserRegistersMissing,
                        || "perf sample did not include user register state".to_string(),
                    );
                }
                if self.user_stack.is_none() {
                    record_unwind_error(summary, SampleErrorKind::NativeStackRead, || {
                        "perf sample did not include user stack bytes".to_string()
                    });
                }
            }
            _ => {}
        }
        None
    }
}

/// Diagnostics are committed only after any metadata refresh and single retry.
#[derive(Default)]
struct UnwindAttempt {
    /// First failing or fallback JIT frame, normalized for code-range lookup.
    /// Identifies a refresh candidate without deciding whether its deadline allows a read.
    refresh_address: Option<u64>,
    /// Terminal error from this attempt, discarded if refreshed metadata causes a retry.
    error: Option<FramehopError>,
    /// Frame-pointer fallbacks that recovered a caller in this attempt.
    /// These counters are merged into the recording only if the attempt is accepted.
    fallbacks: UnwindFallbackStats,
}

impl UnwindAttempt {
    /// Refresh only a failing frame owned by a registered runtime range.
    fn consider_refresh(&mut self, unwinder: &NativeUnwinder, address: FrameAddress) {
        if self.refresh_address.is_none() && unwinder.is_runtime_frame(address) {
            self.refresh_address = Some(address.address_for_lookup());
        }
    }
}

/// Preserve kernel frames, unwind captured user data, and account for the accepted attempt.
/// A metadata change permits one retry from the original capture; refresh errors propagate.
pub(in crate::linux) fn build_sample_stack<C: ConvertRegs<UnwindRegs = UnwindRegsNative>>(
    sample: StackInput<'_>,
    privilege: Priv,
    process_unwinder: &mut ProcessUnwinder,
    stack: &mut Vec<StackFrame>,
    callchain_stack: &[StackFrame],
    summary: &mut RecordingSummary,
    mut refresh: impl FnMut(&mut ProcessUnwinder, u64) -> io::Result<bool>,
) -> io::Result<()> {
    stack.clear();
    let kernel_frame_count = callchain_stack
        .iter()
        .take_while(|&&frame| stack_frame_is_kernel(frame))
        .count();
    let (kernel_frames, ignored_user_frames) = callchain_stack.split_at(kernel_frame_count);
    stack.extend_from_slice(kernel_frames);

    if let Some(capture) = sample.prepare::<C>(privilege, summary) {
        let mut attempt = unwind_captured_stack(&capture, process_unwinder, stack);
        if let Some(address) = attempt.refresh_address {
            if refresh(process_unwinder, address)? {
                stack.truncate(kernel_frame_count);
                attempt = unwind_captured_stack(&capture, process_unwinder, stack);
            }
        }
        summary.unwind_fallbacks.merge(&attempt.fallbacks);
        if let Some(err) = attempt.error {
            record_unwind_error(summary, sample_error_for_framehop(err), || {
                format!("framehop error during perf native unwind: {err}")
            });
        }
    }

    if stack.is_empty() {
        if let Some(ip) = sample.code_addr {
            stack.push(StackFrame::InstructionPointer(ip, privilege.into()));
        }
    }
    summary.ignored_user_callchain_frames = summary
        .ignored_user_callchain_frames
        .saturating_add(ignored_user_frames.len() as u64);
    Ok(())
}

/// Append native frames without committing diagnostics or changing the saved capture.
fn unwind_captured_stack(
    capture: &CapturedUserStack<'_>,
    process_unwinder: &mut ProcessUnwinder,
    stack: &mut Vec<StackFrame>,
) -> UnwindAttempt {
    const MAX_NATIVE_UNWIND_FRAMES: usize = 1_024;

    let (words, _) = capture.bytes.as_chunks::<8>();
    let mut read_stack = |addr: u64| {
        let index = addr
            .checked_sub(capture.sp)
            .filter(|offset| offset % 8 == 0)
            .and_then(|offset| usize::try_from(offset / 8).ok())
            .ok_or(())?;
        words.get(index).copied().map(u64::from_ne_bytes).ok_or(())
    };

    let mut attempt = UnwindAttempt::default();
    let mut regs = capture.regs;
    let mut address = FrameAddress::from_instruction_pointer(capture.pc);
    let native_start = stack.len();
    stack.push(StackFrame::InstructionPointer(capture.pc, StackMode::User));
    let truncated = loop {
        if stack.len() - native_start >= MAX_NATIVE_UNWIND_FRAMES {
            break true;
        }
        match process_unwinder.unwinder.unwind_frame_with_details(
            address,
            &mut regs,
            &mut process_unwinder.cache,
            &mut read_stack,
        ) {
            Ok(outcome) => {
                if outcome.fallback_reason().is_some() {
                    attempt.consider_refresh(&process_unwinder.unwinder, address);
                }
                let Some(return_address) = outcome.return_address() else {
                    break false;
                };
                let Some(caller) = FrameAddress::from_return_address(return_address) else {
                    attempt.consider_refresh(&process_unwinder.unwinder, address);
                    attempt.error = Some(FramehopError::ReturnAddressIsNull);
                    break true;
                };
                if let Some(reason) = outcome.fallback_reason() {
                    attempt.fallbacks.record(fallback_kind(reason));
                }
                address = caller;
                stack.push(StackFrame::ReturnAddress(return_address, StackMode::User));
            }
            Err(err) => {
                attempt.consider_refresh(&process_unwinder.unwinder, address);
                attempt.error = Some(err);
                break true;
            }
        }
    };
    if truncated {
        stack.push(StackFrame::TruncatedStackMarker);
    }
    attempt
}

fn stack_frame_is_kernel(frame: StackFrame) -> bool {
    matches!(
        frame,
        StackFrame::InstructionPointer(_, StackMode::Kernel)
            | StackFrame::ReturnAddress(_, StackMode::Kernel)
    )
}

fn record_unwind_error(
    summary: &mut RecordingSummary,
    kind: SampleErrorKind,
    context: impl FnOnce() -> String,
) {
    summary.error_stats.record_with_log(kind, context);
}

#[inline]
fn sample_error_for_framehop(error: FramehopError) -> SampleErrorKind {
    match error {
        FramehopError::CouldNotReadStack(_) => SampleErrorKind::NativeStackTruncated,
        FramehopError::DidNotAdvance => SampleErrorKind::NativeFramehopDidNotAdvance,
        FramehopError::ReturnAddressIsNull => SampleErrorKind::NativeFramehopReturnAddressNull,
        FramehopError::FramepointerUnwindingMovedBackwards => {
            SampleErrorKind::NativeFramehopMovedBackwards
        }
        FramehopError::IntegerOverflow => SampleErrorKind::NativeFramehopIntegerOverflow,
    }
}

fn fallback_kind(reason: FramePointerFallbackReason) -> UnwindFallbackKind {
    match reason {
        FramePointerFallbackReason::NoModule => UnwindFallbackKind::NoModule,
        // Other Framehop format features can be enabled by another crate in the
        // dependency graph even though this Linux recorder cannot produce them.
        #[allow(unreachable_patterns)]
        FramePointerFallbackReason::UnwindInfo(error) => match error {
            UnwinderError::NoModuleUnwindData => UnwindFallbackKind::NoModuleUnwindData,
            UnwinderError::EhFrameHdrCouldNotFindAddress => UnwindFallbackKind::EhFrameHdrLookup,
            UnwinderError::DwarfCfiIndexCouldNotFindAddress => {
                UnwindFallbackKind::DwarfCfiIndexLookup
            }
            UnwinderError::Dwarf(error) => match error {
                DwarfUnwinderError::FdeFromOffsetFailed(_) => UnwindFallbackKind::DwarfFdeRead,
                DwarfUnwinderError::UnwindInfoForAddressFailed(_) => {
                    UnwindFallbackKind::DwarfUnwindInfo
                }
                DwarfUnwinderError::StackPointerMovedBackwards => {
                    UnwindFallbackKind::DwarfStackPointerMovedBackwards
                }
                DwarfUnwinderError::DidNotAdvance => UnwindFallbackKind::DwarfDidNotAdvance,
                DwarfUnwinderError::CouldNotRecoverCfa => {
                    UnwindFallbackKind::DwarfCouldNotRecoverCfa
                }
                DwarfUnwinderError::CouldNotRecoverReturnAddress => {
                    UnwindFallbackKind::DwarfCouldNotRecoverReturnAddress
                }
                DwarfUnwinderError::CouldNotRecoverFramePointer => {
                    UnwindFallbackKind::DwarfCouldNotRecoverFramePointer
                }
            },
            _ => UnwindFallbackKind::OtherUnwindFormat,
        },
    }
}

#[cfg(test)]
mod tests;
