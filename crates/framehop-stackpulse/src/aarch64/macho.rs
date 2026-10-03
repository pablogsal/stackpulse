use super::arch::ArchAarch64;
use super::unwind_rule::UnwindRuleAarch64;
use crate::instruction_analysis::InstructionAnalysis;
use crate::macho::{CompactUnwindInfoUnwinderError, CompactUnwindInfoUnwinding, CuiUnwindResult};
use macho_unwind_info::opcodes::OpcodeArm64;
use macho_unwind_info::Function;

impl CompactUnwindInfoUnwinding for ArchAarch64 {
    fn unwind_frame(
        function: Function,
        is_first_frame: bool,
        address_offset_within_function: usize,
        function_bytes: Option<&[u8]>,
    ) -> Result<CuiUnwindResult<UnwindRuleAarch64>, CompactUnwindInfoUnwinderError> {
        let opcode = OpcodeArm64::parse(function.opcode);
        if is_first_frame {
            if opcode == OpcodeArm64::Null {
                return Ok(CuiUnwindResult::ExecRule(UnwindRuleAarch64::NoOp));
            }
            // The pc might be in a prologue or an epilogue. The compact unwind info format ignores
            // prologues and epilogues; the opcodes only describe the function body. So we do some
            // instruction analysis to check for prologues and epilogues.
            if let Some(function_bytes) = function_bytes {
                if let Some(rule) = Self::rule_from_instruction_analysis(
                    function_bytes,
                    address_offset_within_function,
                ) {
                    // We are inside a prologue / epilogue. Ignore the opcode and use the rule from
                    // instruction analysis.
                    return Ok(CuiUnwindResult::ExecRule(rule));
                }
            }
        }

        // At this point we know with high certainty that we are in a function body.
        let r = match opcode {
            OpcodeArm64::Null => {
                return Err(CompactUnwindInfoUnwinderError::FunctionHasNoInfo);
            }
            OpcodeArm64::Frameless {
                stack_size_in_bytes,
            } => {
                if is_first_frame {
                    if stack_size_in_bytes == 0 {
                        CuiUnwindResult::ExecRule(UnwindRuleAarch64::NoOp)
                    } else {
                        CuiUnwindResult::ExecRule(UnwindRuleAarch64::OffsetSp {
                            sp_offset_by_16: stack_size_in_bytes / 16,
                        })
                    }
                } else {
                    return Err(CompactUnwindInfoUnwinderError::CallerCannotBeFrameless);
                }
            }
            OpcodeArm64::Dwarf { eh_frame_fde } => CuiUnwindResult::NeedDwarf(eh_frame_fde),
            OpcodeArm64::FrameBased { .. } => {
                // Compact unwind specifies the exact caller SP and saved x29.
                // The caller may omit its frame pointer or use x29 for data.
                // Reserve UseFramePointer and its estimated SP for fallbacks.
                CuiUnwindResult::ExecRule(UnwindRuleAarch64::UseFramepointerWithOffsets {
                    sp_offset_from_fp_by_8: 2,
                    fp_storage_offset_from_fp_by_8: 0,
                    lr_storage_offset_from_fp_by_8: 1,
                })
            }
            OpcodeArm64::UnrecognizedKind(kind) => {
                return Err(CompactUnwindInfoUnwinderError::BadOpcodeKind(kind))
            }
        };
        Ok(r)
    }

    fn rule_for_stub_helper(
        offset: u32,
    ) -> Result<CuiUnwindResult<UnwindRuleAarch64>, CompactUnwindInfoUnwinderError> {
        //    shared:
        //  +0x0  1d309c  B1 94 48 10        adr        x17, #0x100264330
        //  +0x4  1d30a0  1F 20 03 D5        nop
        //  +0x8  1d30a4  F0 47 BF A9        stp        x16, x17, [sp, #-0x10]!
        //  +0xc  1d30a8  1F 20 03 D5        nop
        // +0x10  1d30ac  F0 7A 32 58        ldr        x16, #dyld_stub_binder_100238008
        // +0x14  1d30b0  00 02 1F D6        br         x16
        //     first stub:
        // +0x18  1d30b4  50 00 00 18        ldr        w16, =0x1800005000000000
        // +0x1c  1d30b8  F9 FF FF 17        b          0x1001d309c
        // +0x20  1d30bc  00 00 00 00        (padding)
        //     second stub:
        // +0x24  1d30c0  50 00 00 18        ldr        w16, =0x1800005000000012
        // +0x28  1d30c4  F6 FF FF 17        b          0x1001d309c
        // +0x2c  1d30c8  00 00 00 00        (padding)
        let rule = if offset < 0xc {
            // Stack pointer hasn't been touched, just follow lr
            UnwindRuleAarch64::NoOp
        } else if offset < 0x18 {
            // Add 0x10 to the stack pointer and follow lr
            UnwindRuleAarch64::OffsetSp { sp_offset_by_16: 1 }
        } else {
            // Stack pointer hasn't been touched, just follow lr
            UnwindRuleAarch64::NoOp
        };
        Ok(CuiUnwindResult::ExecRule(rule))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aarch64::{CacheAarch64, UnwindRegsAarch64, UnwinderAarch64};
    use crate::dwarf::tests::{eh_frame_with_fde, AARCH64_CIE};
    use crate::{ExplicitModuleSectionInfo, FrameAddress, Module, Unwinder, UnwinderWithDetails};
    use alloc::vec::Vec;
    use gimli::AArch64;

    fn frame_based_unwind_info() -> Vec<u8> {
        // Header, two first-level entries (function and sentinel), regular page.
        let mut data = Vec::new();
        for word in [1u32, 0, 0, 0, 0, 28, 2, 0x1000, 52, 0, 0x1100, 0, 0, 2] {
            data.extend(word.to_le_bytes());
        }
        data.extend(8u16.to_le_bytes());
        data.extend(1u16.to_le_bytes());
        data.extend(0x1000u32.to_le_bytes());
        data.extend(0x0400_0000u32.to_le_bytes());
        data
    }

    #[test]
    fn compact_frame_record_keeps_exact_sp_for_a_frameless_dwarf_caller() {
        let mut unwinder = UnwinderAarch64::new();
        unwinder.add_module(Module::new(
            "compact".into(),
            0x10000..0x20000,
            0x10000,
            ExplicitModuleSectionInfo {
                unwind_info: Some(frame_based_unwind_info()),
                ..Default::default()
            },
        ));
        // The caller saved x29 without establishing its own frame pointer.
        // Its CFA is SP+32, saved x29 is SP, and saved LR is SP+8.
        let (eh_frame, _) = eh_frame_with_fde(
            &AARCH64_CIE,
            0x1000..0x1100,
            &[
                gimli::DW_CFA_def_cfa_offset.0,
                32,
                gimli::DW_CFA_offset.0 | AArch64::X29.0 as u8,
                4,
                gimli::DW_CFA_offset.0 | AArch64::X30.0 as u8,
                3,
            ],
        );
        unwinder.add_module(Module::new(
            "dwarf".into(),
            0x20000..0x30000,
            0x20000,
            ExplicitModuleSectionInfo {
                eh_frame: Some(eh_frame),
                ..Default::default()
            },
        ));
        let mut cache = CacheAarch64::new();
        // Repeat with the same cache to exercise both decoded and cached rules.
        for _ in 0..2 {
            let mut regs = UnwindRegsAarch64::new(0x111, 0x40, 0x80);
            let mut read_stack = |address| match address {
                0x80 => Ok(0x200),
                0x88 => Ok(0x21010),
                0x90 => Ok(0x200),
                0x98 => Ok(0x22010),
                _ => Err(()),
            };
            let compact = unwinder
                .unwind_frame_with_details(
                    FrameAddress::from_instruction_pointer(0x11010),
                    &mut regs,
                    &mut cache,
                    &mut read_stack,
                )
                .unwrap();
            assert_eq!(compact.return_address(), Some(0x21010));
            assert_eq!(compact.fallback_reason(), None);
            assert_eq!((regs.sp(), regs.fp()), (0x90, 0x200));
            assert!(!regs.sp_is_fp_derived());
            let dwarf = unwinder
                .unwind_frame_with_details(
                    FrameAddress::from_return_address(0x21010).unwrap(),
                    &mut regs,
                    &mut cache,
                    &mut read_stack,
                )
                .unwrap();
            assert_eq!(dwarf.return_address(), Some(0x22010));
            assert_eq!(dwarf.fallback_reason(), None);
            assert_eq!((regs.sp(), regs.fp()), (0xb0, 0x200));
        }
    }

    #[test]
    fn compact_frame_record_restores_a_general_purpose_x29() {
        use crate::unwind_rule::UnwindRule;
        let function = Function {
            start_address: 0,
            end_address: 0x100,
            opcode: 0x0400_0000,
        };
        let CuiUnwindResult::ExecRule(rule) =
            ArchAarch64::unwind_frame(function, false, 16, None).unwrap()
        else {
            panic!("frame-based compact info must produce an unwind rule");
        };
        for saved_x29 in [0, 0x2a, 0x200] {
            let mut regs = UnwindRegsAarch64::new(0x111, 0x40, 0x80);
            let mut read_stack = |address| match address {
                0x80 => Ok(saved_x29),
                0x88 => Ok(0x21010),
                _ => Err(()),
            };
            assert_eq!(
                rule.exec(false, &mut regs, &mut read_stack),
                Ok(Some(0x21010))
            );
            assert_eq!((regs.sp(), regs.fp()), (0x90, saved_x29));
            assert!(!regs.sp_is_fp_derived());
        }
    }
}
