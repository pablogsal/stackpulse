use gimli::{
    AArch64, CfaRule, Encoding, EvaluationStorage, Reader, ReaderOffset, Register, RegisterRule,
    UnwindContextStorage, UnwindSection, UnwindTableRow,
};

use super::{arch::ArchAarch64, unwind_rule::UnwindRuleAarch64, unwindregs::UnwindRegsAarch64};

use crate::unwind_result::UnwindResult;

use crate::dwarf::{
    eval_cfa_rule, eval_register_rule, register_rule_to_cfa_offset, DwarfUnwindRegs,
    DwarfUnwinderError, DwarfUnwinding,
};

impl DwarfUnwindRegs for UnwindRegsAarch64 {
    fn get(&self, register: Register) -> Option<u64> {
        match register {
            AArch64::SP => Some(self.sp()),
            AArch64::X29 => Some(self.fp()),
            AArch64::X30 => Some(self.lr()),
            _ => None,
        }
    }
}

impl DwarfUnwinding for ArchAarch64 {
    fn unwind_frame<F, R, UCS, ES>(
        section: &impl UnwindSection<R>,
        unwind_info: &UnwindTableRow<R::Offset, UCS>,
        encoding: Encoding,
        regs: &mut Self::UnwindRegs,
        is_first_frame: bool,
        read_stack: &mut F,
    ) -> Result<UnwindResult<Self::UnwindRule>, DwarfUnwinderError>
    where
        F: FnMut(u64) -> Result<u64, ()>,
        R: Reader,
        UCS: UnwindContextStorage<R::Offset>,
        ES: EvaluationStorage<R>,
    {
        let cfa_rule = unwind_info.cfa();
        let fp_rule = unwind_info.register(AArch64::X29);
        let lr_rule = unwind_info.register(AArch64::X30);

        if let Some(unwind_rule) =
            translate_into_unwind_rule(cfa_rule, fp_rule.as_ref(), lr_rule.as_ref())
        {
            return Ok(UnwindResult::ExecRule(unwind_rule));
        }

        let cfa = eval_cfa_rule::<R, F, _, ES>(section, cfa_rule, encoding, regs, read_stack)
            .ok_or(DwarfUnwinderError::CouldNotRecoverCfa)?;

        let lr = regs.lr();
        let fp = regs.fp();
        let sp = regs.sp();

        let (fp, lr) = if !is_first_frame {
            if cfa <= sp {
                return Err(DwarfUnwinderError::StackPointerMovedBackwards);
            }
            let fp = eval_register_rule::<R, F, _, ES>(
                section, fp_rule, cfa, encoding, fp, regs, read_stack,
            )
            .ok_or(DwarfUnwinderError::CouldNotRecoverFramePointer)?;
            let lr = eval_register_rule::<R, F, _, ES>(
                section, lr_rule, cfa, encoding, lr, regs, read_stack,
            )
            .ok_or(DwarfUnwinderError::CouldNotRecoverReturnAddress)?;
            (fp, lr)
        } else {
            // For the first frame, be more lenient when encountering errors.
            // TODO: Find evidence of what this gives us. I think on macOS the prologue often has Unknown register rules
            // and we only encounter prologues for the first frame.
            let fp = eval_register_rule::<R, F, _, ES>(
                section, fp_rule, cfa, encoding, fp, regs, read_stack,
            )
            .unwrap_or(fp);
            let lr = eval_register_rule::<R, F, _, ES>(
                section, lr_rule, cfa, encoding, lr, regs, read_stack,
            )
            .unwrap_or(lr);
            (fp, lr)
        };

        regs.set_fp(fp);
        regs.set_sp(cfa);
        regs.set_lr(lr);
        if matches!(
            cfa_rule,
            CfaRule::RegisterAndOffset {
                register: AArch64::X29,
                ..
            }
        ) {
            // An x29-relative CFA gives the exact caller SP, not one estimated by the
            // frame-pointer fallback.
            regs.set_sp_is_fp_derived(false);
        }

        Ok(UnwindResult::Uncacheable(lr))
    }

    fn rule_if_uncovered_by_fde() -> Self::UnwindRule {
        UnwindRuleAarch64::NoOpIfFirstFrameOtherwiseFp
    }
}

fn translate_into_unwind_rule<RO: ReaderOffset>(
    cfa_rule: &CfaRule<RO>,
    fp_rule: Option<&RegisterRule<RO>>,
    lr_rule: Option<&RegisterRule<RO>>,
) -> Option<UnwindRuleAarch64> {
    match cfa_rule {
        CfaRule::RegisterAndOffset { register, offset } => match *register {
            AArch64::SP => {
                let sp_offset_by_16 = u16::try_from(offset / 16).ok()?;
                let lr_cfa_offset = register_rule_to_cfa_offset(lr_rule)?;
                let fp_cfa_offset = register_rule_to_cfa_offset(fp_rule)?;
                match (lr_cfa_offset, fp_cfa_offset) {
                    (None, Some(_)) => None,
                    (None, None) => {
                        match lr_rule {
                            None => {
                                // The column for the return address register was omitted from the DWARF CFI table.
                                // Per spec (at least as of DWARF >= 3), this means that it should be treated
                                // as undefined. However, in practice, it seems that compilers often omit the rule
                                // to say "same value", see https://github.com/gimli-rs/gimli/issues/857 .
                                Some(UnwindRuleAarch64::OffsetSp { sp_offset_by_16 })
                            }
                            Some(RegisterRule::Undefined) => {
                                // The column for the return address was manually set to "undefined"
                                // using DW_CFA_undefined. This usually means that the function never returns
                                // and can be treated as the root of the stack.
                                Some(
                                    UnwindRuleAarch64::OffsetSpIfFirstFrameOtherwiseStackEndsHere {
                                        sp_offset_by_16,
                                    },
                                )
                            }
                            _ => Some(UnwindRuleAarch64::OffsetSp { sp_offset_by_16 }),
                        }
                    }
                    (Some(lr_cfa_offset), None) => {
                        let lr_storage_offset_from_sp_by_8 =
                            i16::try_from((offset + lr_cfa_offset) / 8).ok()?;
                        Some(UnwindRuleAarch64::OffsetSpAndRestoreLr {
                            sp_offset_by_16,
                            lr_storage_offset_from_sp_by_8,
                        })
                    }
                    (Some(lr_cfa_offset), Some(fp_cfa_offset)) => {
                        let lr_storage_offset_from_sp_by_8 =
                            i16::try_from((offset + lr_cfa_offset) / 8).ok()?;
                        let fp_storage_offset_from_sp_by_8 =
                            i16::try_from((offset + fp_cfa_offset) / 8).ok()?;
                        Some(UnwindRuleAarch64::OffsetSpAndRestoreFpAndLr {
                            sp_offset_by_16,
                            fp_storage_offset_from_sp_by_8,
                            lr_storage_offset_from_sp_by_8,
                        })
                    }
                }
            }
            AArch64::X29 => {
                let lr_cfa_offset = register_rule_to_cfa_offset(lr_rule).flatten()?;
                let fp_cfa_offset = register_rule_to_cfa_offset(fp_rule).flatten()?;
                // Even the standard (x29 + 16, -16, -8) row avoids UseFramePointer: that rule is
                // the heuristic fallback, while this row gives the exact caller SP.
                let sp_offset_from_fp_by_8 = u16::try_from(offset / 8).ok()?;
                let lr_storage_offset_from_fp_by_8 =
                    i16::try_from((offset + lr_cfa_offset) / 8).ok()?;
                let fp_storage_offset_from_fp_by_8 =
                    i16::try_from((offset + fp_cfa_offset) / 8).ok()?;
                Some(UnwindRuleAarch64::UseFramepointerWithOffsets {
                    sp_offset_from_fp_by_8,
                    fp_storage_offset_from_fp_by_8,
                    lr_storage_offset_from_fp_by_8,
                })
            }
            _ => None,
        },
        CfaRule::Expression(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::super::{CacheAarch64, UnwindRegsAarch64, UnwinderAarch64};
    use super::*;
    use crate::dwarf::tests::{eh_frame_with_fde, AARCH64_CIE};
    use crate::{ExplicitModuleSectionInfo, FrameAddress, Module, Unwinder};

    #[test]
    fn frame_record_rows_restore_x29_used_as_a_general_register() {
        // CIE (CFA = sp) and an FDE for [0x1000, 0x1100) with the standard frame record row:
        // CFA = x29 + 16, x29 at CFA - 16, x30 at CFA - 8.
        let (eh_frame, _) = eh_frame_with_fde(
            &AARCH64_CIE,
            0x1000..0x1100,
            &[
                gimli::DW_CFA_def_cfa.0,
                AArch64::X29.0 as u8,
                16,
                gimli::DW_CFA_offset.0 | AArch64::X30.0 as u8,
                1,
                gimli::DW_CFA_offset.0 | AArch64::X29.0 as u8,
                2,
            ],
        );
        let mut unwinder = UnwinderAarch64::new();
        unwinder.add_module(Module::new(
            "test".into(),
            0x10000..0x20000,
            0x10000,
            ExplicitModuleSectionInfo {
                eh_frame: Some(eh_frame),
                ..Default::default()
            },
        ));
        // The caller uses x29 as a general register holding 0x2a, below the current x29.
        let mut regs = UnwindRegsAarch64::new(0x111, 0xff0, 0x1000);
        let mut read_stack = |address| match address {
            0x1000 => Ok(0x2a),
            0x1008 => Ok(0x12010),
            _ => Err(()),
        };
        let result = unwinder.unwind_frame(
            FrameAddress::from_instruction_pointer(0x11010),
            &mut regs,
            &mut CacheAarch64::new(),
            &mut read_stack,
        );
        assert_eq!(result, Ok(Some(0x12010)));
        assert_eq!((regs.sp(), regs.fp()), (0x1010, 0x2a));
    }
}
