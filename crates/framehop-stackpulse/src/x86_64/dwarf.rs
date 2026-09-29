use arrayvec::ArrayVec;
use gimli::{
    CfaRule, Encoding, EvaluationStorage, Reader, ReaderOffset, Register, RegisterRule,
    UnwindContextStorage, UnwindSection, UnwindTableRow, X86_64,
};

use super::{
    arch::ArchX86_64,
    unwind_rule::{DwarfRegisterRule, UnwindRuleX86_64, DWARF_CALLEE_SAVED_REGISTERS},
    unwindregs::{Reg, UnwindRegsX86_64},
};
use crate::dwarf::{
    eval_cfa_rule, eval_register_rule, register_rule_to_cfa_offset, DwarfUnwindRegs,
    DwarfUnwinderError, DwarfUnwinding,
};
use crate::unwind_result::UnwindResult;

impl DwarfUnwindRegs for UnwindRegsX86_64 {
    fn get(&self, register: Register) -> Option<u64> {
        match register {
            X86_64::RA => Some(self.ip()),
            X86_64::RAX => self.get_if_set(Reg::RAX),
            X86_64::RDX => self.get_if_set(Reg::RDX),
            X86_64::RCX => self.get_if_set(Reg::RCX),
            X86_64::RBX => self.get_if_set(Reg::RBX),
            X86_64::RSI => self.get_if_set(Reg::RSI),
            X86_64::RDI => self.get_if_set(Reg::RDI),
            // RSP/RBP are always populated by `UnwindRegsX86_64::new`.
            X86_64::RSP => Some(self.sp()),
            X86_64::RBP => Some(self.bp()),
            X86_64::R8 => self.get_if_set(Reg::R8),
            X86_64::R9 => self.get_if_set(Reg::R9),
            X86_64::R10 => self.get_if_set(Reg::R10),
            X86_64::R11 => self.get_if_set(Reg::R11),
            X86_64::R12 => self.get_if_set(Reg::R12),
            X86_64::R13 => self.get_if_set(Reg::R13),
            X86_64::R14 => self.get_if_set(Reg::R14),
            X86_64::R15 => self.get_if_set(Reg::R15),
            _ => None,
        }
    }
}

impl DwarfUnwinding for ArchX86_64 {
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
        let bp_rule = unwind_info.register(X86_64::RBP);
        let ra_rule = unwind_info.register(X86_64::RA);

        // An undefined return address marks the outermost frame, even when the
        // row also saves general registers. Packed rules of 0 keep every
        // callee-saved register, the DWARF default.
        if matches!(ra_rule, None | Some(RegisterRule::Undefined)) {
            return Ok(UnwindResult::ExecRuleWithDwarfRegisterRules(
                UnwindRuleX86_64::EndOfStack,
                0,
            ));
        }

        if let Some(unwind_rule) =
            translate_into_unwind_rule(cfa_rule, bp_rule.as_ref(), ra_rule.as_ref())
        {
            if let Some(register_rules) = translate_into_register_rules(unwind_info) {
                return Ok(UnwindResult::ExecRuleWithDwarfRegisterRules(
                    unwind_rule,
                    register_rules,
                ));
            }
        }

        let cfa = eval_cfa_rule::<R, F, _, ES>(section, cfa_rule, encoding, regs, read_stack)
            .ok_or(DwarfUnwinderError::CouldNotRecoverCfa)?;

        let ip = regs.ip();
        let bp = regs.bp();
        let sp = regs.sp();

        let new_bp = eval_register_rule::<R, F, _, ES>(
            section, bp_rule, cfa, encoding, bp, regs, read_stack,
        )
        .unwrap_or(bp);

        let return_address = match eval_register_rule::<R, F, _, ES>(
            section, ra_rule, cfa, encoding, ip, regs, read_stack,
        ) {
            Some(ra) => ra,
            None => {
                let return_address_location = cfa
                    .checked_sub(8)
                    .ok_or(DwarfUnwinderError::CouldNotRecoverReturnAddress)?;
                read_stack(return_address_location)
                    .map_err(|_| DwarfUnwinderError::CouldNotRecoverReturnAddress)?
            }
        };
        if cfa == sp && return_address == ip {
            return Err(DwarfUnwinderError::DidNotAdvance);
        }
        if !is_first_frame && cfa < regs.sp() {
            return Err(DwarfUnwinderError::StackPointerMovedBackwards);
        }

        let restored_regs = recover_general_registers::<R, F, UCS, ES>(
            section,
            unwind_info,
            cfa,
            encoding,
            regs,
            read_stack,
        );
        regs.clear_non_frame_registers();
        for (register, value) in restored_regs {
            regs.set(register, value);
        }
        regs.set_ip(return_address);
        regs.set_bp(new_bp);
        regs.set_sp(cfa);

        Ok(UnwindResult::Uncacheable(return_address))
    }

    fn rule_if_uncovered_by_fde() -> Self::UnwindRule {
        UnwindRuleX86_64::JustReturnIfFirstFrameOtherwiseFp
    }
}

const GENERAL_REGISTERS: [(Reg, Register); 14] = [
    (Reg::RAX, X86_64::RAX),
    (Reg::RDX, X86_64::RDX),
    (Reg::RCX, X86_64::RCX),
    (Reg::RBX, X86_64::RBX),
    (Reg::RSI, X86_64::RSI),
    (Reg::RDI, X86_64::RDI),
    (Reg::R8, X86_64::R8),
    (Reg::R9, X86_64::R9),
    (Reg::R10, X86_64::R10),
    (Reg::R11, X86_64::R11),
    (Reg::R12, X86_64::R12),
    (Reg::R13, X86_64::R13),
    (Reg::R14, X86_64::R14),
    (Reg::R15, X86_64::R15),
];

/// Packs the general register rules of a row for `exec_with_dwarf_register_rules`, which
/// recovers the same registers as `recover_general_registers` as long as callee-saved
/// registers are only restored from stack slots and caller-saved registers stay undefined.
fn translate_into_register_rules<RO, UCS>(unwind_info: &UnwindTableRow<RO, UCS>) -> Option<u64>
where
    RO: ReaderOffset,
    UCS: UnwindContextStorage<RO>,
{
    let mut register_rules = [DwarfRegisterRule::SameValue; DWARF_CALLEE_SAVED_REGISTERS.len()];
    for (dwarf_register, rule) in unwind_info.registers() {
        let Some(&(register, ..)) = GENERAL_REGISTERS
            .iter()
            .find(|(_, general_register)| general_register == dwarf_register)
        else {
            continue;
        };
        let rule = match *rule {
            RegisterRule::SameValue => DwarfRegisterRule::SameValue,
            RegisterRule::Undefined => DwarfRegisterRule::Undefined,
            RegisterRule::Offset(offset) if offset % 8 == 0 => DwarfRegisterRule::Offset {
                cfa_offset_by_8: i8::try_from(offset / 8).ok()?,
            },
            _ => return None,
        };
        match DWARF_CALLEE_SAVED_REGISTERS
            .iter()
            .position(|&callee_saved| callee_saved == register)
        {
            Some(index) => register_rules[index] = rule,
            None if rule == DwarfRegisterRule::Undefined => {}
            None => return None,
        }
    }
    Some(DwarfRegisterRule::pack(register_rules))
}

fn recover_general_registers<R, F, UCS, ES>(
    section: &impl UnwindSection<R>,
    unwind_info: &UnwindTableRow<R::Offset, UCS>,
    cfa: u64,
    encoding: Encoding,
    regs: &UnwindRegsX86_64,
    read_stack: &mut F,
) -> ArrayVec<(Reg, u64), 14>
where
    R: Reader,
    F: FnMut(u64) -> Result<u64, ()>,
    UCS: UnwindContextStorage<R::Offset>,
    ES: EvaluationStorage<R>,
{
    GENERAL_REGISTERS
        .into_iter()
        .filter_map(|(register, dwarf_register)| {
            let current = regs.get_if_set(register);
            let recovered = match unwind_info.register(dwarf_register) {
                None if DWARF_CALLEE_SAVED_REGISTERS.contains(&register) => current,
                None | Some(RegisterRule::Undefined) => None,
                Some(RegisterRule::SameValue) => current,
                Some(rule) => eval_register_rule::<R, F, _, ES>(
                    section,
                    Some(rule),
                    cfa,
                    encoding,
                    current.unwrap_or_default(),
                    regs,
                    read_stack,
                ),
            };
            recovered.map(|value| (register, value))
        })
        .collect()
}

fn translate_into_unwind_rule<RO: ReaderOffset>(
    cfa_rule: &CfaRule<RO>,
    bp_rule: Option<&RegisterRule<RO>>,
    ra_rule: Option<&RegisterRule<RO>>,
) -> Option<UnwindRuleX86_64> {
    if !matches!(ra_rule, Some(RegisterRule::Offset(-8))) {
        return None;
    }

    match cfa_rule {
        CfaRule::RegisterAndOffset { register, offset } => match *register {
            X86_64::RSP if offset % 8 == 0 => {
                let sp_offset_by_8 = u16::try_from(offset / 8).ok()?;
                let fp_cfa_offset = register_rule_to_cfa_offset(bp_rule)?;
                match fp_cfa_offset {
                    None => Some(UnwindRuleX86_64::OffsetSp { sp_offset_by_8 }),
                    Some(bp_cfa_offset) if bp_cfa_offset % 8 == 0 => {
                        let bp_storage_offset_from_sp_by_8 =
                            i16::try_from(offset.checked_add(bp_cfa_offset)? / 8).ok()?;
                        Some(UnwindRuleX86_64::OffsetSpAndRestoreBp {
                            sp_offset_by_8,
                            bp_storage_offset_from_sp_by_8,
                        })
                    }
                    Some(_) => None,
                }
            }
            X86_64::RBP => {
                let bp_cfa_offset = register_rule_to_cfa_offset(bp_rule).flatten()?;
                if *offset == 16 && bp_cfa_offset == -16 {
                    Some(UnwindRuleX86_64::UseFramePointer)
                } else {
                    // TODO: Maybe handle this case. This case has been observed in _ffi_call_unix64,
                    // which has the following unwind table:
                    //
                    // 00000060 00000024 0000001c FDE cie=00000048 pc=000de548...000de6a6
                    //   0xde548: CFA=reg7+8: reg16=[CFA-8]
                    //   0xde562: CFA=reg6+32: reg6=[CFA-16], reg16=[CFA-8]
                    //   0xde5ad: CFA=reg7+8: reg16=[CFA-8]
                    //   0xde668: CFA=reg7+8: reg6=[CFA-16], reg16=[CFA-8]
                    None
                }
            }
            _ => None,
        },
        CfaRule::Expression(_) => None,
    }
}
