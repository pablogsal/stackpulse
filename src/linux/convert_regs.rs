#[cfg(target_arch = "aarch64")]
use framehop::aarch64::{PtrAuthMask, UnwindRegsAarch64};
#[cfg(target_arch = "x86_64")]
use framehop::x86_64::{Reg, UnwindRegsX86_64};
#[cfg(target_arch = "aarch64")]
use perf_event_open_sys::bindings::{
    PERF_REG_ARM64_LR, PERF_REG_ARM64_PC, PERF_REG_ARM64_SP, PERF_REG_ARM64_X29,
};
#[cfg(target_arch = "x86_64")]
use perf_event_open_sys::bindings::{
    PERF_REG_X86_AX, PERF_REG_X86_BP, PERF_REG_X86_BX, PERF_REG_X86_CX, PERF_REG_X86_DI,
    PERF_REG_X86_DX, PERF_REG_X86_IP, PERF_REG_X86_R10, PERF_REG_X86_R11, PERF_REG_X86_R12,
    PERF_REG_X86_R13, PERF_REG_X86_R14, PERF_REG_X86_R15, PERF_REG_X86_R8, PERF_REG_X86_R9,
    PERF_REG_X86_SI, PERF_REG_X86_SP,
};

#[cfg(target_arch = "x86_64")]
const X86_64_GENERAL_REGISTERS: [(u32, Reg); 16] = [
    (PERF_REG_X86_AX, Reg::RAX),
    (PERF_REG_X86_DX, Reg::RDX),
    (PERF_REG_X86_CX, Reg::RCX),
    (PERF_REG_X86_BX, Reg::RBX),
    (PERF_REG_X86_SI, Reg::RSI),
    (PERF_REG_X86_DI, Reg::RDI),
    (PERF_REG_X86_BP, Reg::RBP),
    (PERF_REG_X86_SP, Reg::RSP),
    (PERF_REG_X86_R8, Reg::R8),
    (PERF_REG_X86_R9, Reg::R9),
    (PERF_REG_X86_R10, Reg::R10),
    (PERF_REG_X86_R11, Reg::R11),
    (PERF_REG_X86_R12, Reg::R12),
    (PERF_REG_X86_R13, Reg::R13),
    (PERF_REG_X86_R14, Reg::R14),
    (PERF_REG_X86_R15, Reg::R15),
];

pub(super) trait ConvertRegs {
    type UnwindRegs;
    /// `(pc, sp, regs)` if every unwind register is present; `None` otherwise.
    fn convert_regs(regs: &[u64]) -> Option<(u64, u64, Self::UnwindRegs)>;
    fn regs_mask() -> u64;
}

fn reg_value(regs: &[u64], regs_mask: u64, register: u32) -> Option<u64> {
    let register_bit = 1_u64.checked_shl(register)?;
    if regs_mask & register_bit == 0 {
        return None;
    }
    let preceding_regs = regs_mask & (register_bit - 1);
    regs.get(preceding_regs.count_ones() as usize).copied()
}

#[cfg(target_arch = "x86_64")]
pub(super) struct ConvertRegsX86_64;
#[cfg(target_arch = "x86_64")]
impl ConvertRegs for ConvertRegsX86_64 {
    type UnwindRegs = UnwindRegsX86_64;
    fn convert_regs(regs: &[u64]) -> Option<(u64, u64, UnwindRegsX86_64)> {
        let regs_mask = Self::regs_mask();
        let (ip, sp, bp) = (
            reg_value(regs, regs_mask, PERF_REG_X86_IP)?,
            reg_value(regs, regs_mask, PERF_REG_X86_SP)?,
            reg_value(regs, regs_mask, PERF_REG_X86_BP)?,
        );
        let mut unwind_regs = UnwindRegsX86_64::new(ip, sp, bp);
        for (perf_reg, framehop_reg) in X86_64_GENERAL_REGISTERS {
            unwind_regs.set(framehop_reg, reg_value(regs, regs_mask, perf_reg)?);
        }
        Some((ip, sp, unwind_regs))
    }
    fn regs_mask() -> u64 {
        X86_64_GENERAL_REGISTERS
            .iter()
            .fold(1_u64 << PERF_REG_X86_IP, |mask, (reg, _)| {
                mask | (1_u64 << reg)
            })
    }
}

#[cfg(all(test, target_arch = "x86_64"))]
mod tests {
    use super::*;

    #[test]
    fn x86_64_conversion_preserves_every_requested_register() {
        let raw: Vec<_> = (0..=PERF_REG_X86_IP)
            .chain(PERF_REG_X86_R8..=PERF_REG_X86_R15)
            .map(|register| 100 + u64::from(register))
            .collect();

        let (ip, sp, regs) = ConvertRegsX86_64::convert_regs(&raw).unwrap();

        assert_eq!(ip, 100 + u64::from(PERF_REG_X86_IP));
        assert_eq!(sp, 100 + u64::from(PERF_REG_X86_SP));
        for (perf_reg, framehop_reg) in X86_64_GENERAL_REGISTERS {
            assert_eq!(
                regs.get_if_set(framehop_reg),
                Some(100 + u64::from(perf_reg))
            );
        }
    }
}

#[cfg(target_arch = "aarch64")]
pub(super) struct ConvertRegsAarch64;
#[cfg(target_arch = "aarch64")]
impl ConvertRegs for ConvertRegsAarch64 {
    type UnwindRegs = UnwindRegsAarch64;
    fn convert_regs(regs: &[u64]) -> Option<(u64, u64, UnwindRegsAarch64)> {
        let regs_mask = Self::regs_mask();
        let (ip, lr, sp, fp) = (
            reg_value(regs, regs_mask, PERF_REG_ARM64_PC)?,
            reg_value(regs, regs_mask, PERF_REG_ARM64_LR)?,
            reg_value(regs, regs_mask, PERF_REG_ARM64_SP)?,
            reg_value(regs, regs_mask, PERF_REG_ARM64_X29)?,
        );
        let ptr_auth_mask = PtrAuthMask::from_max_known_address(ip.max(sp).max(fp));
        Some((
            ip,
            sp,
            UnwindRegsAarch64::new_with_ptr_auth_mask(ptr_auth_mask, lr, sp, fp),
        ))
    }
    fn regs_mask() -> u64 {
        (1_u64 << PERF_REG_ARM64_PC)
            | (1_u64 << PERF_REG_ARM64_LR)
            | (1_u64 << PERF_REG_ARM64_SP)
            | (1_u64 << PERF_REG_ARM64_X29)
    }
}
