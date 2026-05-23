#[cfg(target_arch = "aarch64")]
use framehop::aarch64::UnwindRegsAarch64;
#[cfg(target_arch = "x86_64")]
use framehop::x86_64::UnwindRegsX86_64;
#[cfg(target_arch = "aarch64")]
use perf_event_open_sys::bindings::{
    PERF_REG_ARM64_LR, PERF_REG_ARM64_PC, PERF_REG_ARM64_SP, PERF_REG_ARM64_X29,
};
#[cfg(target_arch = "x86_64")]
use perf_event_open_sys::bindings::{PERF_REG_X86_BP, PERF_REG_X86_IP, PERF_REG_X86_SP};

pub trait ConvertRegs {
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
pub struct ConvertRegsX86_64;
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
        Some((ip, sp, UnwindRegsX86_64::new(ip, sp, bp)))
    }
    fn regs_mask() -> u64 {
        (1_u64 << PERF_REG_X86_IP) | (1_u64 << PERF_REG_X86_SP) | (1_u64 << PERF_REG_X86_BP)
    }
}

#[cfg(target_arch = "aarch64")]
pub struct ConvertRegsAarch64;
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
        Some((ip, sp, UnwindRegsAarch64::new(lr, sp, fp)))
    }
    fn regs_mask() -> u64 {
        (1_u64 << PERF_REG_ARM64_PC)
            | (1_u64 << PERF_REG_ARM64_LR)
            | (1_u64 << PERF_REG_ARM64_SP)
            | (1_u64 << PERF_REG_ARM64_X29)
    }
}
