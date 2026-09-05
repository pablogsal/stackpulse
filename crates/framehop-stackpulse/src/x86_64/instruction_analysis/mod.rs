use super::arch::ArchX86_64;
use crate::instruction_analysis::InstructionAnalysis;

#[cfg(feature = "macho")]
mod epilogue;
#[cfg(feature = "macho")]
mod prologue;

#[cfg(feature = "macho")]
use epilogue::unwind_rule_from_detected_epilogue;
#[cfg(feature = "macho")]
use prologue::unwind_rule_from_detected_prologue;

impl InstructionAnalysis for ArchX86_64 {
    #[cfg(feature = "macho")]
    fn rule_from_prologue_analysis(
        text_bytes: &[u8],
        pc_offset: usize,
    ) -> Option<Self::UnwindRule> {
        unwind_rule_from_detected_prologue(text_bytes, pc_offset)
    }

    #[cfg(feature = "macho")]
    fn rule_from_epilogue_analysis(
        text_bytes: &[u8],
        pc_offset: usize,
    ) -> Option<Self::UnwindRule> {
        unwind_rule_from_detected_epilogue(text_bytes, pc_offset)
    }
}
