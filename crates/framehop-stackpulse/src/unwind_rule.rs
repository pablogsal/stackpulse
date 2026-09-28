use crate::error::Error;

pub trait UnwindRule: Copy + core::fmt::Debug {
    type UnwindRegs;

    fn exec<F>(
        self,
        is_first_frame: bool,
        regs: &mut Self::UnwindRegs,
        read_stack: &mut F,
    ) -> Result<Option<u64>, Error>
    where
        F: FnMut(u64) -> Result<u64, ()>;

    /// Like `exec`, but also recovers the registers that the DWARF CFI row describes.
    /// `register_rules` is packed by the architecture's DWARF unwinder, and zero applies
    /// the DWARF defaults.
    fn exec_with_dwarf_register_rules<F>(
        self,
        _register_rules: u64,
        is_first_frame: bool,
        regs: &mut Self::UnwindRegs,
        read_stack: &mut F,
    ) -> Result<Option<u64>, Error>
    where
        F: FnMut(u64) -> Result<u64, ()>,
    {
        self.exec(is_first_frame, regs, read_stack)
    }

    fn rule_for_stub_functions() -> Self;
    fn rule_for_function_start() -> Self;
    fn fallback_rule() -> Self;
}
