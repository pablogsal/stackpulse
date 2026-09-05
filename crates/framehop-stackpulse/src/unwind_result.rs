use crate::error::UnwinderError;

#[derive(Debug, Clone)]
pub enum UnwindResult<R> {
    ExecRule(R),
    ExecRuleWithDwarfRegisterDefaults(R),
    ExecRuleWithFallback(R, UnwinderError),
    Uncacheable(u64),
}
