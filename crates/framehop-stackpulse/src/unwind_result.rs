use crate::error::UnwinderError;

#[derive(Debug, Clone)]
pub enum UnwindResult<R> {
    ExecRule(R),
    ExecRuleWithDwarfRegisterRules(R, u64),
    ExecRuleWithFallback(R, UnwinderError),
    Uncacheable(u64),
}
