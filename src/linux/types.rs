use perf_event_open::sample::record::Priv;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StackMode {
    User,
    Kernel,
}

impl From<Priv> for StackMode {
    fn from(privilege: Priv) -> Self {
        match privilege {
            Priv::Kernel | Priv::Hv | Priv::GuestKernel => Self::Kernel,
            _ => Self::User,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StackFrame {
    InstructionPointer(u64, StackMode),
    ReturnAddress(u64, StackMode),
    TruncatedStackMarker,
}
