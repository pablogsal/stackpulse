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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stack_mode_classifies_privilege_levels() {
        assert_eq!(StackMode::from(Priv::User), StackMode::User);
        assert_eq!(StackMode::from(Priv::GuestUser), StackMode::User);
        assert_eq!(StackMode::from(Priv::Unknown), StackMode::User);
        assert_eq!(StackMode::from(Priv::Kernel), StackMode::Kernel);
        assert_eq!(StackMode::from(Priv::Hv), StackMode::Kernel);
        assert_eq!(StackMode::from(Priv::GuestKernel), StackMode::Kernel);
    }
}
