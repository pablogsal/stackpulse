use std::fmt;
use std::num::NonZeroI32;

/// Positive Linux process identifier.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct Pid(NonZeroI32);

impl Pid {
    /// Construct a process id, rejecting zero and negative values.
    #[must_use]
    pub const fn new(raw: i32) -> Option<Self> {
        match NonZeroI32::new(raw) {
            Some(raw) if raw.is_positive() => Some(Self(raw)),
            _ => None,
        }
    }

    /// Return the platform `pid_t` representation.
    #[must_use]
    pub const fn get(self) -> i32 {
        self.0.get()
    }

    pub(crate) const fn get_u32(self) -> u32 {
        self.get() as u32
    }
}

impl TryFrom<i32> for Pid {
    type Error = InvalidPid;

    fn try_from(raw: i32) -> Result<Self, Self::Error> {
        Self::new(raw).ok_or(InvalidPid(i64::from(raw)))
    }
}

impl TryFrom<u32> for Pid {
    type Error = InvalidPid;

    fn try_from(raw: u32) -> Result<Self, Self::Error> {
        i32::try_from(raw)
            .ok()
            .and_then(Self::new)
            .ok_or(InvalidPid(i64::from(raw)))
    }
}

impl fmt::Display for Pid {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.get().fmt(fmt)
    }
}

/// Positive Linux thread identifier.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct Tid(NonZeroI32);

impl Tid {
    /// Construct a thread id, rejecting zero and negative values.
    #[must_use]
    pub const fn new(raw: i32) -> Option<Self> {
        match NonZeroI32::new(raw) {
            Some(raw) if raw.is_positive() => Some(Self(raw)),
            _ => None,
        }
    }

    /// Return the platform `pid_t` representation.
    #[must_use]
    pub const fn get(self) -> i32 {
        self.0.get()
    }
}

impl TryFrom<i32> for Tid {
    type Error = InvalidTid;

    fn try_from(raw: i32) -> Result<Self, Self::Error> {
        Self::new(raw).ok_or(InvalidTid(i64::from(raw)))
    }
}

impl TryFrom<u32> for Tid {
    type Error = InvalidTid;

    fn try_from(raw: u32) -> Result<Self, Self::Error> {
        i32::try_from(raw)
            .ok()
            .and_then(Self::new)
            .ok_or(InvalidTid(i64::from(raw)))
    }
}

impl TryFrom<u64> for Tid {
    type Error = InvalidTid;

    fn try_from(raw: u64) -> Result<Self, Self::Error> {
        i32::try_from(raw)
            .ok()
            .and_then(Self::new)
            .ok_or_else(|| InvalidTid(i64::try_from(raw).unwrap_or(i64::MAX)))
    }
}

impl fmt::Display for Tid {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.get().fmt(fmt)
    }
}

/// Invalid process-id input.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, thiserror::Error)]
#[error("invalid process id {0}")]
pub struct InvalidPid(i64);

/// Invalid thread-id input.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, thiserror::Error)]
#[error("invalid thread id {0}")]
pub struct InvalidTid(i64);
