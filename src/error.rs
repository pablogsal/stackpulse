use std::fmt;

/// Error type returned by fallible stackpulse APIs.
///
/// All recorder, spool, and symbolization operations funnel their failures
/// through this enum. It implements [`std::error::Error`] and converts from
/// [`std::io::Error`], so it composes with `?` in callers that already use
/// `Result` from this crate.
#[derive(Debug)]
pub enum Error {
    /// A runtime failure with an attached human-readable message.
    ///
    /// Covers I/O errors, `perf_event_open` failures, malformed perf records,
    /// symbolizer errors, and other failure modes that surface as text rather
    /// than a typed variant.
    RuntimeError(String),
}

/// Convenience alias for `Result<T, Error>` used throughout the crate.
pub type Result<T> = std::result::Result<T, Error>;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RuntimeError(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Self::RuntimeError(err.to_string())
    }
}
