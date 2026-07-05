use std::fmt;

/// Error type returned by fallible stackpulse APIs.
#[derive(Debug)]
pub enum Error {
    /// I/O or OS error.
    Io(std::io::Error),
    /// A runtime failure with an attached human-readable message.
    RuntimeError(String),
}

/// Convenience alias for `Result<T, Error>` used throughout the crate.
pub type Result<T> = std::result::Result<T, Error>;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => err.fmt(f),
            Self::RuntimeError(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            Self::RuntimeError(_) => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}
