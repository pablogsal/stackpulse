use std::io;
#[cfg(test)]
use std::path::Path;
use std::path::PathBuf;

/// Result type used by StackPulse workflows.
pub type Result<T> = std::result::Result<T, Error>;

/// Stable category for a StackPulse error.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ErrorKind {
    /// Filesystem, kernel, or other I/O failure.
    Io,
    /// Invalid caller input.
    InvalidInput,
    /// The operation was denied by the operating system.
    Permission,
    /// The requested sampling rate exceeds the kernel limit.
    FrequencyLimit,
    /// The spool is malformed.
    CorruptSpool,
    /// The requested behavior is unavailable on this system or build.
    Unsupported,
    /// A native symbolizer failed or violated its output contract.
    NativeSymbolizer,
}

/// Error returned by StackPulse workflows.
#[derive(Debug, thiserror::Error)]
#[error("{source}")]
pub struct Error {
    kind: ErrorKind,
    #[source]
    source: Box<dyn std::error::Error + Send + Sync>,
}

impl Error {
    pub(crate) fn new(
        kind: ErrorKind,
        source: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        Self {
            kind,
            source: Box::new(source),
        }
    }

    pub(crate) fn message(kind: ErrorKind, message: impl Into<String>) -> Self {
        Self::new(kind, MessageError(message.into()))
    }

    pub(crate) fn native(source: Box<dyn std::error::Error + Send + Sync>) -> Self {
        Self {
            kind: ErrorKind::NativeSymbolizer,
            source,
        }
    }

    pub(crate) fn spool(source: io::Error) -> Self {
        match source.kind() {
            io::ErrorKind::InvalidData | io::ErrorKind::UnexpectedEof => {
                Self::new(ErrorKind::CorruptSpool, SpoolReadError { source })
            }
            _ => Self::from(source),
        }
    }

    /// Return the stable error category.
    #[must_use]
    pub const fn kind(&self) -> ErrorKind {
        self.kind
    }

    /// Return sampling-limit details when this is a frequency-limit error.
    #[must_use]
    pub fn frequency_limit(&self) -> Option<&crate::record::PerfFrequencyLimit> {
        find_in_chain(self.source.as_ref())
    }

    /// Return the underlying OS error code when this error came from I/O.
    #[must_use]
    pub fn raw_os_error(&self) -> Option<i32> {
        find_raw_os_error(self.source.as_ref())
    }

    /// Borrow the underlying I/O error, when present.
    #[must_use]
    pub fn io_error(&self) -> Option<&io::Error> {
        find_in_chain(self.source.as_ref())
    }
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        let kind = if find_in_chain::<crate::record::PerfFrequencyLimit>(&error).is_some() {
            ErrorKind::FrequencyLimit
        } else {
            match error.kind() {
                io::ErrorKind::InvalidInput => ErrorKind::InvalidInput,
                io::ErrorKind::PermissionDenied => ErrorKind::Permission,
                io::ErrorKind::Unsupported => ErrorKind::Unsupported,
                _ => ErrorKind::Io,
            }
        };
        Self::new(kind, error)
    }
}

fn find_in_chain<'a, T>(mut error: &'a (dyn std::error::Error + 'static)) -> Option<&'a T>
where
    T: std::error::Error + 'static,
{
    loop {
        if let Some(error) = error.downcast_ref::<T>() {
            return Some(error);
        }
        error = next_error(error)?;
    }
}

fn find_raw_os_error(mut error: &(dyn std::error::Error + 'static)) -> Option<i32> {
    loop {
        if let Some(io_error) = error.downcast_ref::<io::Error>() {
            if let Some(code) = io_error.raw_os_error() {
                return Some(code);
            }
        }
        error = next_error(error)?;
    }
}

fn next_error<'a>(
    error: &'a (dyn std::error::Error + 'static),
) -> Option<&'a (dyn std::error::Error + 'static)> {
    error
        .downcast_ref::<io::Error>()
        .and_then(io::Error::get_ref)
        .map(|source| source as &(dyn std::error::Error + 'static))
        .or_else(|| error.source())
}

impl From<Error> for io::Error {
    fn from(error: Error) -> Self {
        let kind = match error.kind {
            ErrorKind::FrequencyLimit | ErrorKind::InvalidInput => io::ErrorKind::InvalidInput,
            ErrorKind::Permission => io::ErrorKind::PermissionDenied,
            ErrorKind::CorruptSpool | ErrorKind::NativeSymbolizer => io::ErrorKind::InvalidData,
            ErrorKind::Unsupported => io::ErrorKind::Unsupported,
            ErrorKind::Io => error
                .io_error()
                .map_or(io::ErrorKind::Other, io::Error::kind),
        };
        Self::new(kind, error)
    }
}

#[derive(Debug, thiserror::Error)]
#[error("{operation}; cleanup also failed: {cleanup}")]
struct CleanupError {
    #[source]
    operation: io::Error,
    cleanup: io::Error,
}

pub(crate) fn with_cleanup_error(operation: io::Error, cleanup: io::Error) -> io::Error {
    let kind = operation.kind();
    io::Error::new(kind, CleanupError { operation, cleanup })
}

pub(crate) fn and_cleanup(operation: io::Result<()>, cleanup: io::Result<()>) -> io::Result<()> {
    match (operation, cleanup) {
        (Err(operation), Err(cleanup)) => Err(with_cleanup_error(operation, cleanup)),
        (Err(operation), Ok(())) => Err(operation),
        (Ok(()), Err(cleanup)) => Err(cleanup),
        (Ok(()), Ok(())) => Ok(()),
    }
}

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
struct MessageError(String);

#[derive(Debug, thiserror::Error)]
#[error("failed to read spool: {source}")]
struct SpoolReadError {
    #[source]
    source: io::Error,
}

#[derive(Debug, thiserror::Error)]
#[error("failed to parse ELF {}: {source}", path.display())]
pub(crate) struct ElfParseError {
    path: PathBuf,
    #[source]
    source: goblin::error::Error,
}

impl ElfParseError {
    pub(crate) fn new(path: impl Into<PathBuf>, source: goblin::error::Error) -> Self {
        Self {
            path: path.into(),
            source,
        }
    }

    #[cfg(test)]
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn into_io_error(self) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workflow_errors_keep_useful_classification_and_details() {
        let limit = crate::record::PerfFrequencyLimit {
            requested_frequency: 20_000,
            max_frequency: 10_000,
        };
        let error = Error::from(io::Error::new(io::ErrorKind::InvalidInput, limit));

        assert_eq!(error.kind(), ErrorKind::FrequencyLimit);
        assert_eq!(error.frequency_limit(), Some(&limit));
        assert!(error.to_string().contains("20000"));
        assert!(error.to_string().contains("10000"));

        let generic = Error::from(io::Error::new(io::ErrorKind::InvalidData, "bad proc data"));
        let spool = Error::spool(io::Error::new(io::ErrorKind::InvalidData, "bad record tag"));
        assert_eq!(generic.kind(), ErrorKind::Io);
        assert_eq!(spool.kind(), ErrorKind::CorruptSpool);
        assert_eq!(spool.to_string(), "failed to read spool: bad record tag");
    }

    #[test]
    fn cleanup_context_keeps_the_operational_error_primary() {
        let operation = io::Error::from_raw_os_error(libc::ENOSPC);
        let cleanup = io::Error::other("cleanup sentinel");
        let composed = with_cleanup_error(operation, cleanup);

        assert_eq!(composed.kind(), io::ErrorKind::StorageFull);
        assert!(composed.to_string().contains("cleanup sentinel"));
        let source = composed
            .get_ref()
            .and_then(std::error::Error::source)
            .and_then(|source| source.downcast_ref::<io::Error>());
        assert_eq!(source.and_then(io::Error::raw_os_error), Some(libc::ENOSPC));

        let error = Error::from(composed);
        assert_eq!(error.kind(), ErrorKind::Io);
        assert_eq!(error.raw_os_error(), Some(libc::ENOSPC));

        let limit = crate::record::PerfFrequencyLimit {
            requested_frequency: 20_000,
            max_frequency: 10_000,
        };
        let operation = io::Error::new(io::ErrorKind::InvalidInput, limit);
        let cleanup = io::Error::from_raw_os_error(libc::EPERM);
        let error = Error::from(with_cleanup_error(operation, cleanup));

        assert_eq!(error.kind(), ErrorKind::FrequencyLimit);
        assert_eq!(error.frequency_limit(), Some(&limit));
    }

    #[test]
    fn io_conversion_keeps_os_classification_and_stackpulse_source() {
        let converted: io::Error = Error::from(io::Error::from_raw_os_error(libc::ENOENT)).into();
        assert_eq!(converted.kind(), io::ErrorKind::NotFound);
        assert_eq!(
            converted
                .get_ref()
                .and_then(|error| error.downcast_ref::<Error>())
                .and_then(Error::raw_os_error),
            Some(libc::ENOENT)
        );
    }
}
