use std::fmt;
use std::path::{Path, PathBuf};

/// Error type returned by fallible stackpulse APIs.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// I/O or OS error.
    Io(std::io::Error),
    /// An ELF image could not be parsed.
    ElfParse(ElfParseError),
}

/// An ELF parse failure with the affected path and original parser error.
#[derive(Debug)]
pub struct ElfParseError {
    path: PathBuf,
    source: goblin::error::Error,
}

impl ElfParseError {
    pub(crate) fn new(path: impl Into<PathBuf>, source: goblin::error::Error) -> Self {
        Self {
            path: path.into(),
            source,
        }
    }

    /// Path of the ELF image that failed to parse.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl fmt::Display for ElfParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "failed to parse ELF {}: {}",
            self.path.display(),
            self.source
        )
    }
}

impl std::error::Error for ElfParseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => err.fmt(f),
            Self::ElfParse(err) => err.fmt(f),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            Self::ElfParse(err) => Some(err),
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

impl From<ElfParseError> for Error {
    fn from(err: ElfParseError) -> Self {
        Self::ElfParse(err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_and_source_follow_io_error() {
        let err = Error::from(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "denied",
        ));

        assert_eq!(err.to_string(), "denied");
        assert!(std::error::Error::source(&err).is_some());
    }

    #[test]
    fn elf_parse_error_preserves_path_and_source_chain() {
        let parser_error = goblin::elf::Elf::parse(&[]).expect_err("reject empty ELF");
        let err = Error::from(ElfParseError::new("/tmp/broken.so", parser_error));

        assert!(err.to_string().starts_with("failed to parse ELF "));
        let source = std::error::Error::source(&err).expect("ELF error source");
        let parse = source
            .downcast_ref::<ElfParseError>()
            .expect("structured ELF parse error");
        assert_eq!(parse.path(), Path::new("/tmp/broken.so"));
        assert!(source
            .source()
            .is_some_and(|source| { source.downcast_ref::<goblin::error::Error>().is_some() }));
    }

    #[test]
    fn errors_are_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}

        assert_send_sync::<Error>();
        assert_send_sync::<ElfParseError>();
    }
}
