use std::fmt;
use std::io;
#[cfg(test)]
use std::path::Path;
use std::path::PathBuf;

#[derive(Debug)]
pub(crate) struct ElfParseError {
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

    #[cfg(test)]
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn into_io_error(self) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, self)
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
