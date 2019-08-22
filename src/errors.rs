use err_derive::Error;
use std::io;

#[derive(Debug, Error)]
pub enum DiskError {
    #[error(
        display = "invalid disk length (expected: 0x{:X}, got {:X}",
        expected,
        actual
    )]
    InvalidDiskLength { expected: usize, actual: usize },

    #[error(display = "error occurred while reading data: {}", 0)]
    IoError(io::Error),

    #[error(
        display = "filesystem has invalid magic. expected 0x58544146, got 0x{:X}",
        0
    )]
    InvalidFilesystemMagic { magic: u32, offset: u64 },
}

impl From<io::Error> for DiskError {
    fn from(error: io::Error) -> Self {
        DiskError::IoError(error)
    }
}
