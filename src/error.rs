use std::fmt;
use std::io;

/// Error types that can occur during packet parsing
#[derive(Debug)]
pub enum PacketError {
    /// The input buffer is too small to contain a valid packet header
    BufferTooSmall { expected: usize, actual: usize },
    
    /// Invalid magic number in packet header
    InvalidMagic { expected: u32, found: u32 },
    
    /// Packet length field is inconsistent with actual data
    LengthMismatch { declared: usize, actual: usize },
    
    /// Unknown packet type identifier
    UnknownPacketType(u8),
    
    /// Invalid checksum detected
    ChecksumMismatch { expected: u16, found: u16 },
    
    /// Packet version is not supported
    UnsupportedVersion { version: u8, max_supported: u8 },
    
    /// Invalid field value in packet header
    InvalidFieldValue { field: &'static str, value: u32 },
    
    /// Truncated packet data
    TruncatedData { position: usize, required: usize },
    
    /// IO error during file operations
    IoError(io::Error),
    
    /// End of stream reached unexpectedly
    EndOfStream,
}

impl fmt::Display for PacketError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PacketError::BufferTooSmall { expected, actual } => {
                write!(f, "Buffer too small: expected {} bytes, got {}", expected, actual)
            }
            PacketError::InvalidMagic { expected, found } => {
                write!(f, "Invalid magic number: expected 0x{:08X}, found 0x{:08X}", expected, found)
            }
            PacketError::LengthMismatch { declared, actual } => {
                write!(f, "Length mismatch: declared {} bytes, actual {} bytes", declared, actual)
            }
            PacketError::UnknownPacketType(ty) => {
                write!(f, "Unknown packet type: 0x{:02X}", ty)
            }
            PacketError::ChecksumMismatch { expected, found } => {
                write!(f, "Checksum mismatch: expected 0x{:04X}, found 0x{:04X}", expected, found)
            }
            PacketError::UnsupportedVersion { version, max_supported } => {
                write!(f, "Unsupported version: {} (max supported: {})", version, max_supported)
            }
            PacketError::InvalidFieldValue { field, value } => {
                write!(f, "Invalid value for field '{}': {}", field, value)
            }
            PacketError::TruncatedData { position, required } => {
                write!(f, "Truncated data at position {}: required {} bytes", position, required)
            }
            PacketError::IoError(err) => {
                write!(f, "IO error: {}", err)
            }
            PacketError::EndOfStream => {
                write!(f, "End of stream reached unexpectedly")
            }
        }
    }
}

impl std::error::Error for PacketError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            PacketError::IoError(err) => Some(err),
            _ => None,
        }
    }
}

impl From<io::Error> for PacketError {
    fn from(err: io::Error) -> Self {
        PacketError::IoError(err)
    }
}

/// Result type alias for packet parsing operations
pub type PacketResult<T> = Result<T, PacketError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display_buffer_too_small() {
        let err = PacketError::BufferTooSmall { expected: 64, actual: 32 };
        assert!(err.to_string().contains("Buffer too small"));
        assert!(err.to_string().contains("64"));
        assert!(err.to_string().contains("32"));
    }

    #[test]
    fn test_error_display_invalid_magic() {
        let err = PacketError::InvalidMagic { expected: 0x12345678, found: 0x87654321 };
        assert!(err.to_string().contains("Invalid magic number"));
    }

    #[test]
    fn test_error_from_io_error() {
        let io_err = io::Error::new(io::ErrorKind::UnexpectedEof, "unexpected eof");
        let packet_err: PacketError = io_err.into();
        assert!(matches!(packet_err, PacketError::IoError(_)));
    }
}
