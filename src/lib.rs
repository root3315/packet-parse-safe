//! # packet-parse-safe
//!
//! A memory-safe binary packet parser written in Rust.
//!
//! This library provides a robust, type-safe interface for parsing binary network packets
//! with comprehensive error handling and validation. It leverages Rust's ownership system
//! to ensure memory safety without garbage collection.
//!
//! ## Features
//!
//! - **Memory Safety**: No raw pointers or unsafe blocks in the core parsing logic
//! - **Type Safety**: Strong typing for packet types and error conditions
//! - **Validation**: Comprehensive header and checksum validation
//! - **Error Handling**: Detailed error types for all failure modes
//! - **Statistics**: Built-in parsing statistics tracking
//!
//! ## Example
//!
//! ```rust
//! use packet_parse_safe::{Packet, PacketParser, PacketType};
//!
//! // Create a packet
//! let packet = Packet::new(PacketType::Data, vec![0x01, 0x02, 0x03]);
//!
//! // Serialize to bytes
//! let bytes = packet.to_bytes();
//!
//! // Parse the packet back
//! let mut parser = PacketParser::new();
//! let parsed = parser.parse(&bytes).unwrap();
//!
//! assert_eq!(parsed.header.packet_type, PacketType::Data);
//! ```

pub mod error;
pub mod packet;
pub mod parser;

pub use error::{PacketError, PacketResult};
pub use packet::{Packet, PacketFlags, PacketHeader, PacketType};
pub use parser::{PacketParser, ParserConfig, ParserConfigBuilder, ParseStats};

/// Library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Protocol magic number for quick reference
pub const MAGIC: u32 = packet::PACKET_MAGIC;

/// Current protocol version
pub const VERSION_NUM: u8 = packet::PROTOCOL_VERSION;

/// Header size in bytes
pub const HEADER_SIZE: usize = packet::HEADER_SIZE;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_library_constants() {
        assert_eq!(MAGIC, 0x5041434B);
        assert_eq!(VERSION_NUM, 1);
        assert_eq!(HEADER_SIZE, 16);
    }

    #[test]
    fn test_end_to_end() {
        let packet = Packet::new(PacketType::Control, vec![0xCA, 0xFE]);
        let bytes = packet.to_bytes();
        
        let mut parser = PacketParser::new();
        let parsed = parser.parse(&bytes).unwrap();
        
        assert_eq!(parsed.header.packet_type, PacketType::Control);
        assert_eq!(parsed.payload, vec![0xCA, 0xFE]);
    }
}
