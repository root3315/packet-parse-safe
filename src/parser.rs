use std::fs::File;
use std::io::{self, BufReader, Read, Write};
use std::path::Path;

use byteorder::{BigEndian, ReadBytesExt};

use crate::error::{PacketError, PacketResult};
use crate::packet::{Packet, PacketHeader, PacketType, HEADER_SIZE, PACKET_MAGIC, PROTOCOL_VERSION};

/// Parser configuration options
#[derive(Debug, Clone)]
pub struct ParserConfig {
    /// Whether to verify checksums
    pub verify_checksum: bool,
    /// Whether to validate packet headers
    pub validate_headers: bool,
    /// Maximum payload size to accept
    pub max_payload_size: usize,
}

impl Default for ParserConfig {
    fn default() -> Self {
        ParserConfig {
            verify_checksum: true,
            validate_headers: true,
            max_payload_size: 65536,
        }
    }
}

/// Statistics about parsed packets
#[derive(Debug, Default)]
pub struct ParseStats {
    pub total_packets: usize,
    pub data_packets: usize,
    pub ack_packets: usize,
    pub control_packets: usize,
    pub heartbeat_packets: usize,
    pub error_packets: usize,
    pub total_bytes: usize,
    pub parse_errors: usize,
}

impl ParseStats {
    /// Record a successfully parsed packet
    pub fn record_packet(&mut self, packet_type: PacketType, payload_size: usize) {
        self.total_packets += 1;
        self.total_bytes += HEADER_SIZE + payload_size;
        
        match packet_type {
            PacketType::Data => self.data_packets += 1,
            PacketType::Acknowledgment => self.ack_packets += 1,
            PacketType::Control => self.control_packets += 1,
            PacketType::Heartbeat => self.heartbeat_packets += 1,
            PacketType::Error => self.error_packets += 1,
        }
    }

    /// Record a parse error
    pub fn record_error(&mut self) {
        self.parse_errors += 1;
    }
}

/// Binary packet parser for memory-safe parsing
pub struct PacketParser {
    config: ParserConfig,
    stats: ParseStats,
}

impl PacketParser {
    /// Create a new parser with default configuration
    pub fn new() -> Self {
        PacketParser {
            config: ParserConfig::default(),
            stats: ParseStats::default(),
        }
    }

    /// Create a new parser with custom configuration
    pub fn with_config(config: ParserConfig) -> Self {
        PacketParser {
            config,
            stats: ParseStats::default(),
        }
    }

    /// Get parsing statistics
    pub fn stats(&self) -> &ParseStats {
        &self.stats
    }

    /// Reset parsing statistics
    pub fn reset_stats(&mut self) {
        self.stats = ParseStats::default();
    }

    /// Parse a single packet from a byte buffer
    pub fn parse(&mut self, buffer: &[u8]) -> PacketResult<Packet> {
        if buffer.len() < HEADER_SIZE {
            self.stats.record_error();
            return Err(PacketError::BufferTooSmall {
                expected: HEADER_SIZE,
                actual: buffer.len(),
            });
        }

        let header = self.parse_header(buffer)?;
        
        let payload_len = header.payload_length as usize;
        if payload_len > self.config.max_payload_size {
            self.stats.record_error();
            return Err(PacketError::InvalidFieldValue {
                field: "payload_length",
                value: payload_len as u32,
            });
        }

        let expected_total = HEADER_SIZE + payload_len;
        if buffer.len() < expected_total {
            self.stats.record_error();
            return Err(PacketError::TruncatedData {
                position: buffer.len(),
                required: expected_total,
            });
        }

        let payload = buffer[HEADER_SIZE..expected_total].to_vec();
        let packet = Packet { header, payload };

        if self.config.verify_checksum && !packet.header.verify_checksum() {
            self.stats.record_error();
            return Err(PacketError::ChecksumMismatch {
                expected: packet.header.checksum,
                found: packet.header.calculate_checksum(),
            });
        }

        if self.config.validate_headers {
            packet.validate()?;
        }

        self.stats.record_packet(packet.header.packet_type, packet.payload.len());
        Ok(packet)
    }

    /// Parse packet header from buffer
    fn parse_header(&self, buffer: &[u8]) -> PacketResult<PacketHeader> {
        use crate::packet::PacketFlags;

        let magic = u32::from_be_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]);
        
        if magic != PACKET_MAGIC {
            self.stats.record_error();
            return Err(PacketError::InvalidMagic {
                expected: PACKET_MAGIC,
                found: magic,
            });
        }

        let version = buffer[4];
        if version > PROTOCOL_VERSION {
            self.stats.record_error();
            return Err(PacketError::UnsupportedVersion {
                version,
                max_supported: PROTOCOL_VERSION,
            });
        }

        let packet_type = PacketType::from_u8(buffer[5])?;
        let flags = PacketFlags::from_u8(buffer[6]);
        
        let sequence_bytes = [buffer[8], buffer[9], buffer[10], buffer[11]];
        let sequence_number = u32::from_be_bytes(sequence_bytes);
        
        let length_bytes = [buffer[12], buffer[13]];
        let payload_length = u16::from_be_bytes(length_bytes) as u32;
        
        let checksum_bytes = [buffer[14], buffer[15]];
        let checksum = u16::from_be_bytes(checksum_bytes);

        Ok(PacketHeader {
            magic,
            version,
            packet_type,
            flags,
            sequence_number,
            payload_length,
            checksum,
        })
    }

    /// Parse all packets from a byte buffer
    pub fn parse_all(&mut self, buffer: &[u8]) -> PacketResult<Vec<Packet>> {
        let mut packets = Vec::new();
        let mut offset = 0;

        while offset < buffer.len() {
            let remaining = &buffer[offset..];
            
            if remaining.len() < HEADER_SIZE {
                break;
            }

            let payload_len = u16::from_be_bytes([remaining[12], remaining[13]]) as usize;
            let packet_size = HEADER_SIZE + payload_len;

            if remaining.len() < packet_size {
                break;
            }

            let packet = self.parse(&remaining[..packet_size])?;
            packets.push(packet);
            offset += packet_size;
        }

        Ok(packets)
    }

    /// Parse packets from a file
    pub fn parse_file<P: AsRef<Path>>(&mut self, path: P) -> PacketResult<Vec<Packet>> {
        let file = File::open(path.as_ref())?;
        let mut reader = BufReader::new(file);
        let mut buffer = Vec::new();
        reader.read_to_end(&mut buffer)?;
        self.parse_all(&buffer)
    }

    /// Write a packet to a file
    pub fn write_packet<P: AsRef<Path>>(&self, packet: &Packet, path: P) -> io::Result<()> {
        let mut file = File::create(path.as_ref())?;
        file.write_all(&packet.to_bytes())?;
        file.flush()?;
        Ok(())
    }

    /// Write multiple packets to a file
    pub fn write_packets<P: AsRef<Path>>(&self, packets: &[Packet], path: P) -> io::Result<()> {
        let mut file = File::create(path.as_ref())?;
        for packet in packets {
            file.write_all(&packet.to_bytes())?;
        }
        file.flush()?;
        Ok(())
    }
}

impl Default for PacketParser {
    fn default() -> Self {
        Self::new()
    }
}

/// Builder for creating parser configurations
pub struct ParserConfigBuilder {
    config: ParserConfig,
}

impl ParserConfigBuilder {
    pub fn new() -> Self {
        ParserConfigBuilder {
            config: ParserConfig::default(),
        }
    }

    pub fn with_checksum_verification(mut self, verify: bool) -> Self {
        self.config.verify_checksum = verify;
        self
    }

    pub fn with_header_validation(mut self, validate: bool) -> Self {
        self.config.validate_headers = validate;
        self
    }

    pub fn with_max_payload_size(mut self, size: usize) -> Self {
        self.config.max_payload_size = size;
        self
    }

    pub fn build(self) -> ParserConfig {
        self.config
    }
}

impl Default for ParserConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::Packet;

    #[test]
    fn test_parser_creation() {
        let parser = PacketParser::new();
        assert_eq!(parser.stats().total_packets, 0);
    }

    #[test]
    fn test_parser_config_builder() {
        let config = ParserConfigBuilder::new()
            .with_checksum_verification(false)
            .with_header_validation(true)
            .with_max_payload_size(1024)
            .build();
        
        assert!(!config.verify_checksum);
        assert!(config.validate_headers);
        assert_eq!(config.max_payload_size, 1024);
    }

    #[test]
    fn test_parse_valid_packet() {
        let payload = vec![0x01, 0x02, 0x03, 0x04];
        let packet = Packet::new(PacketType::Data, payload);
        let bytes = packet.to_bytes();

        let mut parser = PacketParser::new();
        let parsed = parser.parse(&bytes).unwrap();

        assert_eq!(parsed.header.packet_type, PacketType::Data);
        assert_eq!(parsed.payload, vec![0x01, 0x02, 0x03, 0x04]);
        assert_eq!(parser.stats().total_packets, 1);
    }

    #[test]
    fn test_parse_invalid_magic() {
        let mut buffer = vec![0x00, 0x00, 0x00, 0x00];
        buffer.resize(HEADER_SIZE, 0);

        let mut parser = PacketParser::new();
        let result = parser.parse(&buffer);
        
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), PacketError::InvalidMagic { .. }));
    }

    #[test]
    fn test_parse_buffer_too_small() {
        let buffer = vec![0x50, 0x41, 0x43, 0x4B];

        let mut parser = PacketParser::new();
        let result = parser.parse(&buffer);
        
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), PacketError::BufferTooSmall { .. }));
    }

    #[test]
    fn test_parse_all_packets() {
        let packet1 = Packet::new(PacketType::Data, vec![0x01, 0x02]);
        let packet2 = Packet::new(PacketType::Ack, vec![0x03, 0x04]);
        
        let mut buffer = Vec::new();
        buffer.extend_from_slice(&packet1.to_bytes());
        buffer.extend_from_slice(&packet2.to_bytes());

        let mut parser = PacketParser::new();
        let packets = parser.parse_all(&buffer).unwrap();

        assert_eq!(packets.len(), 2);
        assert_eq!(packets[0].header.packet_type, PacketType::Data);
        assert_eq!(packets[1].header.packet_type, PacketType::Acknowledgment);
    }

    #[test]
    fn test_parse_stats() {
        let packet = Packet::new(PacketType::Heartbeat, vec![]);
        let bytes = packet.to_bytes();

        let mut parser = PacketParser::new();
        parser.parse(&bytes).unwrap();

        let stats = parser.stats();
        assert_eq!(stats.total_packets, 1);
        assert_eq!(stats.heartbeat_packets, 1);
        assert_eq!(stats.total_bytes, HEADER_SIZE);
    }
}
