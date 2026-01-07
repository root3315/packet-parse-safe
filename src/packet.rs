use crate::error::{PacketError, PacketResult};

/// Magic number identifying valid packets
pub const PACKET_MAGIC: u32 = 0x5041434B; // "PACK" in ASCII

/// Current supported protocol version
pub const PROTOCOL_VERSION: u8 = 1;

/// Maximum allowed payload size (64 KB)
pub const MAX_PAYLOAD_SIZE: usize = 65536;

/// Minimum header size in bytes
pub const HEADER_SIZE: usize = 16;

/// Packet types supported by the protocol
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PacketType {
    Data = 0x01,
    Acknowledgment = 0x02,
    Control = 0x03,
    Heartbeat = 0x04,
    Error = 0x05,
}

impl PacketType {
    /// Convert from raw byte to PacketType
    pub fn from_u8(value: u8) -> PacketResult<Self> {
        match value {
            0x01 => Ok(PacketType::Data),
            0x02 => Ok(PacketType::Acknowledgment),
            0x03 => Ok(PacketType::Control),
            0x04 => Ok(PacketType::Heartbeat),
            0x05 => Ok(PacketType::Error),
            _ => Err(PacketError::UnknownPacketType(value)),
        }
    }

    /// Get the string representation of the packet type
    pub fn as_str(&self) -> &'static str {
        match self {
            PacketType::Data => "DATA",
            PacketType::Acknowledgment => "ACK",
            PacketType::Control => "CTRL",
            PacketType::Heartbeat => "HEARTBEAT",
            PacketType::Error => "ERROR",
        }
    }
}

/// Packet flags for additional metadata
#[derive(Debug, Clone, Copy, Default)]
pub struct PacketFlags {
    pub encrypted: bool,
    pub compressed: bool,
    pub fragmented: bool,
    pub last_fragment: bool,
    pub priority: u8,
}

impl PacketFlags {
    /// Parse flags from a u8 value
    pub fn from_u8(value: u8) -> Self {
        PacketFlags {
            encrypted: (value & 0x01) != 0,
            compressed: (value & 0x02) != 0,
            fragmented: (value & 0x04) != 0,
            last_fragment: (value & 0x08) != 0,
            priority: (value >> 4) & 0x0F,
        }
    }

    /// Convert flags to u8
    pub fn to_u8(&self) -> u8 {
        let mut value: u8 = 0;
        if self.encrypted {
            value |= 0x01;
        }
        if self.compressed {
            value |= 0x02;
        }
        if self.fragmented {
            value |= 0x04;
        }
        if self.last_fragment {
            value |= 0x08;
        }
        value |= (self.priority & 0x0F) << 4;
        value
    }
}

/// Packet header structure
#[derive(Debug, Clone)]
pub struct PacketHeader {
    pub magic: u32,
    pub version: u8,
    pub packet_type: PacketType,
    pub flags: PacketFlags,
    pub sequence_number: u32,
    pub payload_length: u32,
    pub checksum: u16,
}

impl PacketHeader {
    /// Create a new packet header
    pub fn new(
        packet_type: PacketType,
        sequence_number: u32,
        payload_length: u32,
    ) -> Self {
        PacketHeader {
            magic: PACKET_MAGIC,
            version: PROTOCOL_VERSION,
            packet_type,
            flags: PacketFlags::default(),
            sequence_number,
            payload_length,
            checksum: 0,
        }
    }

    /// Validate the header fields
    pub fn validate(&self) -> PacketResult<()> {
        if self.magic != PACKET_MAGIC {
            return Err(PacketError::InvalidMagic {
                expected: PACKET_MAGIC,
                found: self.magic,
            });
        }

        if self.version > PROTOCOL_VERSION {
            return Err(PacketError::UnsupportedVersion {
                version: self.version,
                max_supported: PROTOCOL_VERSION,
            });
        }

        if self.payload_length as usize > MAX_PAYLOAD_SIZE {
            return Err(PacketError::InvalidFieldValue {
                field: "payload_length",
                value: self.payload_length,
            });
        }

        Ok(())
    }

    /// Calculate the checksum for this header
    pub fn calculate_checksum(&self) -> u16 {
        let mut sum: u32 = 0;
        sum += (self.magic >> 16) as u32;
        sum += (self.magic & 0xFFFF) as u32;
        sum += self.version as u32;
        sum += self.packet_type as u32;
        sum += self.flags.to_u8() as u32;
        sum += (self.sequence_number >> 16) as u32;
        sum += (self.sequence_number & 0xFFFF) as u32;
        sum += (self.payload_length >> 16) as u32;
        sum += (self.payload_length & 0xFFFF) as u32;
        
        // Fold 32-bit sum to 16-bit
        while sum > 0xFFFF {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        !sum as u16
    }

    /// Verify the checksum
    pub fn verify_checksum(&self) -> bool {
        self.checksum == self.calculate_checksum()
    }
}

/// Complete packet structure with header and payload
#[derive(Debug, Clone)]
pub struct Packet {
    pub header: PacketHeader,
    pub payload: Vec<u8>,
}

impl Packet {
    /// Create a new packet with the given type and payload
    pub fn new(packet_type: PacketType, payload: Vec<u8>) -> Self {
        let mut header = PacketHeader::new(
            packet_type,
            0,
            payload.len() as u32,
        );
        header.checksum = header.calculate_checksum();
        
        Packet { header, payload }
    }

    /// Create a packet with custom sequence number
    pub fn with_sequence(
        packet_type: PacketType,
        payload: Vec<u8>,
        sequence_number: u32,
    ) -> Self {
        let mut header = PacketHeader::new(
            packet_type,
            sequence_number,
            payload.len() as u32,
        );
        header.checksum = header.calculate_checksum();
        
        Packet { header, payload }
    }

    /// Get the total size of the packet in bytes
    pub fn total_size(&self) -> usize {
        HEADER_SIZE + self.payload.len()
    }

    /// Validate the entire packet
    pub fn validate(&self) -> PacketResult<()> {
        self.header.validate()?;
        
        if self.header.payload_length as usize != self.payload.len() {
            return Err(PacketError::LengthMismatch {
                declared: self.header.payload_length as usize,
                actual: self.payload.len(),
            });
        }

        if !self.header.verify_checksum() {
            return Err(PacketError::ChecksumMismatch {
                expected: self.header.checksum,
                found: self.header.calculate_checksum(),
            });
        }

        Ok(())
    }

    /// Serialize the packet to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::with_capacity(self.total_size());
        
        // Write magic (4 bytes, big-endian)
        buffer.extend_from_slice(&self.header.magic.to_be_bytes());
        
        // Write version (1 byte)
        buffer.push(self.header.version);
        
        // Write packet type (1 byte)
        buffer.push(self.header.packet_type as u8);
        
        // Write flags (1 byte)
        buffer.push(self.header.flags.to_u8());
        
        // Write reserved byte
        buffer.push(0x00);
        
        // Write sequence number (4 bytes, big-endian)
        buffer.extend_from_slice(&self.header.sequence_number.to_be_bytes());
        
        // Write payload length (2 bytes, big-endian)
        buffer.extend_from_slice(&(self.header.payload_length as u16).to_be_bytes());
        
        // Write checksum (2 bytes, big-endian)
        buffer.extend_from_slice(&self.header.checksum.to_be_bytes());
        
        // Write payload
        buffer.extend_from_slice(&self.payload);
        
        buffer
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_packet_type_from_u8() {
        assert_eq!(PacketType::from_u8(0x01).unwrap(), PacketType::Data);
        assert_eq!(PacketType::from_u8(0x02).unwrap(), PacketType::Acknowledgment);
        assert!(PacketType::from_u8(0xFF).is_err());
    }

    #[test]
    fn test_packet_flags_roundtrip() {
        let flags = PacketFlags {
            encrypted: true,
            compressed: false,
            fragmented: true,
            last_fragment: false,
            priority: 5,
        };
        let encoded = flags.to_u8();
        let decoded = PacketFlags::from_u8(encoded);
        
        assert_eq!(flags.encrypted, decoded.encrypted);
        assert_eq!(flags.compressed, decoded.compressed);
        assert_eq!(flags.fragmented, decoded.fragmented);
        assert_eq!(flags.last_fragment, decoded.last_fragment);
        assert_eq!(flags.priority, decoded.priority);
    }

    #[test]
    fn test_packet_creation() {
        let payload = vec![0x01, 0x02, 0x03, 0x04];
        let packet = Packet::new(PacketType::Data, payload.clone());
        
        assert_eq!(packet.header.magic, PACKET_MAGIC);
        assert_eq!(packet.header.version, PROTOCOL_VERSION);
        assert_eq!(packet.header.packet_type, PacketType::Data);
        assert_eq!(packet.payload, payload);
    }

    #[test]
    fn test_packet_validation() {
        let payload = vec![0x01, 0x02, 0x03, 0x04];
        let packet = Packet::new(PacketType::Data, payload);
        
        assert!(packet.validate().is_ok());
    }

    #[test]
    fn test_packet_serialization() {
        let payload = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let packet = Packet::with_sequence(PacketType::Control, payload, 42);
        
        let bytes = packet.to_bytes();
        assert_eq!(bytes.len(), packet.total_size());
        assert_eq!(bytes.len(), HEADER_SIZE + 4);
    }

    #[test]
    fn test_checksum_calculation() {
        let header = PacketHeader::new(PacketType::Data, 1, 100);
        let checksum = header.calculate_checksum();
        assert_ne!(checksum, 0);
        
        let mut header_with_checksum = header.clone();
        header_with_checksum.checksum = checksum;
        assert!(header_with_checksum.verify_checksum());
    }
}
