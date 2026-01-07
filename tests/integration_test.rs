use std::fs::File;
use std::io::Write;

use packet_parse_safe::{
    Packet, PacketError, PacketParser, PacketType, ParserConfigBuilder, HEADER_SIZE,
};

/// Create a temporary file with packet data for testing
fn create_temp_packet_file(packets: &[Packet]) -> tempfile::NamedTempFile {
    let temp_file = tempfile::NamedTempFile::new().expect("Failed to create temp file");
    let mut file = temp_file.reopen().expect("Failed to reopen temp file");
    
    for packet in packets {
        file.write_all(&packet.to_bytes()).expect("Failed to write packet");
    }
    file.flush().expect("Failed to flush");
    
    temp_file
}

#[test]
fn test_roundtrip_single_packet() {
    let original_payload = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
    let original_packet = Packet::with_sequence(PacketType::Data, original_payload.clone(), 42);
    
    let bytes = original_packet.to_bytes();
    
    let mut parser = PacketParser::new();
    let parsed = parser.parse(&bytes).expect("Failed to parse packet");
    
    assert_eq!(parsed.header.magic, original_packet.header.magic);
    assert_eq!(parsed.header.version, original_packet.header.version);
    assert_eq!(parsed.header.packet_type, original_packet.header.packet_type);
    assert_eq!(parsed.header.sequence_number, original_packet.header.sequence_number);
    assert_eq!(parsed.payload, original_payload);
}

#[test]
fn test_roundtrip_multiple_packets() {
    let packets = vec![
        Packet::with_sequence(PacketType::Data, vec![0x01, 0x02], 1),
        Packet::with_sequence(PacketType::Acknowledgment, vec![0x03], 2),
        Packet::with_sequence(PacketType::Control, vec![0x04, 0x05, 0x06], 3),
        Packet::with_sequence(PacketType::Heartbeat, vec![], 4),
        Packet::with_sequence(PacketType::Error, vec![0xFF], 5),
    ];
    
    let mut buffer = Vec::new();
    for packet in &packets {
        buffer.extend_from_slice(&packet.to_bytes());
    }
    
    let mut parser = PacketParser::new();
    let parsed_packets = parser.parse_all(&buffer).expect("Failed to parse packets");
    
    assert_eq!(parsed_packets.len(), packets.len());
    
    for (original, parsed) in packets.iter().zip(parsed_packets.iter()) {
        assert_eq!(parsed.header.packet_type, original.header.packet_type);
        assert_eq!(parsed.header.sequence_number, original.header.sequence_number);
        assert_eq!(parsed.payload, original.payload);
    }
}

#[test]
fn test_parse_from_file() {
    let packets = vec![
        Packet::new(PacketType::Data, vec![0xAA, 0xBB]),
        Packet::new(PacketType::Control, vec![0xCC, 0xDD, 0xEE]),
    ];
    
    let temp_file = create_temp_packet_file(&packets);
    let path = temp_file.path();
    
    let mut parser = PacketParser::new();
    let parsed = parser.parse_file(path).expect("Failed to parse file");
    
    assert_eq!(parsed.len(), 2);
    assert_eq!(parsed[0].header.packet_type, PacketType::Data);
    assert_eq!(parsed[1].header.packet_type, PacketType::Control);
}

#[test]
fn test_parser_with_custom_config() {
    let config = ParserConfigBuilder::new()
        .with_checksum_verification(false)
        .with_header_validation(false)
        .with_max_payload_size(1024)
        .build();
    
    let packet = Packet::new(PacketType::Data, vec![0x01, 0x02, 0x03]);
    let bytes = packet.to_bytes();
    
    let mut parser = PacketParser::with_config(config);
    let result = parser.parse(&bytes);
    
    assert!(result.is_ok());
}

#[test]
fn test_invalid_magic_number() {
    let mut buffer = vec![0x00, 0x00, 0x00, 0x00];
    buffer.resize(HEADER_SIZE, 0);
    
    let mut parser = PacketParser::new();
    let result = parser.parse(&buffer);
    
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), PacketError::InvalidMagic { .. }));
}

#[test]
fn test_unsupported_version() {
    let mut buffer = vec![0x50, 0x41, 0x43, 0x4B]; // Magic
    buffer.push(99); // Version 99 (unsupported)
    buffer.push(0x01); // Packet type
    buffer.push(0x00); // Flags
    buffer.push(0x00); // Reserved
    buffer.extend_from_slice(&0u32.to_be_bytes()); // Sequence number
    buffer.extend_from_slice(&0u16.to_be_bytes()); // Payload length
    buffer.extend_from_slice(&0u16.to_be_bytes()); // Checksum
    
    let mut parser = PacketParser::new();
    let result = parser.parse(&buffer);
    
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), PacketError::UnsupportedVersion { .. }));
}

#[test]
fn test_unknown_packet_type() {
    let mut buffer = vec![0x50, 0x41, 0x43, 0x4B]; // Magic
    buffer.push(1); // Version
    buffer.push(0xFF); // Unknown packet type
    buffer.push(0x00); // Flags
    buffer.push(0x00); // Reserved
    buffer.extend_from_slice(&0u32.to_be_bytes()); // Sequence number
    buffer.extend_from_slice(&0u16.to_be_bytes()); // Payload length
    buffer.extend_from_slice(&0u16.to_be_bytes()); // Checksum
    
    let mut parser = PacketParser::new();
    let result = parser.parse(&buffer);
    
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), PacketError::UnknownPacketType(_)));
}

#[test]
fn test_truncated_packet() {
    let packet = Packet::new(PacketType::Data, vec![0x01, 0x02, 0x03, 0x04]);
    let bytes = packet.to_bytes();
    
    // Truncate the buffer to simulate incomplete data
    let truncated = &bytes[..HEADER_SIZE + 2];
    
    let mut parser = PacketParser::new();
    let result = parser.parse(truncated);
    
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), PacketError::TruncatedData { .. }));
}

#[test]
fn test_checksum_verification() {
    let packet = Packet::new(PacketType::Data, vec![0x01, 0x02, 0x03]);
    let mut bytes = packet.to_bytes();
    
    // Corrupt the checksum
    let checksum_offset = HEADER_SIZE - 2;
    bytes[checksum_offset] = 0x00;
    bytes[checksum_offset + 1] = 0x00;
    
    let mut parser = PacketParser::new();
    let result = parser.parse(&bytes);
    
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), PacketError::ChecksumMismatch { .. }));
}

#[test]
fn test_payload_size_limit() {
    let config = ParserConfigBuilder::new()
        .with_max_payload_size(4)
        .build();
    
    let packet = Packet::new(PacketType::Data, vec![0x01, 0x02, 0x03, 0x04, 0x05]);
    let bytes = packet.to_bytes();
    
    let mut parser = PacketParser::with_config(config);
    let result = parser.parse(&bytes);
    
    assert!(result.is_err());
}

#[test]
fn test_statistics_tracking() {
    let packets = vec![
        Packet::new(PacketType::Data, vec![0x01]),
        Packet::new(PacketType::Data, vec![0x02]),
        Packet::new(PacketType::Acknowledgment, vec![]),
        Packet::new(PacketType::Heartbeat, vec![]),
    ];
    
    let mut buffer = Vec::new();
    for packet in &packets {
        buffer.extend_from_slice(&packet.to_bytes());
    }
    
    let mut parser = PacketParser::new();
    let _ = parser.parse_all(&buffer);
    
    let stats = parser.stats();
    assert_eq!(stats.total_packets, 4);
    assert_eq!(stats.data_packets, 2);
    assert_eq!(stats.ack_packets, 1);
    assert_eq!(stats.heartbeat_packets, 1);
    assert_eq!(stats.parse_errors, 0);
}

#[test]
fn test_empty_payload_packets() {
    let packet = Packet::new(PacketType::Heartbeat, vec![]);
    let bytes = packet.to_bytes();
    
    let mut parser = PacketParser::new();
    let parsed = parser.parse(&bytes).expect("Failed to parse empty payload packet");
    
    assert_eq!(parsed.header.packet_type, PacketType::Heartbeat);
    assert!(parsed.payload.is_empty());
    assert_eq!(parsed.total_size(), HEADER_SIZE);
}

#[test]
fn test_large_payload() {
    let payload: Vec<u8> = (0..1000).map(|i| (i % 256) as u8).collect();
    let packet = Packet::new(PacketType::Data, payload.clone());
    let bytes = packet.to_bytes();
    
    let mut parser = PacketParser::new();
    let parsed = parser.parse(&bytes).expect("Failed to parse large payload packet");
    
    assert_eq!(parsed.payload.len(), 1000);
    assert_eq!(parsed.payload, payload);
}

#[test]
fn test_packet_flags_encoding() {
    use packet_parse_safe::PacketFlags;
    
    let flags = PacketFlags {
        encrypted: true,
        compressed: true,
        fragmented: false,
        last_fragment: true,
        priority: 7,
    };
    
    let encoded = flags.to_u8();
    let decoded = PacketFlags::from_u8(encoded);
    
    assert_eq!(decoded.encrypted, flags.encrypted);
    assert_eq!(decoded.compressed, flags.compressed);
    assert_eq!(decoded.fragmented, flags.fragmented);
    assert_eq!(decoded.last_fragment, flags.last_fragment);
    assert_eq!(decoded.priority, flags.priority);
}

#[test]
fn test_sequential_sequence_numbers() {
    let packets: Vec<Packet> = (0..10)
        .map(|seq| Packet::with_sequence(PacketType::Data, vec![seq as u8], seq))
        .collect();
    
    let mut buffer = Vec::new();
    for packet in &packets {
        buffer.extend_from_slice(&packet.to_bytes());
    }
    
    let mut parser = PacketParser::new();
    let parsed = parser.parse_all(&buffer).expect("Failed to parse sequence");
    
    assert_eq!(parsed.len(), 10);
    for (i, packet) in parsed.iter().enumerate() {
        assert_eq!(packet.header.sequence_number, i as u32);
    }
}

#[test]
fn test_write_and_read_packets() {
    let packets = vec![
        Packet::new(PacketType::Data, vec![0x11, 0x22]),
        Packet::new(PacketType::Control, vec![0x33, 0x44, 0x55]),
    ];
    
    let temp_file = tempfile::NamedTempFile::new().expect("Failed to create temp file");
    let path = temp_file.path().to_path_buf();
    
    let parser = PacketParser::new();
    parser.write_packets(&packets, &path).expect("Failed to write packets");
    
    let mut read_parser = PacketParser::new();
    let read_packets = read_parser.parse_file(&path).expect("Failed to read packets");
    
    assert_eq!(read_packets.len(), packets.len());
    for (original, read) in packets.iter().zip(read_packets.iter()) {
        assert_eq!(original.header.packet_type, read.header.packet_type);
        assert_eq!(original.payload, read.payload);
    }
}
