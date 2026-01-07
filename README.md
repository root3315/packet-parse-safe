# packet-parse-safe

A memory-safe binary packet parser written in Rust.

## Overview

`packet-parse-safe` is a robust, type-safe library for parsing binary network packets. It leverages Rust's ownership system and type system to ensure memory safety without garbage collection, while providing comprehensive error handling and validation.

## Features

- **Memory Safety**: No raw pointers or unsafe blocks in the core parsing logic
- **Type Safety**: Strong typing for packet types, flags, and error conditions
- **Validation**: Comprehensive header and checksum validation
- **Error Handling**: Detailed error types for all failure modes
- **Statistics**: Built-in parsing statistics tracking
- **Configurable**: Flexible parser configuration via builder pattern
- **File I/O**: Direct parsing from and writing to files

## Installation

### From Source

```bash
git clone https://github.com/example/packet-parse-safe.git
cd packet-parse-safe
cargo build --release
```

The binary will be available at `target/release/packet-parse-safe`.

### As a Library

Add this to your `Cargo.toml`:

```toml
[dependencies]
packet-parse-safe = "0.1.0"
```

## Usage

### Command Line Interface

```bash
# Parse packets from a file
packet-parse-safe -p input.bin

# Generate sample packets
packet-parse-safe -g -o packets.bin

# Validate packets
packet-parse-safe --validate -i data.bin

# Show parsing statistics
packet-parse-safe --stats -i data.bin

# Verbose output
packet-parse-safe -p input.bin --verbose

# Skip checksum verification
packet-parse-safe -p input.bin --no-checksum
```

### Command Line Options

| Option | Description |
|--------|-------------|
| `-p, --parse` | Parse packets from input file (default mode) |
| `-g, --generate` | Generate sample packets to output file |
| `--validate` | Validate packets without full parsing |
| `--stats` | Show parsing statistics |
| `-i, --input FILE` | Input file path |
| `-o, --output FILE` | Output file path |
| `--verbose` | Enable verbose output |
| `--no-checksum` | Skip checksum verification |
| `-h, --help` | Print help information |
| `-v, --version` | Print version information |

### Library Usage

#### Basic Parsing

```rust
use packet_parse_safe::{Packet, PacketParser, PacketType};

// Create a packet
let packet = Packet::new(PacketType::Data, vec![0x01, 0x02, 0x03]);

// Serialize to bytes
let bytes = packet.to_bytes();

// Parse the packet back
let mut parser = PacketParser::new();
let parsed = parser.parse(&bytes).unwrap();

assert_eq!(parsed.header.packet_type, PacketType::Data);
assert_eq!(parsed.payload, vec![0x01, 0x02, 0x03]);
```

#### Parsing Multiple Packets

```rust
use packet_parse_safe::{Packet, PacketParser, PacketType};

// Create multiple packets
let packets = vec![
    Packet::new(PacketType::Data, vec![0x01, 0x02]),
    Packet::new(PacketType::Acknowledgment, vec![0x03]),
    Packet::new(PacketType::Heartbeat, vec![]),
];

// Concatenate into a single buffer
let mut buffer = Vec::new();
for packet in &packets {
    buffer.extend_from_slice(&packet.to_bytes());
}

// Parse all packets
let mut parser = PacketParser::new();
let parsed = parser.parse_all(&buffer).unwrap();

assert_eq!(parsed.len(), 3);
```

#### Custom Configuration

```rust
use packet_parse_safe::{PacketParser, ParserConfigBuilder};

let config = ParserConfigBuilder::new()
    .with_checksum_verification(false)  // Skip checksum verification
    .with_header_validation(true)        // Validate headers
    .with_max_payload_size(4096)         // Set max payload size
    .build();

let parser = PacketParser::with_config(config);
```

#### File Operations

```rust
use packet_parse_safe::{Packet, PacketParser, PacketType};

// Parse from file
let mut parser = PacketParser::new();
let packets = parser.parse_file("data.bin").unwrap();

// Write to file
let packet = Packet::new(PacketType::Data, vec![0x01, 0x02]);
parser.write_packet(&packet, "output.bin").unwrap();

// Write multiple packets
parser.write_packets(&packets, "output.bin").unwrap();
```

#### Statistics

```rust
use packet_parse_safe::PacketParser;

let mut parser = PacketParser::new();
let _ = parser.parse_file("data.bin").unwrap();

let stats = parser.stats();
println!("Total packets: {}", stats.total_packets);
println!("Data packets: {}", stats.data_packets);
println!("ACK packets: {}", stats.ack_packets);
println!("Total bytes: {}", stats.total_bytes);
```

## How It Works

### Packet Format

The binary packet format consists of a 16-byte header followed by variable-length payload:

```
Offset  Size  Field           Description
------  ----  --------------  ------------------------------------
0       4     Magic           Magic number (0x5041434B = "PACK")
4       1     Version         Protocol version (currently 1)
5       1     Type            Packet type identifier
6       1     Flags           Packet flags (bitfield)
7       1     Reserved        Reserved for future use
8       4     Sequence        Sequence number (big-endian)
12      2     Payload Length  Payload size in bytes (big-endian)
14      2     Checksum        Header checksum (big-endian)
16      N     Payload         Variable-length payload data
```

### Packet Types

| Type | Value | Description |
|------|-------|-------------|
| DATA | 0x01 | Data packet with payload |
| ACK | 0x02 | Acknowledgment packet |
| CTRL | 0x03 | Control/command packet |
| HEARTBEAT | 0x04 | Keep-alive packet |
| ERROR | 0x05 | Error notification packet |

### Flags

The flags byte is a bitfield:

```
Bit  Name          Description
---  ----          -----------
0    Encrypted     Packet payload is encrypted
1    Compressed    Packet payload is compressed
2    Fragmented    Packet is part of a fragmented sequence
3    Last Fragment This is the last fragment
4-7  Priority      Priority level (0-15)
```

### Checksum Algorithm

The header checksum is calculated using a simple ones' complement sum:

1. Sum all 16-bit words in the header (excluding checksum field)
2. Fold any carry bits back into the sum
3. Take the ones' complement of the result

### Memory Safety Guarantees

- All buffer accesses are bounds-checked
- No raw pointer arithmetic
- No manual memory management
- Type-safe parsing with enum-based packet types
- Comprehensive error handling with detailed error types

## Project Structure

```
packet-parse-safe/
├── Cargo.toml           # Project configuration
├── Cargo.lock           # Dependency lock file
├── README.md            # This file
├── src/
│   ├── lib.rs           # Library root and public API
│   ├── main.rs          # CLI application entry point
│   ├── error.rs         # Error types and handling
│   ├── packet.rs        # Packet data structures
│   └── parser.rs        # Core parsing logic
└── tests/
    └── integration_test.rs  # Integration tests
```

## Testing

Run all tests:

```bash
cargo test
```

Run tests with output:

```bash
cargo test -- --nocapture
```

Run specific test:

```bash
cargo test test_roundtrip_single_packet
```

## License

MIT License - see LICENSE file for details.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests: `cargo test`
5. Submit a pull request
