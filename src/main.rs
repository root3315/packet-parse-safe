use std::env;
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::Path;
use std::process;

use packet_parse_safe::{
    Packet, PacketError, PacketParser, PacketType, ParserConfigBuilder,
};

/// Application version
const APP_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Default output file for generated packets
const DEFAULT_OUTPUT: &str = "packets.bin";

/// Command-line arguments structure
struct Args {
    mode: Mode,
    input_file: Option<String>,
    output_file: Option<String>,
    verbose: bool,
    no_checksum: bool,
}

/// Operation mode
enum Mode {
    Parse,
    Generate,
    Validate,
    Stats,
    Help,
    Version,
}

impl Args {
    fn parse(args: &[String]) -> Result<Self, String> {
        let mut mode = Mode::Help;
        let mut input_file = None;
        let mut output_file = None;
        let mut verbose = false;
        let mut no_checksum = false;

        let mut i = 1;
        while i < args.len() {
            match args[i].as_str() {
                "-h" | "--help" => {
                    mode = Mode::Help;
                }
                "-v" | "--version" => {
                    mode = Mode::Version;
                }
                "-p" | "--parse" => {
                    mode = Mode::Parse;
                }
                "-g" | "--generate" => {
                    mode = Mode::Generate;
                }
                "--validate" => {
                    mode = Mode::Validate;
                }
                "--stats" => {
                    mode = Mode::Stats;
                }
                "-i" | "--input" => {
                    if i + 1 < args.len() {
                        input_file = Some(args[i + 1].clone());
                        i += 1;
                    } else {
                        return Err("Missing argument for --input".to_string());
                    }
                }
                "-o" | "--output" => {
                    if i + 1 < args.len() {
                        output_file = Some(args[i + 1].clone());
                        i += 1;
                    } else {
                        return Err("Missing argument for --output".to_string());
                    }
                }
                "--verbose" => {
                    verbose = true;
                }
                "--no-checksum" => {
                    no_checksum = true;
                }
                arg if arg.starts_with('-') => {
                    return Err(format!("Unknown option: {}", arg));
                }
                arg => {
                    if input_file.is_none() {
                        input_file = Some(arg.to_string());
                    } else if output_file.is_none() {
                        output_file = Some(arg.to_string());
                    } else {
                        return Err(format!("Unexpected argument: {}", arg));
                    }
                }
            }
            i += 1;
        }

        Ok(Args {
            mode,
            input_file,
            output_file,
            verbose,
            no_checksum,
        })
    }
}

fn print_help() {
    println!("packet-parse-safe v{}", APP_VERSION);
    println!();
    println!("A memory-safe binary packet parser written in Rust");
    println!();
    println!("USAGE:");
    println!("    packet-parse-safe [OPTIONS] [INPUT] [OUTPUT]");
    println!();
    println!("MODES:");
    println!("    -p, --parse       Parse packets from input file (default)");
    println!("    -g, --generate    Generate sample packets to output file");
    println!("    --validate        Validate packets without full parsing");
    println!("    --stats           Show parsing statistics");
    println!();
    println!("OPTIONS:");
    println!("    -i, --input FILE  Input file path");
    println!("    -o, --output FILE Output file path");
    println!("    --verbose         Enable verbose output");
    println!("    --no-checksum     Skip checksum verification");
    println!("    -h, --help        Print help information");
    println!("    -v, --version     Print version information");
    println!();
    println!("EXAMPLES:");
    println!("    packet-parse-safe -p input.bin");
    println!("    packet-parse-safe -g -o packets.bin");
    println!("    packet-parse-safe --stats -i data.bin");
}

fn print_version() {
    println!("packet-parse-safe {}", APP_VERSION);
    println!("Rust binary packet parser with memory safety guarantees");
}

fn generate_sample_packets(output_path: &str, verbose: bool) -> io::Result<()> {
    let packets = vec![
        Packet::new(PacketType::Data, vec![0x01, 0x02, 0x03, 0x04, 0x05]),
        Packet::with_sequence(PacketType::Acknowledgment, vec![0xAA], 1),
        Packet::with_sequence(PacketType::Control, vec![0x10, 0x20], 2),
        Packet::with_sequence(PacketType::Heartbeat, vec![], 3),
        Packet::with_sequence(PacketType::Data, vec![0xDE, 0xAD, 0xBE, 0xEF], 4),
    ];

    let mut parser = PacketParser::new();
    let mut file = File::create(output_path)?;

    for packet in &packets {
        let bytes = packet.to_bytes();
        file.write_all(&bytes)?;
        
        if verbose {
            println!(
                "Generated: type={}, seq={}, payload_size={}",
                packet.header.packet_type.as_str(),
                packet.header.sequence_number,
                packet.payload.len()
            );
        }
    }

    file.flush()?;
    
    if verbose {
        println!();
        println!("Generated {} packets to '{}'", packets.len(), output_path);
    }

    Ok(())
}

fn parse_packets(input_path: &str, verbose: bool, no_checksum: bool) -> Result<(), PacketError> {
    let mut config_builder = ParserConfigBuilder::new();
    if no_checksum {
        config_builder = config_builder.with_checksum_verification(false);
    }
    
    let mut parser = PacketParser::with_config(config_builder.build());
    let packets = parser.parse_file(input_path)?;

    if verbose {
        println!("Parsed {} packets from '{}':", packets.len(), input_path);
        println!();
    }

    for (i, packet) in packets.iter().enumerate() {
        if verbose {
            println!(
                "[{}] Type: {:6} | Seq: {:5} | Payload: {} bytes | Flags: {}{}{}{}",
                i,
                packet.header.packet_type.as_str(),
                packet.header.sequence_number,
                packet.payload.len(),
                if packet.header.flags.encrypted { "E" } else { "-" },
                if packet.header.flags.compressed { "C" } else { "-" },
                if packet.header.flags.fragmented { "F" } else { "-" },
                if packet.header.flags.last_fragment { "L" } else { "-" },
            );

            if !packet.payload.is_empty() {
                let hex_payload: Vec<String> = packet
                    .payload
                    .iter()
                    .map(|b| format!("{:02X}", b))
                    .collect();
                println!("    Payload: {}", hex_payload.join(" "));
            }
        }
    }

    if verbose {
        println!();
        print_stats(&parser);
    }

    Ok(())
}

fn validate_packets(input_path: &str, verbose: bool) -> Result<(), PacketError> {
    let mut parser = PacketParser::new();
    let packets = parser.parse_file(input_path)?;

    let mut valid_count = 0;
    let mut invalid_count = 0;

    for packet in &packets {
        match packet.validate() {
            Ok(()) => {
                valid_count += 1;
                if verbose {
                    println!("VALID: type={}, seq={}", 
                        packet.header.packet_type.as_str(),
                        packet.header.sequence_number);
                }
            }
            Err(e) => {
                invalid_count += 1;
                if verbose {
                    println!("INVALID: {}", e);
                }
            }
        }
    }

    println!("Validation complete: {} valid, {} invalid", valid_count, invalid_count);
    Ok(())
}

fn show_stats(input_path: &str) -> Result<(), PacketError> {
    let mut parser = PacketParser::new();
    let _ = parser.parse_file(input_path)?;
    print_stats(&parser);
    Ok(())
}

fn print_stats(parser: &PacketParser) {
    let stats = parser.stats();
    println!("Parsing Statistics:");
    println!("  Total packets:    {}", stats.total_packets);
    println!("  Data packets:     {}", stats.data_packets);
    println!("  ACK packets:      {}", stats.ack_packets);
    println!("  Control packets:  {}", stats.control_packets);
    println!("  Heartbeat packets: {}", stats.heartbeat_packets);
    println!("  Error packets:    {}", stats.error_packets);
    println!("  Total bytes:      {}", stats.total_bytes);
    println!("  Parse errors:     {}", stats.parse_errors);
}

fn read_from_stdin() -> io::Result<Vec<u8>> {
    let mut buffer = Vec::new();
    io::stdin().read_to_end(&mut buffer)?;
    Ok(buffer)
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    let args = Args::parse(&args).map_err(|e| {
        eprintln!("Error: {}", e);
        eprintln!("Use --help for usage information");
        process::exit(1);
    })?;

    match args.mode {
        Mode::Help => {
            print_help();
        }
        Mode::Version => {
            print_version();
        }
        Mode::Generate => {
            let output = args.output_file.unwrap_or_else(|| DEFAULT_OUTPUT.to_string());
            generate_sample_packets(&output, args.verbose)?;
        }
        Mode::Parse | Mode::Validate | Mode::Stats => {
            let input = args.input_file.ok_or_else(|| {
                "No input file specified. Use -i or provide a file path."
            })?;

            if !Path::new(&input).exists() {
                return Err(format!("Input file not found: {}", input).into());
            }

            match args.mode {
                Mode::Parse => {
                    parse_packets(&input, args.verbose, args.no_checksum)?;
                }
                Mode::Validate => {
                    validate_packets(&input, args.verbose)?;
                }
                Mode::Stats => {
                    show_stats(&input)?;
                }
                _ => unreachable!(),
            }
        }
    }

    Ok(())
}

fn main() {
    if let Err(e) = run() {
        eprintln!("Error: {}", e);
        process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_args_parsing_help() {
        let args = Args::parse(&["program".to_string(), "--help".to_string()]).unwrap();
        assert!(matches!(args.mode, Mode::Help));
    }

    #[test]
    fn test_args_parsing_version() {
        let args = Args::parse(&["program".to_string(), "-v".to_string()]).unwrap();
        assert!(matches!(args.mode, Mode::Version));
    }

    #[test]
    fn test_args_parsing_parse() {
        let args = Args::parse(&[
            "program".to_string(),
            "-p".to_string(),
            "-i".to_string(),
            "input.bin".to_string(),
        ]).unwrap();
        assert!(matches!(args.mode, Mode::Parse));
        assert_eq!(args.input_file, Some("input.bin".to_string()));
    }

    #[test]
    fn test_args_parsing_generate() {
        let args = Args::parse(&[
            "program".to_string(),
            "-g".to_string(),
            "-o".to_string(),
            "output.bin".to_string(),
        ]).unwrap();
        assert!(matches!(args.mode, Mode::Generate));
        assert_eq!(args.output_file, Some("output.bin".to_string()));
    }

    #[test]
    fn test_args_parsing_verbose() {
        let args = Args::parse(&[
            "program".to_string(),
            "--verbose".to_string(),
        ]).unwrap();
        assert!(args.verbose);
    }

    #[test]
    fn test_args_parsing_no_checksum() {
        let args = Args::parse(&[
            "program".to_string(),
            "--no-checksum".to_string(),
        ]).unwrap();
        assert!(args.no_checksum);
    }

    #[test]
    fn test_args_parsing_unknown_option() {
        let result = Args::parse(&[
            "program".to_string(),
            "--unknown".to_string(),
        ]);
        assert!(result.is_err());
    }
}
