use anyhow::Result;
use clap::Parser;
use hkdf::Hkdf;
use pcap::pcap_to_tests;
use s2n_quic_core::crypto::InitialKey as _;
use s2n_quic_core::crypto::Key;
use s2n_quic_crypto::initial::InitialKey;
use sha2::Sha256;
use sni::{parse_sni, parse_sni_normal, rustls_parse_sni};
use std::path::PathBuf;
use tquic::{endpoint, PacketHeader};

mod pcap;
mod sni;

#[derive(Parser, Debug)]
enum Args {
    Tester {
        /// Tests dir (for input and output)
        #[arg(short, long)]
        tests_dir: PathBuf,
    },

    PcapParser {
        /// Input pcap file path
        #[arg(short, long)]
        input_pcap: PathBuf,

        /// Tests dir (for input and output)
        #[arg(short, long)]
        tests_dir: PathBuf,
    },
}

fn main() -> Result<()> {
    let dcid = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08]; // read from packet
    let (key, _) = InitialKey::new_server(&dcid);

    let header = [
        0xc3, 0x00, 0x00, 0x00, 0x01, 0x08, 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08, 0x00,
        0x00, 0x44, 0x9e, 0x00, 0x00, 0x00, 0x02,
    ];

    let mut payload = hex::decode(std::fs::read_to_string("./encrypted-packet.txt")?.trim())?;
    key.decrypt(2, &header, &mut payload).unwrap();

    println!("{payload:02X?}");

    /*
    let initial_salt = [
        0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c,
        0xad, 0xcc, 0xbb, 0x7f, 0x0a,
    ];

    let client_in = [
        0x00, 0x20, 0x0f, 0x74, 0x6c, 0x73, 0x31, 0x33, 0x20, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74,
        0x20, 0x69, 0x6e, 0x00,
    ];

    let hk = Hkdf::<Sha256>::new(Some(&initial_salt), &dcid);

    let mut client_initial_secret = [0; 32];
    hk.expand(&client_in, &mut client_initial_secret).unwrap();

    println!("{client_initial_secret:02X?}");
    */

    // test quic parsing
    //let quic_packet = std::fs::read("/home/notpilif/Downloads/quic-initial.bin")?;
    //let packet_header = PacketHeader::from_bytes(&quic_packet, 8)?;
    //println!("{packet_header:?}");

    return Ok(());

    let args = Args::parse();
    match args {
        Args::Tester { tests_dir } => {
            tester(&tests_dir)?;
        }
        Args::PcapParser {
            input_pcap,
            tests_dir,
        } => {
            pcap_to_tests(&input_pcap, &tests_dir)?;
        }
    }

    Ok(())
}

fn tester(tests_dir: &PathBuf) -> Result<()> {
    let test_files = std::fs::read_dir(tests_dir)?;
    let mut wrong_n = 0;
    for file in test_files {
        let file = file?;
        if !file.file_name().to_str().unwrap_or("").ends_with(".bin") {
            println!("[ERROR] Not bin file: {file:?}");
            continue;
        }

        println!("\n\nParse: {file:?}");
        let buf = std::fs::read(file.path())?;
        //let parsed = parse_sni(&buf)?;
        let parsed = parse_sni_normal(&buf).unwrap_or("".to_string());
        let true_parsed = rustls_parse_sni(&buf).unwrap_or("ERROR".to_string());

        println!("Parsed: {parsed:?} | True parsed: {true_parsed:?}");
        if parsed != true_parsed {
            println!("[ERROR] WRONG PARSE!!!!");
            wrong_n += 1;
        }
        println!("\n\n");
    }

    println!("\n\nWRONG_N: {wrong_n}\n\n");
    Ok(())
}
