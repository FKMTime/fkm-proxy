use anyhow::Result;
use clap::Parser;
use pcap::pcap_to_tests;
use sni::{parse_sni, parse_sni_normal, rustls_parse_sni};
use std::path::PathBuf;

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
