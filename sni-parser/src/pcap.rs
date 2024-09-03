use anyhow::{bail, Result};
use etherparse::{SlicedPacket, TransportSlice};
use pcap_parser::{traits::PcapReaderIterator, Block, PcapBlockOwned, PcapError, PcapNGReader};
use std::{fs::File, path::PathBuf};

pub fn pcap_to_tests(pcap_path: &PathBuf, tests_path: &PathBuf) -> Result<()> {
    _ = std::fs::remove_dir_all(tests_path);
    _ = std::fs::create_dir_all(tests_path);
    if std::fs::metadata(pcap_path).is_err() {
        bail!("Wrong Pcap input file");
    }

    let file = File::open(pcap_path).unwrap();
    let mut reader = PcapNGReader::new(4 * 1024 * 1024, file)?;

    let mut test_n = 1;
    let mut tmp_buf = Vec::new();
    loop {
        match reader.next() {
            Ok((offset, block)) => {
                if let PcapBlockOwned::NG(b) = block {
                    if b.is_data_block() {
                        if let Block::EnhancedPacket(ref packet) = b {
                            match SlicedPacket::from_ethernet(&packet.data) {
                                Err(value) => println!("Err {:?}", value),
                                Ok(value) => {
                                    if let Some(ref transport) = value.transport {
                                        if let TransportSlice::Tcp(tcp) = transport {
                                            tmp_buf.extend_from_slice(tcp.payload());

                                            if tcp.psh() {
                                                let sni_res =
                                                    crate::rustls_parse_sni(&tmp_buf);

                                                if let Ok(sni) = sni_res {
                                                    println!("{sni:?}");
                                                    let file_path = tests_path
                                                        .join(format!("test_{test_n}"))
                                                        .with_extension("bin");

                                                    std::fs::write(file_path, &tmp_buf)?;
                                                    test_n += 1;
                                                }
                                                tmp_buf.clear();
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                reader.consume(offset);
            }
            Err(PcapError::Eof) => break,
            Err(PcapError::Incomplete(_)) => {
                reader.refill().unwrap();
            }
            Err(e) => panic!("error while reading: {:?}", e),
        }
    }

    Ok(())
}
