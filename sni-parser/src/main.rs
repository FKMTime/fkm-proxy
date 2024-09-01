use anyhow::{anyhow, Result};
use rustls::server::Acceptor;

fn main() -> Result<()> {
    let test_files = std::fs::read_dir("./tests")?;
    for file in test_files {
        let file = file?;
        if !file.file_name().to_str().unwrap_or("").ends_with(".bin") {
            println!("[ERROR] Not bin file: {file:?}");
            continue;
        }

        let buf = std::fs::read(file.path())?;
        let parsed = parse_sni(&buf)?;

        let mut acceptor = Acceptor::default();
        let mut n_buf = &buf[..];
        acceptor.read_tls(&mut n_buf)?;

        let accepted = acceptor
            .accept()
            .map_err(|e| anyhow!("{e:?}"))?
            .ok_or_else(|| anyhow!("No tls msg"))?;

        let true_parsed = accepted
            .client_hello()
            .server_name()
            .ok_or_else(|| anyhow!("No server name"))?
            .to_string();

        println!("Parsed: {parsed:?} | True parsed: {true_parsed:?}");
    }

    Ok(())
}

fn parse_sni(buf: &[u8]) -> Result<String> {
    Ok("".to_string())
}
