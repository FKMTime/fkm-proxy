use anyhow::Result;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

pub async fn get_domain_by_hash(hash: u64, proxy_addr: String) -> Result<String> {
    let mut connector = TcpStream::connect(&proxy_addr).await?;
    let mut buf = [0u8; 80];
    buf[0] = 0x02; // get domain by hash
    buf[1..9].copy_from_slice(&hash.to_be_bytes());

    connector.write_all(&buf).await?;

    let mut domain = String::new();
    connector.read_to_string(&mut domain).await?;

    Ok(domain)
}
