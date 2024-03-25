use aes_gcm::{
    aead::{Aead, OsRng},
    AeadCore, Aes128Gcm, KeyInit,
};
use anyhow::Result;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

pub fn generate_hello_packet(connector_type: u8, token: &u128, hash: &u64) -> [u8; 80] {
    let mut conn_buff = [0u8; 80];
    conn_buff[0] = connector_type;
    conn_buff[1..9].copy_from_slice(&hash.to_be_bytes());

    let cipher = Aes128Gcm::new_from_slice(token.to_be_bytes().as_ref()).unwrap();
    let nonce = Aes128Gcm::generate_nonce(&mut OsRng); // 12 bytes
    conn_buff[10..22].copy_from_slice(nonce.as_slice());

    let generated_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let mut auth_bytes = [0u8; 24]; // KEY(16B) + TIMESTAMP(8B)
    auth_bytes[..16].copy_from_slice(token.to_be_bytes().as_ref());
    auth_bytes[16..24].copy_from_slice(&generated_at.to_be_bytes());

    let encrypted = cipher.encrypt(&nonce, auth_bytes.as_ref()).unwrap(); // 40 bytes
    conn_buff[23..63].copy_from_slice(encrypted.as_ref());
    conn_buff
}

pub fn construct_http_redirect(url: &str) -> String {
    format!(
        "HTTP/1.1 301 Moved Permanently\r\nLocation: {}\r\nContent-Length: 0\r\n\r\n",
        url
    )
}

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
