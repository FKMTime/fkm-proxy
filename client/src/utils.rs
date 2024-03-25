use aes_gcm::{
    aead::{Aead, OsRng},
    AeadCore, Aes128Gcm, KeyInit,
};
use std::{
    fs::File,
    io::BufReader,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};

pub fn load_certs(path: &Path) -> std::io::Result<Vec<CertificateDer<'static>>> {
    rustls_pemfile::certs(&mut BufReader::new(File::open(path)?)).collect()
}

pub fn load_keys(path: &Path) -> std::io::Result<PrivateKeyDer<'static>> {
    let key = rustls_pemfile::private_key(&mut BufReader::new(File::open(path)?))?.unwrap();
    Ok(key)
}

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
