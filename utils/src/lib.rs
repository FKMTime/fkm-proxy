use aes_gcm::{
    aead::{Aead, OsRng},
    AeadCore, Aes128Gcm, KeyInit, Nonce,
};
use anyhow::{anyhow, Result};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

pub mod certs;
pub mod encryption;
pub mod http;

pub fn generate_hello_packet(
    connector_type: u8,
    token: &u128,
    hash: &u64,
) -> Result<[u8; 80], HelloPacketError> {
    let mut conn_buff = [0u8; 80];
    conn_buff[0] = connector_type;
    conn_buff[1..9].copy_from_slice(&hash.to_be_bytes());

    let cipher = Aes128Gcm::new_from_slice(token.to_be_bytes().as_ref())
        .map_err(|_| anyhow!("Invalid token length"))?;

    let nonce = Aes128Gcm::generate_nonce(&mut OsRng); // 12 bytes
    conn_buff[10..22].copy_from_slice(nonce.as_slice());

    let generated_at = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

    let mut auth_bytes = [0u8; 24]; // KEY(16B) + TIMESTAMP(8B)
    auth_bytes[..16].copy_from_slice(token.to_be_bytes().as_ref());
    auth_bytes[16..24].copy_from_slice(&generated_at.to_be_bytes());

    let encrypted = cipher
        .encrypt(&nonce, auth_bytes.as_ref())
        .map_err(|_| HelloPacketError::EncryptionError)?; // 40 bytes

    conn_buff[23..63].copy_from_slice(encrypted.as_ref());
    Ok(conn_buff)
}

pub fn parse_hello_packet(
    token: u128,
    connection_buff: &[u8; 80],
    hello_packet_ttl: u64,
) -> Result<(), HelloPacketError> {
    let nonce = Nonce::from_slice(&connection_buff[10..22]);
    let cipher = Aes128Gcm::new_from_slice(token.to_be_bytes().as_ref()).unwrap();
    let decrypted_buff = cipher
        .decrypt(nonce, &connection_buff[23..63])
        .map_err(|_| anyhow!("Cant decrypt!"))?;

    let decrypted_token = u128::from_be_bytes(decrypted_buff[0..16].try_into()?);
    let timestamp = u64::from_be_bytes(decrypted_buff[16..24].try_into()?);

    if token != decrypted_token {
        return Err(HelloPacketError::TokenMismatch);
    }

    let current_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();

    if current_time - timestamp > hello_packet_ttl {
        return Err(HelloPacketError::HelloPacketIsTooOld);
    }

    Ok(())
}

#[derive(Error, Debug)]
pub enum HelloPacketError {
    #[error("Token mismatch!")]
    TokenMismatch,

    #[error("Hello packet is too old!")]
    HelloPacketIsTooOld,

    #[error("Encryption error!")]
    EncryptionError,

    #[error(transparent)]
    TryFromSlice(#[from] std::array::TryFromSliceError),

    #[error(transparent)]
    SystemTime(#[from] std::time::SystemTimeError),

    #[error(transparent)]
    Anyhow(#[from] anyhow::Error),
}
