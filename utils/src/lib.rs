use anyhow::Result;
use std::net::{SocketAddr, ToSocketAddrs};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub mod certs;
pub mod http;

pub fn parse_socketaddr(arg: &str) -> Result<SocketAddr> {
    let addrs = arg.to_socket_addrs()?;
    for addr in addrs {
        if addr.is_ipv4() {
            return Ok(addr);
        }
    }

    Err(anyhow::anyhow!("No ipv4 socketaddr found!"))
}

pub fn generate_hello_packet(
    connector_type: u8,
    token: &u128,
    hash: &u64,
    own_ssl: bool,
) -> Result<[u8; 80], HelloPacketError> {
    let mut conn_buff = [0u8; 80];
    conn_buff[0] = connector_type;
    conn_buff[1..9].copy_from_slice(&hash.to_be_bytes());
    conn_buff[10..26].copy_from_slice(&token.to_be_bytes());
    conn_buff[26] = own_ssl as u8;

    Ok(conn_buff)
}

pub fn parse_hello_packet(
    token: u128,
    connection_buff: &[u8; 80],
) -> Result<bool, HelloPacketError> {
    //let parsed_connector_type = connection_buff[0];
    //let parsed_hash = u64::from_be_bytes(connection_buff[1..9].try_into()?);
    let parsed_token = u128::from_be_bytes(connection_buff[10..26].try_into()?);

    if parsed_token != token {
        return Err(HelloPacketError::TokenMismatch);
    }

    Ok(connection_buff[26] != 0x00)
}

pub fn generate_string_packet(string: &str) -> Result<Vec<u8>> {
    let mut bytes = string.as_bytes().to_vec();
    bytes.push(0); // null terminator

    Ok(bytes)
}

pub async fn send_string_to_stream<T>(stream: &mut T, string: &str) -> Result<()>
where
    T: AsyncWrite + Unpin,
{
    let bytes = generate_string_packet(string)?;
    stream.write_all(&bytes).await?;

    Ok(())
}

pub async fn read_string_from_stream<T>(stream: &mut T) -> Result<String>
where
    T: AsyncRead + Unpin,
{
    let mut buffer = Vec::new();
    loop {
        let byte = stream.read_u8().await?;
        if byte == 0 {
            break;
        }

        buffer.push(byte);
    }

    Ok(String::from_utf8(buffer)?)
}

#[derive(Error, Debug)]
pub enum HelloPacketError {
    #[error("Token mismatch!")]
    TokenMismatch,

    #[error(transparent)]
    TryFromSlice(#[from] std::array::TryFromSliceError),

    #[error(transparent)]
    Anyhow(#[from] anyhow::Error),
}

pub fn read_http_host(in_buffer: &[u8]) -> Result<String> {
    let mut lines = in_buffer.split(|&x| x == b'\n');
    let host = lines
        .find(|x| x.to_ascii_lowercase().starts_with(b"host:"))
        .ok_or_else(|| anyhow::anyhow!("No host"))?;

    let host = String::from_utf8_lossy(&host[5..]).trim().to_string();
    Ok(host)
}
