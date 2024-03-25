use aes_gcm::{
    aead::{Aead, Buffer, OsRng},
    AeadCore, Aes128Gcm, KeyInit,
};
use anyhow::Result;
use clap::{command, Parser};
use std::{
    path::Path,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use tokio_rustls::TlsAcceptor;

mod utils;

#[derive(Parser, Debug, Clone)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short, long, default_value = "v1.filipton.space:6969", env = "PROXY")]
    proxy_addr: String,

    #[arg(short, long, default_value = "127.0.0.1:80", env = "LOCAL_NOSSL")]
    nossl: String,

    #[arg(short, long, default_value = "127.0.0.1:443", env = "LOCAL_SSL")]
    ssl: String,

    #[arg(short, long, env = "HASH")]
    hash: u64,

    #[arg(short, long, env = "TOKEN")]
    token: u128,
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

#[tokio::main]
async fn main() -> Result<()> {
    _ = dotenvy::dotenv();
    let args = Args::parse();

    let mut connector = TcpStream::connect(&args.proxy_addr).await?;
    let hello_packet = generate_hello_packet(0, &args.token, &args.hash);

    connector.write_all(&hello_packet).await?;

    loop {
        let res = connector.read_u8().await?;
        let ssl = res == 0x01;
        /*
        let local_addr = if res == 0x00 {
            args.nossl.to_string()
        } else if res == 0x01 {
            args.ssl.to_string()
        } else {
            continue;
        };
        */

        let conn_buff = generate_hello_packet(1, &args.token, &args.hash);
        tokio::task::spawn(spawn_tunnel(
            conn_buff,
            args.nossl.to_string(),
            args.proxy_addr.to_string(),
            ssl,
        ));
    }

    //Ok(())
}

async fn spawn_tunnel(
    conn_buff: [u8; 80],
    local_addr: String,
    proxy_addr: String,
    ssl: bool,
) -> Result<()> {
    let mut tunnel_stream = TcpStream::connect(proxy_addr).await?;
    tunnel_stream.set_nodelay(true)?;
    tunnel_stream.write_all(&conn_buff).await?;

    let mut local_stream = TcpStream::connect(local_addr).await?;
    local_stream.set_nodelay(true)?;

    if ssl {
        let certs = crate::utils::load_certs(Path::new("key.crt"))?;
        let privkey = crate::utils::load_keys(Path::new("priv.key"))?;

        let config = tokio_rustls::rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, privkey)?;

        let acceptor = TlsAcceptor::from(Arc::new(config));
        let mut stream = acceptor.accept(tunnel_stream).await?;

        tokio::io::copy_bidirectional(&mut local_stream, &mut stream).await?;
    } else {
        tokio::io::copy_bidirectional(&mut local_stream, &mut tunnel_stream).await?;
    }

    Ok(())
}
