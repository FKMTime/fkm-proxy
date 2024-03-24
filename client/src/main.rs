use anyhow::Result;
use clap::{command, Parser};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

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

#[tokio::main]
async fn main() -> Result<()> {
    _ = dotenvy::dotenv();
    let args = Args::parse();

    let mut connector = TcpStream::connect(&args.proxy_addr).await?;
    let mut conn_buff = [0u8; 64];

    conn_buff[0] = 0x00;
    conn_buff[1..9].copy_from_slice(&args.hash.to_be_bytes());
    conn_buff[10..26].copy_from_slice(&args.token.to_be_bytes());
    connector.write_all(&conn_buff).await?;

    conn_buff[0] = 0x01; // set the first byte to 0x01 to indicate that next connection is a tunnel
    loop {
        let res = connector.read_u8().await?;
        let local_addr = if res == 0x00 {
            args.nossl.to_string()
        } else if res == 0x01 {
            args.ssl.to_string()
        } else {
            continue;
        };

        tokio::task::spawn(spawn_tunnel(
            conn_buff,
            local_addr,
            args.proxy_addr.to_string(),
        ));
    }

    //Ok(())
}

async fn spawn_tunnel(conn_buff: [u8; 64], local_addr: String, proxy_addr: String) -> Result<()> {
    let mut tunnel_stream = TcpStream::connect(proxy_addr).await?;
    tunnel_stream.set_nodelay(true)?;
    tunnel_stream.write_all(&conn_buff).await?;

    let mut local_stream = TcpStream::connect(local_addr).await?;
    local_stream.set_nodelay(true)?;

    tokio::io::copy_bidirectional(&mut local_stream, &mut tunnel_stream).await?;
    Ok(())
}
