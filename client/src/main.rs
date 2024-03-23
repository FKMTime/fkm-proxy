use anyhow::Result;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

const SERVER_ADDR: &str = "v1.filipton.space:6969";
const TOKEN: u128 = 0x6942069420;

#[tokio::main]
async fn main() -> Result<()> {
    let mut connector = TcpStream::connect(SERVER_ADDR).await?;
    let mut conn_buff = [0u8; 64];
    conn_buff[0] = 0x00;

    let token_bytes = TOKEN.to_be_bytes();
    conn_buff[1..17].copy_from_slice(&token_bytes);

    connector.write_all(&conn_buff).await?;
    loop {
        let res = connector.read_u8().await?;
        if res == 0x40 {
            tokio::task::spawn(spawn_tunnel());
        }
    }

    //Ok(())
}

async fn spawn_tunnel() -> Result<()> {
    let mut local_stream = TcpStream::connect("127.0.0.1:80").await?;
    let mut tunnel_stream = TcpStream::connect(SERVER_ADDR).await?;
    local_stream.set_nodelay(true)?;

    let mut conn_buff = [0u8; 64];
    conn_buff[0] = 0x01;

    let token_bytes = TOKEN.to_be_bytes();
    conn_buff[1..17].copy_from_slice(&token_bytes);

    tunnel_stream.write_all(&conn_buff).await?;
    tunnel_stream.set_nodelay(true)?;

    tokio::io::copy_bidirectional(&mut local_stream, &mut tunnel_stream).await?;
    Ok(())
}
