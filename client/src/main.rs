use anyhow::Result;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

const SERVER_ADDR: &str = "127.0.0.1:6969";

#[tokio::main]
async fn main() -> Result<()> {
    let mut connector = TcpStream::connect(SERVER_ADDR).await?;
    let mut conn_buff = [0u8; 64];
    conn_buff[0] = 0x00; // tell the server we are the connector

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
    let mut local_stream = TcpStream::connect("127.0.0.1:5000").await?;
    let mut tunnel_stream = TcpStream::connect(SERVER_ADDR).await?;
    local_stream.set_nodelay(true)?;

    let mut conn_buff = [0u8; 64];
    conn_buff[0] = 0x01; // tell the server we are the tunnel
    tunnel_stream.write_all(&conn_buff).await?;
    tunnel_stream.set_nodelay(true)?;

    println!("Tunnel created");
    tokio::io::copy_bidirectional(&mut local_stream, &mut tunnel_stream).await?;
    Ok(())
}
