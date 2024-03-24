use anyhow::Result;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

const SERVER_ADDR: &str = "v1.filipton.space:6969";
const LOCAL_ADDR_NOSSL: &str = "127.0.0.1:80";
const LOCAL_ADDR_SSL: &str = "127.0.0.1:443";
const URL_HASH: u64 = 12885814852862947872; // generated by server (hash of the URL)
const TOKEN: u128 = 0x6942069420; // generated by server (random token)

#[tokio::main]
async fn main() -> Result<()> {
    let mut connector = TcpStream::connect(SERVER_ADDR).await?;
    let mut conn_buff = [0u8; 64];

    conn_buff[0] = 0x00;
    conn_buff[1..9].copy_from_slice(&URL_HASH.to_be_bytes());
    conn_buff[10..26].copy_from_slice(&TOKEN.to_be_bytes());
    connector.write_all(&conn_buff).await?;

    conn_buff[0] = 0x01; // set the first byte to 0x01 to indicate that next connection is a tunnel
    loop {
        let res = connector.read_u8().await?;
        println!("res: {res}");
        tokio::task::spawn(spawn_tunnel(conn_buff, res));
    }

    //Ok(())
}

async fn spawn_tunnel(conn_buff: [u8; 64], option: u8) -> Result<()> {
    let local_addr = if option == 0x00 {
        LOCAL_ADDR_NOSSL
    } else if option == 0x01 {
        LOCAL_ADDR_SSL
    } else {
        return Err(anyhow::anyhow!("Invalid option"));
    };

    let mut tunnel_stream = TcpStream::connect(SERVER_ADDR).await?;
    tunnel_stream.set_nodelay(true)?;
    tunnel_stream.write_all(&conn_buff).await?;

    println!("Tunneling to {}", local_addr);
    let mut local_stream = TcpStream::connect(local_addr).await?;
    local_stream.set_nodelay(true)?;

    tokio::io::copy_bidirectional(&mut local_stream, &mut tunnel_stream).await?;
    Ok(())
}
