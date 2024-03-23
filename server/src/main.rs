use anyhow::Result;
use kanal::{AsyncReceiver, AsyncSender};
use std::{collections::HashMap, sync::Arc};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::RwLock,
};

pub type OpenTunnChan = Arc<
    RwLock<
        HashMap<
            u128,
            (
                AsyncSender<()>,
                AsyncSender<TcpStream>,
                AsyncReceiver<TcpStream>,
            ),
        >,
    >,
>;

pub type ClientMap = Arc<RwLock<HashMap<String, u128>>>;

#[tokio::main]
async fn main() -> Result<()> {
    let addr = std::env::args().nth(1).unwrap_or("1337".to_string());
    let connector_addr = "0.0.0.0:6969".to_string();

    let open_tunnel_chan: OpenTunnChan = Arc::new(RwLock::new(HashMap::new()));
    let client_map: ClientMap = Arc::new(RwLock::new(HashMap::new()));

    {
        let mut client_map = client_map.write().await;
        client_map.insert("test.fkm.filipton.space".to_string(), 0x6942069420);
    }

    tokio::task::spawn(remote_listener(
        addr,
        open_tunnel_chan.clone(),
        client_map.clone(),
    ));

    tokio::task::spawn(connector_listener(
        connector_addr,
        open_tunnel_chan.clone(),
        client_map.clone(),
    ));

    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {
        _ = sigterm.recv() => {
            println!("Received SIGTERM, stopping server!");
        }
        _ = tokio::signal::ctrl_c() => {
            println!("Received SIGINT, stopping server!");
        }
    }
    Ok(())
}

async fn connector_listener(
    addr: String,
    open_tunnel_chanel: OpenTunnChan,
    client_map: ClientMap,
) -> Result<()> {
    println!("Connector listening on: {addr}");
    let listener = TcpListener::bind(addr).await?;

    loop {
        let (stream, _) = listener.accept().await?;
        stream.set_nodelay(true)?;
        tokio::task::spawn(connector_handler(
            stream,
            open_tunnel_chanel.clone(),
            client_map.clone(),
        ));
    }
}

async fn connector_handler(
    mut stream: TcpStream,
    open_tunnel_channel: OpenTunnChan,
    client_map: ClientMap,
) -> Result<()> {
    let mut connection_buff = [0u8; 64];
    stream.read_exact(&mut connection_buff).await?;

    let client_map = client_map.read().await;
    let token: u128 = u128::from_be_bytes(connection_buff[1..17].try_into().unwrap());
    if !map_contains_value(&client_map, token) {
        return Ok(());
    }

    // im the connector!
    if connection_buff[0] == 0 {
        let (tx, rx) = kanal::unbounded_async::<()>();
        let (stream_tx, stream_rx) = kanal::unbounded_async();

        {
            open_tunnel_channel
                .write()
                .await
                .insert(token, (tx, stream_tx, stream_rx));
        }

        loop {
            let _ = rx.recv().await?;
            stream.write_u8(0x40).await?; // 0x40 - open tunnel
        }
    } else if connection_buff[0] == 1 {
        // im the tunnel!
        let open_tunnel_channel = open_tunnel_channel.read().await;
        let tx = &open_tunnel_channel.get(&token).unwrap().1;

        tx.send(stream).await?;
    }

    Ok(())
}

async fn remote_listener(
    addr: String,
    open_tunnel_channel: OpenTunnChan,
    client_map: ClientMap,
) -> Result<()> {
    println!("Remote listening on: {addr}");
    let listener = TcpListener::bind(addr).await?;
    loop {
        let (stream, _) = listener.accept().await?;
        stream.set_nodelay(true)?;
        tokio::task::spawn(handle_client(
            stream,
            open_tunnel_channel.clone(),
            client_map.clone(),
        ));
    }
}

async fn handle_client(
    mut stream: TcpStream,
    open_tunnel_channel: OpenTunnChan,
    client_map: ClientMap,
) -> Result<()> {
    let mut in_buffer = [0; 8192];

    let n = stream.read(&mut in_buffer).await?;
    let mut start = 0;
    let mut stop = 0;
    for i in 0..n {
        if in_buffer[i] == b'\n' {
            if start == 0 {
                start = i + 1;
                continue;
            } else if stop == 0 {
                stop = i - 1;
                break;
            }
        }
    }

    // Skip "Host: " part of host header (to get host only)
    start += 6;

    let host = String::from_utf8_lossy(&in_buffer[start..stop]);
    println!("Host: {host}");
    let client_map = client_map.read().await;
    let token = client_map.get(host.as_ref());
    if token.is_none() {
        return Ok(());
    }

    let chan = open_tunnel_channel.read().await;
    let (tx, _s_tx, s_rx) = chan.get(&token.unwrap()).unwrap();
    tx.send(()).await?;

    let mut tunnel = s_rx.recv().await?;
    tunnel.write_all(&in_buffer[..n]).await?;
    tokio::io::copy_bidirectional(&mut stream, &mut tunnel).await?;

    Ok(())
}

fn map_contains_value<K, V>(map: &HashMap<K, V>, value: V) -> bool
where
    V: PartialEq,
{
    map.values().any(|v| *v == value)
}
