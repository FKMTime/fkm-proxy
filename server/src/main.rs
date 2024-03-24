use crate::structs::SharedProxyState;
use anyhow::{anyhow, Result};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

mod structs;

#[tokio::main]
async fn main() -> Result<()> {
    let addr = std::env::args().nth(1).unwrap_or("1337".to_string());
    let connector_addr = "0.0.0.0:6969".to_string();

    let shared_proxy_state = SharedProxyState::new();
    shared_proxy_state
        .insert_client("bvcxbvxc.fkm.com:1337", 0x6942069420)
        .await;

    tokio::task::spawn(remote_listener(addr, shared_proxy_state.clone()));

    tokio::task::spawn(connector_listener(
        connector_addr,
        shared_proxy_state.clone(),
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

async fn connector_listener(addr: String, state: SharedProxyState) -> Result<()> {
    println!("Connector listening on: {addr}");
    let listener = TcpListener::bind(addr).await?;

    loop {
        let (stream, _) = listener.accept().await?;
        stream.set_nodelay(true)?;
        tokio::task::spawn(connector_handler(stream, state.clone()));
    }
}

async fn connector_handler(mut stream: TcpStream, state: SharedProxyState) -> Result<()> {
    let mut connection_buff = [0u8; 64];
    stream.read_exact(&mut connection_buff).await?;

    let url_hash: u64 = u64::from_be_bytes(connection_buff[1..9].try_into()?);

    // token should be encrypted using aes or sth!
    let token: u128 = u128::from_be_bytes(connection_buff[10..26].try_into()?);

    let url_client_token = state
        .get_token_by_url_hash(url_hash)
        .await
        .ok_or_else(|| anyhow!("Cant find token!"))?;

    if token != url_client_token {
        return Ok(());
    }

    // im the connector!
    if connection_buff[0] == 0 {
        let (tx, rx) = kanal::unbounded_async::<bool>();
        let (stream_tx, stream_rx) = kanal::unbounded_async();
        state
            .insert_tunnel_connector(token, (tx, stream_tx, stream_rx))
            .await;

        loop {
            let res = rx.recv().await?;
            if res { // if true, close connector
                println!("Closing connector!");
                return Ok(());
            }

            stream.write_u8(0x40).await?; // 0x40 - open tunnel
        }
    } else if connection_buff[0] == 1 {
        // im the tunnel!
        let tx = state
            .get_tunnel_tx(token)
            .await
            .ok_or_else(|| anyhow!("Cant find tunnel tx!"))?;

        tx.send(stream).await?;
    }

    Ok(())
}

async fn remote_listener(addr: String, state: SharedProxyState) -> Result<()> {
    println!("Remote listening on: {addr}");
    let listener = TcpListener::bind(addr).await?;
    loop {
        let (stream, _) = listener.accept().await?;
        stream.set_nodelay(true)?;
        tokio::task::spawn(handle_client(stream, state.clone()));
    }
}

async fn handle_client(mut stream: TcpStream, state: SharedProxyState) -> Result<()> {
    let mut in_buffer = [0; 1024];

    let n = stream.peek(&mut in_buffer).await?;
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

    let token = state
        .get_client_token(&host)
        .await
        .ok_or_else(|| anyhow!("Token not found!"))?;

    let tunn = state
        .get_tunnel_entry(token)
        .await
        .ok_or_else(|| anyhow!("Tunnel entry not found!"))?;

    tunn.0.send(false).await?;
    let mut tunnel = tunn.2.recv().await?;

    tokio::io::copy_bidirectional(&mut stream, &mut tunnel).await?;

    Ok(())
}
