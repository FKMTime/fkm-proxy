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
            String,
            (
                AsyncSender<()>,
                AsyncSender<TcpStream>,
                AsyncReceiver<TcpStream>,
            ),
        >,
    >,
>;

#[tokio::main]
async fn main() -> Result<()> {
    let addr = std::env::args().nth(1).unwrap_or("1337".to_string());
    let connector_addr = "0.0.0.0:6969".to_string();

    let open_tunnel_chan: OpenTunnChan = Arc::new(RwLock::new(HashMap::new()));

    tokio::task::spawn(remote_listener(addr, open_tunnel_chan.clone()));
    tokio::task::spawn(connector_listener(connector_addr, open_tunnel_chan.clone()));

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

async fn connector_listener(addr: String, open_tunnel_chanel: OpenTunnChan) -> Result<()> {
    println!("Connector listening on: {addr}");
    let listener = TcpListener::bind(addr).await?;

    loop {
        let (stream, _) = listener.accept().await?;
        tokio::task::spawn(connector_handler(stream, open_tunnel_chanel.clone()));
    }
}

async fn connector_handler(mut stream: TcpStream, open_tunnel_channel: OpenTunnChan) -> Result<()> {
    let mut connection_buff = [0u8; 64];
    stream.read_exact(&mut connection_buff).await?;

    // im the connector!
    if connection_buff[0] == 0 {
        println!("New connector");
        let (tx, rx) = kanal::unbounded_async::<()>();
        let (stream_tx, stream_rx) = kanal::unbounded_async();

        {
            open_tunnel_channel
                .write()
                .await
                .insert("dsa".to_string(), (tx, stream_tx, stream_rx));
        }

        loop {
            let _ = rx.recv().await?;
            println!("Send new tunnel req");
            stream.write_u8(0x40).await?; // 0x40 - open tunnel
        }
    } else if connection_buff[0] == 1 {
        // im the tunnel!
        let tun_dest = "dsa"; // read from connection_buff
        let open_tunnel_channel = open_tunnel_channel.read().await;
        let tx = &open_tunnel_channel.get(tun_dest).unwrap().1;

        stream.set_nodelay(true)?;
        tx.send(stream).await?;
        println!("new tunnel conn");
    }

    Ok(())
}

async fn remote_listener(addr: String, open_tunnel_channel: OpenTunnChan) -> Result<()> {
    println!("Remote listening on: {addr}");
    let listener = TcpListener::bind(addr).await?;
    loop {
        let (stream, _) = listener.accept().await?;
        tokio::task::spawn(handle_client(stream, open_tunnel_channel.clone()));
    }
}

async fn handle_client(mut stream: TcpStream, open_tunnel_channel: OpenTunnChan) -> Result<()> {
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
    println!("str: |{host}|");
    let host = "dsa"; // for test

    let chan = open_tunnel_channel.read().await;
    let (tx, _s_tx, s_rx) = chan.get(host).unwrap();
    tx.send(()).await?;

    let mut tunnel = s_rx.recv().await?;
    tunnel.write(&in_buffer).await?;
    stream.set_nodelay(true)?;
    println!("Got new tunnel");
    tokio::io::copy_bidirectional(&mut stream, &mut tunnel).await?;

    Ok(())
}
