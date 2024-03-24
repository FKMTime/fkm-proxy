use crate::structs::{SharedProxyState, TunnelEntry, TunnelError};
use anyhow::{anyhow, Result};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tokio_rustls::rustls::server::Acceptor;

pub async fn spawn_tunnel_connector(
    remote_addrs: Vec<(&str, bool)>,
    connector_addr: &str,
    shared_proxy_state: SharedProxyState,
) -> Result<()> {
    for remote_addr in remote_addrs {
        tokio::task::spawn(remote_listener(
            remote_addr.0.to_string(),
            shared_proxy_state.clone(),
            remote_addr.1,
        ));
    }

    tokio::task::spawn(connector_listener(
        connector_addr.to_string(),
        shared_proxy_state.clone(),
    ));

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
        println!("Connector connected to url with hash: {url_hash}");

        let (tx, rx) = kanal::unbounded_async::<u8>();
        let (stream_tx, stream_rx) = kanal::unbounded_async();
        state
            .insert_tunnel_connector(token, (tx, stream_tx, stream_rx))
            .await;

        loop {
            tokio::select! {
                res = rx.recv() => {
                    let res = res?;
                    if res == u8::MAX {
                        // if max, close connector
                        return Ok(());
                    }

                    stream.write_u8(res).await?;
                }
                res = stream.read_u8() => {
                    if res.is_err() {
                        state.remove_tunnel(token).await;
                        // tunnel is closed
                        return Ok(());
                    }
                }
            }
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

async fn remote_listener(addr: String, state: SharedProxyState, ssl: bool) -> Result<()> {
    println!("Remote listening on: {addr} (SSL: {ssl})");
    let listener = TcpListener::bind(addr).await?;
    loop {
        let (stream, _) = listener.accept().await?;
        stream.set_nodelay(true)?;
        tokio::task::spawn(handle_client(stream, state.clone(), ssl));
    }
}

async fn handle_client(mut stream: TcpStream, state: SharedProxyState, ssl: bool) -> Result<()> {
    let mut in_buffer = [0; 8192];

    let n = stream.peek(&mut in_buffer).await?;

    let host = if ssl {
        let mut n_buf = &in_buffer[..n];
        let mut acceptor = Acceptor::default();
        _ = acceptor.read_tls(&mut n_buf);
        let accepted = acceptor
            .accept()
            .map_err(|e| anyhow::anyhow!(format!("{e:?}")))?
            .ok_or_else(|| anyhow::anyhow!("No tls message"))?;

        accepted
            .client_hello()
            .server_name()
            .ok_or_else(|| anyhow::anyhow!("No server name"))?
            .to_string()
    } else {
        let mut lines = in_buffer[..n].split(|&x| x == b'\n');
        let host = lines
            .find(|x| x.starts_with(b"Host:"))
            .ok_or_else(|| anyhow::anyhow!("No host"))?;

        String::from_utf8_lossy(&host[5..]).trim().to_string()
    };

    let tunn = match get_tunn(&state, &host).await {
        Ok(tunn) => tunn,
        Err(TunnelError::TunnelDoesNotExist) => {
            _ = crate::utils::write_raw_http_resp(
                &mut stream,
                404,
                "NOT FOUND",
                "That tunnel does not exists!",
                ssl,
                &state,
            )
            .await;
            anyhow::bail!("Tunnel does not exist!");
        }
        Err(TunnelError::NoConnectorForTunnel) => {
            _ = crate::utils::write_raw_http_resp(
                &mut stream,
                404,
                "NOT FOUND",
                "Connector for this tunnel isn't connected!",
                ssl,
                &state,
            )
            .await;
            anyhow::bail!("No connector for tunnel!");
        }
        _ => {
            anyhow::bail!("Error getting tunnel!");
        }
    };

    tunn.0.send(u8::from(ssl)).await?;
    let mut tunnel = tunn.2.recv().await?;

    tokio::io::copy_bidirectional(&mut stream, &mut tunnel).await?;
    Ok(())
}

async fn get_tunn(state: &SharedProxyState, host: &str) -> Result<TunnelEntry, TunnelError> {
    let token = state
        .get_client_token(&host)
        .await
        .ok_or_else(|| TunnelError::TunnelDoesNotExist)?;

    let tunn = state
        .get_tunnel_entry(token)
        .await
        .ok_or_else(|| TunnelError::NoConnectorForTunnel)?;

    Ok(tunn)
}
