use crate::structs::{SharedProxyState, TunnelEntry, TunnelError};
use anyhow::{anyhow, Result};
use std::{collections::HashMap, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tokio_rustls::{rustls::pki_types, TlsAcceptor, TlsConnector};

const STATIC_HTML: &str = include_str!("./index.html");

pub async fn spawn_tunnel_connector(
    remote_addrs: Vec<(&str, bool)>,
    connector_addr: &str,
    shared_proxy_state: SharedProxyState,
) -> Result<()> {
    for remote_addr in remote_addrs {
        let addr = remote_addr.0.to_string();
        let shared_proxy_state = shared_proxy_state.clone();

        tokio::task::spawn(async move {
            let res = remote_listener(&addr, shared_proxy_state, remote_addr.1).await;
            if let Err(e) = res {
                tracing::error!("[{}] Remote listener error: {e}", addr);
            }
        });
    }

    let connector_addr = connector_addr.to_string();
    let shared_proxy_state = shared_proxy_state.clone();
    tokio::task::spawn(async move {
        let res = connector_listener(connector_addr, shared_proxy_state).await;
        if let Err(e) = res {
            tracing::error!("Connector listener error: {e}");
        }
    });

    Ok(())
}

async fn connector_listener(addr: String, state: SharedProxyState) -> Result<()> {
    tracing::info!("Connector listening on: {addr}");
    let listener = TcpListener::bind(addr).await?;
    let connector = state.get_tls_connector().await;

    loop {
        let (stream, _) = listener.accept().await?;
        stream.set_nodelay(true)?;

        let state = state.clone();
        let connector = connector.clone();
        tokio::task::spawn(async move {
            let res = connector_handler(stream, state, connector).await;
            if let Err(e) = res {
                tracing::error!("Connector error: {e}");
            }
        });
    }
}

async fn connector_handler(
    stream: TcpStream,
    state: SharedProxyState,
    connector: Arc<TlsConnector>,
) -> Result<()> {
    let mut stream = connector
        .connect(pki_types::ServerName::try_from("proxy.lan")?, stream)
        .await?;

    let mut connection_buff = [0u8; 80];
    stream.read_exact(&mut connection_buff).await?;

    let url_hash: u64 = u64::from_be_bytes(connection_buff[1..9].try_into()?);
    let token = state
        .get_token_by_url_hash(url_hash)
        .await
        .ok_or_else(|| anyhow!("Cant find token!"))?;

    let res = ::utils::parse_hello_packet(token, &connection_buff);
    if let Err(e) = res {
        return Err(e.into());
    }

    // im the connector!
    if connection_buff[0] == 0 {
        tracing::info!("Connector connected to url with hash: {url_hash}");
        let domain = state
            .get_domain_by_hash(url_hash)
            .await
            .ok_or_else(|| anyhow!("Cant find domain!"))?;
        ::utils::send_string_to_stream(&mut stream, &domain).await?;

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

async fn remote_listener(addr: &str, state: SharedProxyState, ssl: bool) -> Result<()> {
    tracing::info!("Remote listening on: {addr} (SSL: {ssl})");
    let listener = TcpListener::bind(addr).await?;
    let acceptor = state.get_tls_acceptor().await;

    loop {
        let (stream, _) = listener.accept().await?;
        stream.set_nodelay(true)?;

        let state = state.clone();
        let acceptor = acceptor.clone();
        tokio::task::spawn(async move {
            let res = handle_client(stream, state, ssl, acceptor).await;
            if let Err(e) = res {
                tracing::error!("Handle client error: {e}");
            }
        });
    }
}

async fn handle_client(
    stream: TcpStream,
    state: SharedProxyState,
    ssl: bool,
    acceptor: Arc<TlsAcceptor>,
) -> Result<()> {
    if ssl {
        let stream = acceptor.accept(stream).await?;
        handle_client_inner(stream, state, true).await?;
    } else {
        handle_client_inner(stream, state, false).await?;
    }

    Ok(())
}

async fn handle_client_inner<T>(mut stream: T, state: SharedProxyState, ssl: bool) -> Result<()>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let mut in_buffer = [0; 8192];

    let (host, n) = ::utils::read_http_host(&mut stream, &mut in_buffer).await?;
    if host == state.get_panel_domain().await {
        serve_panel(&mut stream, in_buffer, n, &state).await?;

        return Ok(());
    }

    if let Ok((tunn, _)) = get_tunn_or_error(&state, &host, &mut stream).await {
        tunn.0.send(u8::from(ssl)).await?;
        let tunnel_res = tokio::time::timeout(
            Duration::from_millis(state.get_tunnel_timeout().await),
            tunn.2.recv(),
        )
        .await;

        if let Err(_) = tunnel_res {
            tracing::error!("Tunnel timeout");
            return Ok(());
        }

        let mut tunnel = tunnel_res??;
        tunnel.write_all(&in_buffer[..n]).await?; // relay the first packet
        _ = tokio::io::copy_bidirectional(&mut stream, &mut tunnel).await;
        _ = tunnel.shutdown().await;
        _ = stream.shutdown().await;
    }
    Ok(())
}

async fn get_tunn_or_error<T>(
    state: &SharedProxyState,
    host: &str,
    stream: &mut T,
) -> Result<(TunnelEntry, u128)>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let tunn = match get_tunn(&state, &host).await {
        Ok(tunn) => tunn,
        Err(TunnelError::TunnelDoesNotExist) => {
            _ = ::utils::http::write_raw_http_resp(
                stream,
                404,
                "NOT FOUND",
                "That tunnel does not exists!",
            )
            .await;
            anyhow::bail!("Tunnel does not exist!");
        }
        Err(TunnelError::NoConnectorForTunnel) => {
            _ = ::utils::http::write_raw_http_resp(
                stream,
                404,
                "NOT FOUND",
                "Connector for this tunnel isn't connected!",
            )
            .await;
            anyhow::bail!("No connector for tunnel!");
        }
        _ => {
            anyhow::bail!("Error getting tunnel!");
        }
    };

    Ok(tunn)
}

async fn get_tunn(
    state: &SharedProxyState,
    host: &str,
) -> Result<(TunnelEntry, u128), TunnelError> {
    let token = state
        .get_client_token(&host)
        .await
        .ok_or_else(|| TunnelError::TunnelDoesNotExist)?;

    let tunn = state
        .get_tunnel_entry(token)
        .await
        .ok_or_else(|| TunnelError::NoConnectorForTunnel)?;

    Ok((tunn, token))
}

async fn serve_panel<T>(
    stream: &mut T,
    in_buffer: [u8; 8192],
    n: usize,
    state: &SharedProxyState,
) -> Result<()>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let mut lines = in_buffer[..n].lines();
    let http_header = lines
        .next_line()
        .await?
        .ok_or_else(|| anyhow!("No http header!"))?;
    let http_header = http_header.split_whitespace().collect::<Vec<&str>>();

    if http_header[1].starts_with("/create") && http_header[0] == "POST" {
        let query = http_header[1]
            .split("?")
            .nth(1)
            .ok_or_else(|| anyhow!("No url query!"))?;

        let search: HashMap<&str, &str> = query
            .split("&")
            .map(|x| x.split("=").collect::<Vec<&str>>())
            .map(|x| (x[0], x[1]))
            .collect();

        let url = search.get("url").ok_or_else(|| anyhow!("No url!"))?;
        let (hash, token) = state.generate_new_client(*url).await?;

        let body = format!(
            "{{\"url\":\"{}\",\"hash\":\"{}\",\"token\":\"{}\"}}",
            url, hash, token
        );

        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );

        stream.write_all(response.as_bytes()).await?;
    } else if http_header[1] == "/" && http_header[0] == "GET" {
        _ = ::utils::http::write_raw_http_resp(stream, 200, "OK", STATIC_HTML).await;
    } else {
        _ = ::utils::http::write_raw_http_resp(
            stream,
            404,
            "NOT FOUND",
            "That page does not exists!",
        )
        .await;
        return Ok(());
    }
    Ok(())
}
