use crate::structs::{SharedProxyState, TunnelError, TunnelGetResult, TunnelRequest, TunnelSender};
use anyhow::{Result, anyhow};
use fkm_proxy::utils::{
    ConnectorPacket, ConnectorPacketType, ConnectorStream, HelloPacket, HelloPacketType,
    send_string_to_stream,
};
use kanal::AsyncReceiver;
use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tokio_rustls::{TlsAcceptor, rustls::pki_types};

const PANEL_HTML: &str = include_str!("./resources/index.html");
const ERROR_HTML: &str = include_str!("./resources/error.html");

pub async fn spawn_tunnel_connector(
    remote_addrs: Vec<(SocketAddr, bool)>,
    connector_addr: SocketAddr,
    shared_proxy_state: SharedProxyState,
) -> Result<()> {
    for remote_addr in remote_addrs {
        let shared_proxy_state = shared_proxy_state.clone();

        tokio::task::spawn(async move {
            let res = remote_listener(remote_addr.0, shared_proxy_state, remote_addr.1).await;
            if let Err(e) = res {
                tracing::error!("[{}] Remote listener error: {e}", remote_addr.0);
            }
        });
    }

    let shared_proxy_state_c = shared_proxy_state.clone();
    tokio::task::spawn(async move {
        let res = connector_listener_tcp(connector_addr, shared_proxy_state_c).await;
        if let Err(e) = res {
            tracing::error!("Tcp connector listener error: {e}");
        }
    });

    tokio::task::spawn(async move {
        let res = connector_listener_udp(connector_addr, shared_proxy_state).await;
        if let Err(e) = res {
            tracing::error!("Udp connector listener error: {e}");
        }
    });

    Ok(())
}

async fn connector_listener_tcp(addr: SocketAddr, state: SharedProxyState) -> Result<()> {
    tracing::info!("[TCP] Connector listening on: {addr}");
    let listener = TcpListener::bind(addr).await?;
    let acceptor = state.get_tls_acceptor().await;

    loop {
        let (stream, remote_addr) = listener.accept().await?;
        stream.set_nodelay(true)?;

        let state = state.clone();
        let acceptor = acceptor.clone();
        tokio::task::spawn(async move {
            let res = connector_handler_tcp(stream, state, acceptor).await;
            if let Err(e) = res {
                tracing::error!("[TCP] Connector handler from {remote_addr} error: {e}");
            }
        });
    }
}

async fn connector_listener_udp(addr: SocketAddr, state: SharedProxyState) -> Result<()> {
    tracing::info!("Udp connector listening on: {addr}");

    let (certs, key) = {
        let cert = rcgen::generate_simple_self_signed(vec!["proxy.local".into()])?;
        let key = pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der());
        let key: pki_types::PrivateKeyDer = key.into();
        let cert: pki_types::CertificateDer = cert.cert.into();
        (vec![cert], key)
    };

    let server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;

    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)?,
    ));

    let transport_config = Arc::get_mut(&mut server_config.transport)
        .ok_or(anyhow::anyhow!("Transport config arc get_mut error"))?;
    transport_config.max_concurrent_uni_streams(0_u8.into());

    let endpoint = quinn::Endpoint::server(server_config, addr)?;

    while let Some(conn) = endpoint.accept().await {
        let fut = handle_quic_connection(conn, state.clone());
        tokio::spawn(async move {
            if let Err(e) = fut.await {
                tracing::error!("[QUIC] Connection failed: {e}")
            }
        });
    }

    Ok(())
}

async fn handle_quic_connection(conn: quinn::Incoming, state: SharedProxyState) -> Result<()> {
    let connection = conn.await?;
    let remote_addr = connection.remote_address();

    loop {
        let stream = connection.accept_bi().await;
        let stream = match stream {
            Err(quinn::ConnectionError::ApplicationClosed { .. }) => {
                tracing::info!("[QUIC] Connection from {remote_addr} closed");
                return Ok(());
            }
            Err(e) => {
                return Err(e.into());
            }
            Ok(s) => s,
        };

        let fut = connector_handler(ConnectorStream::Quic(stream), state.clone());
        tokio::spawn(async move {
            if let Err(e) = fut.await {
                tracing::error!("[QUIC] Connector handler from {remote_addr} failed: {e}");
            }
        });
    }
}

async fn connector_handler_tcp(
    stream: TcpStream,
    state: SharedProxyState,
    acceptor: Arc<TlsAcceptor>,
) -> Result<()> {
    let stream = ConnectorStream::TcpTlsServer(Box::new(acceptor.accept(stream).await?));
    connector_handler(stream, state).await
}

#[inline(always)]
async fn connector_handler(mut stream: ConnectorStream, state: SharedProxyState) -> Result<()> {
    let mut connection_buff = [0u8; HelloPacket::buf_size()];
    stream.read_exact(&mut connection_buff).await?;

    let hello_packet = ::fkm_proxy::utils::HelloPacket::from_buf(&connection_buff);
    let Ok(domain) = state
        .get_domain_by_token(hello_packet.token)
        .await
        .ok_or_else(|| fkm_proxy::utils::HelloPacketError::TokenMismatch)
    else {
        _ = stream
            .write_all(
                &ConnectorPacket {
                    packet_type: ConnectorPacketType::Close,
                    tunnel_id: 0,
                    ssl: false,
                }
                .to_buf(),
            )
            .await;
        _ = send_string_to_stream(&mut stream, "Wrong token").await;
        _ = stream.flush().await;

        tracing::warn!("Closing tunnel with reason: Wrong token");
        tokio::time::sleep(Duration::from_millis(100)).await;
        stream.shutdown().await;
        return Ok(());
    };

    // im the connector!
    if hello_packet.hp_type == HelloPacketType::Connector {
        tracing::info!(
            "Connector({}) connected to url with domain: {domain}",
            stream.get_name()
        );

        _ = stream
            .write_all(
                &ConnectorPacket {
                    packet_type: ConnectorPacketType::ConnectorConnected,
                    tunnel_id: 0,
                    ssl: false,
                }
                .to_buf(),
            )
            .await;
        stream.write_u16(state.consts.nonssl_port).await?;
        stream.write_u16(state.consts.ssl_port).await?;
        fkm_proxy::utils::send_string_to_stream(&mut stream, &domain).await?;

        let (tx, rx) = kanal::unbounded_async::<TunnelRequest>();
        state
            .insert_tunnel_connector(hello_packet.token, tx, hello_packet.own_ssl)
            .await;

        let res = connector_loop(&mut stream, rx).await;
        if let Err(ref e) = res {
            tracing::error!("Connector loop: {e:?}");
        }

        if matches!(res, Ok(true)) {
            state.remove_tunnel(hello_packet.token).await;
        }
        stream.shutdown().await;
    } else if hello_packet.hp_type == HelloPacketType::Tunnel {
        // im the tunnel!
        let tx = state
            .get_tunnel_oneshot(hello_packet.tunnel_id)
            .await
            .ok_or_else(|| anyhow!("Cant find tunnel with that id (probably after timeout)!"))?;

        _ = tx.send(stream);
    }

    Ok(())
}

async fn connector_loop(
    stream: &mut ConnectorStream,
    rx: AsyncReceiver<TunnelRequest>,
) -> Result<bool> {
    let mut pinger = tokio::time::interval(Duration::from_secs(15));
    loop {
        tokio::select! {
            res = rx.recv() => {
                let res = res?;
                match res {
                    TunnelRequest::Close(reason) => {
                        _ = stream.write_all(&ConnectorPacket {
                            packet_type: ConnectorPacketType::Close,
                            tunnel_id: 0,
                            ssl: false,
                        }.to_buf()).await;
                        _ = send_string_to_stream(stream, &reason).await;
                        _ = stream.flush().await;

                        tracing::warn!("Closing tunnel with reason: {reason}");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        return Ok(false)
                    },
                    TunnelRequest::Request { ssl, tunnel_id } => {
                        stream.write_all(&ConnectorPacket {
                            packet_type: ConnectorPacketType::TunnelRequest,
                            tunnel_id,
                            ssl,
                        }.to_buf()).await?;
                    }
                }
            }
            res = stream.read_u8() => {
                if res.is_err() {
                    return Ok(true);
                }
            }
            _ = pinger.tick() => {
                stream.write_all(&ConnectorPacket {
                    packet_type: ConnectorPacketType::Ping,
                    tunnel_id: 0,
                    ssl: false,
                }.to_buf()).await?;

                let read = stream.read_u8().await?;
                if read != 0x69 {
                    tracing::error!("Wrong pong response: {:x}", read);
                    _ = stream.shutdown().await;
                    return Ok(true);
                }
            }
        }
    }
}

async fn remote_listener(addr: SocketAddr, state: SharedProxyState, ssl: bool) -> Result<()> {
    tracing::info!("Remote listening on: {addr} (SSL: {ssl})");
    let listener = TcpListener::bind(addr).await?;
    let acceptor = state.get_tls_remote_acceptor().await;

    loop {
        let (stream, _) = listener.accept().await?;
        stream.set_nodelay(true)?;

        let state = state.clone();
        let acceptor = acceptor.clone();
        tokio::task::spawn(async move {
            let res = handle_http_client(stream, state, ssl, acceptor).await;
            if let Err(e) = res {
                tracing::error!("Handle client error: {e}");
            }
        });
    }
}

async fn handle_http_client(
    mut stream: TcpStream,
    state: SharedProxyState,
    ssl: bool,
    acceptor: Arc<TlsAcceptor>,
) -> Result<()> {
    let host = match get_host(&mut stream, ssl).await {
        Ok(host) => host,
        Err(_) => return Ok(()),
    };

    let tunn_res = get_host_tunnel(&state, &host).await;
    let own_ssl = tunn_res.as_ref().map(|x| x.own_ssl).unwrap_or(false);

    if ssl {
        if own_ssl {
            handle_client_inner(stream, state, tunn_res, &host, true).await?;
        } else {
            let stream = acceptor.accept(stream).await?;
            handle_client_inner(stream, state, tunn_res, &host, true).await?;
        }
    } else {
        handle_client_inner(stream, state, tunn_res, &host, false).await?;
    }

    Ok(())
}

async fn get_host(stream: &mut TcpStream, ssl: bool) -> Result<String> {
    let mut in_buffer = [0; 4096];
    let n = stream.peek(&mut in_buffer).await?;
    let host = if ssl {
        qls_proto_utils::tls::sni::parse_sni(&in_buffer[..n])
            .ok_or_else(|| anyhow!("Server name not found in TLS initial handshake"))?
            .to_string()
    } else {
        let host = ::fkm_proxy::utils::read_http_host(&in_buffer[..n])?;
        let host = host
            .split(":")
            .next()
            .ok_or(anyhow::anyhow!("Host port doesnt exists."))?; // remove port from host

        host.to_owned()
    };

    Ok(host)
}

async fn handle_client_inner<T>(
    mut stream: T,
    state: SharedProxyState,
    tunn_res: TunnelGetResult,
    host: &str,
    ssl: bool,
) -> Result<()>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    if state.is_host_panel(host) {
        let mut in_buffer = [0; 8192];
        let n = stream.read(&mut in_buffer).await?;
        serve_panel(&mut stream, &in_buffer[..n], &state).await?;
        return Ok(());
    }

    if let Ok(tunn) = get_tunn_or_error(tunn_res, &mut stream).await {
        let mut generated_tunnel_id = [0u8; 16];
        state
            .consts
            .rng
            .secure_random
            .fill(&mut generated_tunnel_id)
            .map_err(|_| anyhow::anyhow!("Rng fill error"))?;

        let generated_tunnel_id = u128::from_be_bytes(generated_tunnel_id);

        let (tx, rx) = tokio::sync::oneshot::channel();
        state.insert_tunnel_oneshot(generated_tunnel_id, tx).await;

        tunn.send(TunnelRequest::Request {
            ssl,
            tunnel_id: generated_tunnel_id,
        })
        .await?;

        let tunnel_res =
            tokio::time::timeout(Duration::from_millis(state.get_tunnel_timeout().await), rx).await;

        if tunnel_res.is_err() {
            _ = state.get_tunnel_oneshot(generated_tunnel_id).await;

            _ = ::fkm_proxy::utils::http::write_http_resp(
                &mut stream,
                404,
                &ERROR_HTML.replace(
                    "{MSG}",
                    &format!("Tunnel timeout! REF ID: {generated_tunnel_id}"),
                ),
                "text/html",
            )
            .await;
            tracing::error!("Tunnel timeout (REF ID: {generated_tunnel_id})");

            return Ok(());
        }

        let mut tunnel = tunnel_res??;
        _ = tokio::io::copy_bidirectional(&mut stream, &mut tunnel).await;
        _ = tunnel.shutdown().await;
    }

    _ = stream.shutdown().await;
    Ok(())
}

async fn get_tunn_or_error<T>(tunn_res: TunnelGetResult, stream: &mut T) -> Result<TunnelSender>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let tunn = match tunn_res {
        Ok(tunn) => tunn,
        Err(TunnelError::TunnelDoesNotExist) => {
            _ = ::fkm_proxy::utils::http::write_http_resp(
                stream,
                404,
                &ERROR_HTML.replace("{MSG}", "This tunnel does not exists!"),
                "text/html",
            )
            .await;
            anyhow::bail!("Tunnel does not exist!");
        }
        Err(TunnelError::NoConnectorForTunnel) => {
            _ = ::fkm_proxy::utils::http::write_http_resp(
                stream,
                404,
                &ERROR_HTML.replace("{MSG}", "Connector for this tunnel isn't connected!"),
                "text/html",
            )
            .await;
            anyhow::bail!("No connector for tunnel!");
        }
        _ => {
            anyhow::bail!("Error getting tunnel!");
        }
    };

    Ok(tunn.sender)
}

async fn get_host_tunnel(state: &SharedProxyState, host: &str) -> TunnelGetResult {
    let token = state
        .get_client_token(host)
        .await
        .ok_or_else(|| TunnelError::TunnelDoesNotExist)?;

    let tunn = state
        .get_tunnel_entry(token)
        .await
        .ok_or_else(|| TunnelError::NoConnectorForTunnel)?;

    Ok(tunn)
}

async fn serve_panel<T>(stream: &mut T, in_buffer: &[u8], state: &SharedProxyState) -> Result<()>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let mut lines = in_buffer.lines();
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
        let token = state.generate_new_client(url).await?;

        let body = format!("{{\"url\":\"{url}\",\"token\":\"{token}\"}}");
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
            body.len(),
        );

        stream.write_all(response.as_bytes()).await?;
    } else if http_header[1] == "/" && http_header[0] == "GET" {
        _ = fkm_proxy::utils::http::write_http_resp(stream, 200, PANEL_HTML, "text/html").await;
    } else {
        _ = fkm_proxy::utils::http::write_http_resp(
            stream,
            404,
            "That page does not exists!",
            "text/html",
        )
        .await;
        return Ok(());
    }
    Ok(())
}
