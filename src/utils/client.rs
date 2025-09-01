use anyhow::{Result, anyhow};
use quinn::{ClientConfig, Connection, Endpoint, crypto::rustls::QuicClientConfig};
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::TcpStream,
    time::Instant,
};
use tokio_rustls::TlsConnector;

use crate::utils::{
    ConnectorPacket, ConnectorPacketType, ConnectorStream, HelloPacket, HelloPacketType,
    certs::{NoCertVerification, SkipQuicServerVerification},
    http::write_http_resp,
    read_string_from_stream,
    ssh::{SshPacketHeader, SshPacketType},
};

pub struct Options {
    pub proxy: SocketAddr,
    pub local: SocketAddr,
    pub local_ssl: Option<SocketAddr>,
    pub token: u128,
    pub redirect_ssl: bool,
    pub serve_files: bool,
    pub files_index: bool,
    pub quic: bool,
    pub ssh_cmd: Option<String>,

    pub consts: Consts,
}

#[derive(Debug, Clone)]
pub struct Consts {
    pub max_req_time: u128,
    pub error_html: &'static str,
    pub list_html: &'static str,
}

#[derive(Debug)]
#[allow(dead_code)]
struct TunnelSettings {
    proxy_addr: SocketAddr,
    ssl_addr: SocketAddr,
    nonssl_addr: SocketAddr,
    use_quic: bool,
    ssh_cmd: Option<String>,

    serve_files: bool,
    files_index: bool,

    consts: Arc<Consts>,
}

#[derive(Clone)]
struct ConnectionOpener {
    quic_endpoint: Endpoint,
    quic_connection: Option<Connection>,
    tls_connector: Arc<TlsConnector>,
}

pub async fn spawn_connector(options: Options) {
    loop {
        if let Err(e) = connector(&options).await {
            tracing::error!("Connector error: {e}");
        }

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
}

async fn connector(options: &Options) -> Result<()> {
    let mut endpoint = Endpoint::client(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))?;
    endpoint.set_default_client_config(ClientConfig::new(Arc::new(QuicClientConfig::try_from(
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(SkipQuicServerVerification::new())
            .with_no_client_auth(),
    )?)));

    let config = tokio_rustls::rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoCertVerification))
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));

    let mut opener = ConnectionOpener {
        quic_endpoint: endpoint,
        quic_connection: None,
        tls_connector: Arc::new(connector),
    };

    if options.quic {
        opener.quic_connection = Some(
            opener
                .quic_endpoint
                .connect(options.proxy, "proxy.lan")?
                .await?,
        );
    }

    let opener = Arc::new(opener);
    let mut stream = if options.quic {
        let quic_bi = opener
            .quic_connection
            .as_ref()
            .ok_or(anyhow!("Quic Connection ref get"))?
            .open_bi()
            .await
            .map_err(|e| anyhow!("failed to open stream: {}", e))?;

        ConnectorStream::Quic(quic_bi)
    } else {
        let stream = TcpStream::connect(&options.proxy).await?;
        stream.set_nodelay(true)?;
        let stream = opener
            .tls_connector
            .connect(
                rustls::pki_types::ServerName::try_from("proxy.lan")?,
                stream,
            )
            .await?;

        ConnectorStream::TcpTlsClient(Box::new(stream))
    };

    let mut buf = [0; ConnectorPacket::buf_size()];

    let mut hello_packet = HelloPacket {
        hp_type: HelloPacketType::Connector,
        token: options.token,
        own_ssl: options.local_ssl.is_some(),
        redirect_ssl: options.redirect_ssl,
        tunnel_id: 0,
    };

    stream.write_all(&hello_packet.to_buf()).await?;
    let res = stream.read_exact(&mut buf).await;
    if res.is_err() {
        tracing::error!("Connector read error: {res:?}. Closing connection.");
        return Ok(());
    }
    let packet = ConnectorPacket::from_buf(&buf);
    match packet.packet_type {
        ConnectorPacketType::ConnectorConnected => {}
        ConnectorPacketType::Close => {
            let reason = read_string_from_stream(&mut stream).await?;
            tracing::error!("Closing connector! Close reason: {reason}");
            return Ok(());
        }
        _ => {
            tracing::error!("Closing connector! Wrong packet response!");
            return Ok(());
        }
    }

    let nonssl_port = stream.read_u16().await?;
    let ssl_port = stream.read_u16().await?;
    let domain = read_string_from_stream(&mut stream).await?;
    tracing::info!(
        "Access through:\n - http://{domain}:{nonssl_port}\n - https://{domain}:{ssl_port}"
    );

    hello_packet.hp_type = HelloPacketType::Tunnel;

    let mut last_ping = tokio::time::interval_at(
        Instant::now() + Duration::from_secs(30),
        Duration::from_secs(30),
    );

    let consts = Arc::new(options.consts.clone());
    loop {
        tokio::select! {
            res = stream.read_exact(&mut buf) => {
                if res.is_err() {
                    tracing::error!("Connector read error: {res:?}. Closing connection.");
                    return Ok(());
                }

                let packet = ConnectorPacket::from_buf(&buf);
                if packet.packet_type == ConnectorPacketType::Ping {
                    stream.write_u8(0x69).await?;
                    last_ping.reset();

                    continue; // ping/pong
                } else if packet.packet_type == ConnectorPacketType::Close {
                    let reason = read_string_from_stream(&mut stream).await?;
                    tracing::error!("Closing connector! Close reason: {reason}");
                    return Ok(());
                }

                let opener = opener.clone();
                let requested_time = Instant::now();
                let settings = TunnelSettings {
                    proxy_addr: options.proxy,
                    ssl_addr: options.local_ssl.unwrap_or(options.local),
                    nonssl_addr: options.local,
                    use_quic: options.quic,
                    ssh_cmd: options.ssh_cmd.clone(),

                    serve_files: options.serve_files,
                    files_index: options.files_index,
                    consts: consts.clone()
                };

                hello_packet.tunnel_id = packet.tunnel_id;
                let hello_packet = hello_packet.to_buf();

                tokio::task::spawn(async move {
                    let res = if packet.ssh {
                        spawn_ssh_tunnel(
                            opener,
                            hello_packet,
                            settings,
                            requested_time,
                        )
                            .await
                    } else {
                        spawn_tunnel(
                            opener,
                            hello_packet,
                            settings,
                            packet.ssl,
                            requested_time,
                        )
                            .await
                    };

                    if let Err(e) = res {
                        tracing::error!("Tunnel Error: {e}");
                    }
                });
            }
            _ = last_ping.tick() => {
                tracing::error!("No ping for 30s! Closing connector");
                return Ok(());
            }
        }
    }
}

async fn establish_connection(
    opener: Arc<ConnectionOpener>,
    hello_packet: [u8; HelloPacket::buf_size()],
    settings: &TunnelSettings,
    request_time: Instant,
) -> Result<ConnectorStream> {
    if request_time.elapsed().as_millis() > settings.consts.max_req_time {
        return Err(anyhow!("Requested time exceeded max request time."));
    }

    let mut tunnel_stream = if settings.use_quic {
        let quic_bi = opener
            .quic_connection
            .as_ref()
            .ok_or(anyhow::anyhow!("Quic Connection ref get"))?
            .open_bi()
            .await
            .map_err(|e| anyhow!("failed to open stream: {}", e))?;
        ConnectorStream::Quic(quic_bi)
    } else {
        let stream = TcpStream::connect(settings.proxy_addr).await?;
        stream.set_nodelay(true)?;
        let stream = opener
            .tls_connector
            .connect(
                rustls::pki_types::ServerName::try_from("proxy.lan")?,
                stream,
            )
            .await?;

        ConnectorStream::TcpTlsClient(Box::new(stream))
    };

    tunnel_stream.write_all(&hello_packet).await?;
    Ok(tunnel_stream)
}

async fn spawn_tunnel(
    opener: Arc<ConnectionOpener>,
    hello_packet: [u8; HelloPacket::buf_size()],
    settings: TunnelSettings,
    ssl: bool,
    request_time: Instant,
) -> Result<()> {
    let mut tunnel_stream =
        establish_connection(opener, hello_packet, &settings, request_time).await?;

    if settings.serve_files {
        _ = super::serve::serve_files(&mut tunnel_stream, settings.files_index, &settings.consts)
            .await;
        tunnel_stream.flush().await?;
        _ = tunnel_stream.shutdown().await;
        return Ok(());
    }

    let local_addr = match ssl {
        true => settings.ssl_addr,
        false => settings.nonssl_addr,
    };

    let Ok(mut local_stream) = TcpStream::connect(local_addr).await else {
        write_http_resp(
            &mut tunnel_stream,
            500,
            &settings
                .consts
                .error_html
                .replace("{MSG}", "Local server not running!"),
            "text/html",
        )
        .await?;
        _ = tunnel_stream.shutdown().await;

        return Ok(());
    };

    local_stream.set_nodelay(true)?;
    _ = tokio::io::copy_bidirectional(&mut local_stream, &mut tunnel_stream).await;
    _ = local_stream.shutdown().await;
    _ = tunnel_stream.shutdown().await;
    Ok(())
}

async fn spawn_ssh_tunnel(
    opener: Arc<ConnectionOpener>,
    hello_packet: [u8; HelloPacket::buf_size()],
    settings: TunnelSettings,
    request_time: Instant,
) -> Result<()> {
    let mut tunnel_stream =
        establish_connection(opener, hello_packet, &settings, request_time).await?;

    let mut header_buf = [0; SshPacketHeader::HEADER_LENGTH];
    let mut buf = [0u8; 4096];
    tunnel_stream.read_exact(&mut header_buf).await?;
    let header = SshPacketHeader::from_buf(&header_buf);

    let tunnel_user = if header.packet_type == SshPacketType::User {
        tunnel_stream
            .read_exact(&mut buf[..header.length as usize])
            .await?;

        core::str::from_utf8(&buf[..header.length as usize])?
    } else {
        return Err(anyhow!("Wrong first ssh tunnel packet!"));
    };

    let (mut pty, pts) = pty_process::open().unwrap();
    let cmd = pty_process::Command::new("bash").env("PROXY_USER", tunnel_user);
    let mut child = cmd.spawn(pts).unwrap();

    loop {
        tokio::select! {
            recv = tunnel_stream.read_exact(&mut header_buf) => {
                if let Ok(n) = recv {
                    if n == 0 {
                        break;
                    }
                    /*

                            let rows = stream.read_u16().await?;
                            let cols = stream.read_u16().await?;
                            pty.resize(pty_process::Size::new(rows, cols)).unwrap();
                        },
                        1 => {
                            let n = stream.read_u16().await? as usize;
                            let mut buf = vec![0; n];
                            stream.read_exact(&mut buf[..n]).await?;
                            pty.write_all(&buf[..n]).await.unwrap();
                    */

                    let header = SshPacketHeader::from_buf(&header_buf);
                    match header.packet_type {
                        crate::utils::ssh::SshPacketType::PtyResize => {
                            let rows = tunnel_stream.read_u16().await?;
                            let cols = tunnel_stream.read_u16().await?;
                            pty.resize(pty_process::Size::new(rows, cols)).unwrap();
                        },
                        crate::utils::ssh::SshPacketType::Data => {
                            let mut rem = header.length as usize;

                            while rem > 0 {
                                let read_n = rem.min(4096);
                                tunnel_stream.read_exact(&mut buf[..read_n]).await.unwrap();
                                pty.write_all(&buf[..read_n]).await.unwrap();

                                rem -= read_n;
                            }

                        },
                        _ => {}
                    }
                }
            }
            res = pty.read(&mut buf) => {
                if let Ok(n) = res {
                    if n == 0 {
                        break;
                    }

                    tunnel_stream
                        .write_all(
                            &SshPacketHeader {
                                packet_type: super::ssh::SshPacketType::Data,
                                length: n as u32,
                            }
                            .to_buf(),
                        )
                        .await?;
                    tunnel_stream.write_all(&buf[..n]).await?;
                } else {
                    break;
                }
            }
            p_res = child.wait() => {
                if p_res.is_err() {
                    break;
                }

                let _p_res = p_res.unwrap();
                break;
            }
        }
    }

    _ = tunnel_stream.shutdown().await;
    Ok(())
}
