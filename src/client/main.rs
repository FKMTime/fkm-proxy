use anyhow::{Result, anyhow};
use clap::{Parser, command};
use fkm_proxy::utils::{
    ConnectorPacket, ConnectorPacketType, ConnectorStream, HelloPacket,
    certs::{cert_from_str, key_from_str},
    http::{construct_http_redirect, write_http_resp},
    parse_socketaddr, read_string_from_stream,
};
use quinn::{ClientConfig, Endpoint, crypto::rustls::QuicClientConfig};
use rcgen::CertifiedKey;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::Instant,
};

mod serve;

const MAX_REQUEST_TIME: u128 = 1000;
const ERROR_HTML: &str = include_str!("./resources/error.html");
const LIST_HTML: &str = include_str!("./resources/list.html");

#[derive(Parser, Debug, Clone)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short, long, value_parser = parse_socketaddr, default_value = "vps.filipton.space:6969", env = "PROXY")]
    proxy_addr: SocketAddr,

    #[arg(short, long, value_parser = parse_socketaddr, default_value = "127.0.0.1:80", env = "ADDR")]
    addr: SocketAddr,

    #[arg(long, value_parser = parse_socketaddr, env = "SSL_ADDR")]
    ssl_addr: Option<SocketAddr>,

    #[arg(short, long, env = "TOKEN")]
    token: u128,

    #[arg(short, long, action, env = "REDIRECT_SSL")]
    redirect_ssl: bool,

    #[arg(long, action, short = 'f')]
    serve_files: bool,

    #[arg(long, action, short = 'i')]
    files_index: bool,

    #[arg(long, action, env = "USE_QUIC")]
    use_quic: bool,
}

#[derive(Debug)]
#[allow(dead_code)]
struct TunnelSettings {
    proxy_addr: SocketAddr,
    ssl_addr: SocketAddr,
    nonssl_addr: SocketAddr,
    redirect_ssl: bool,

    serve_files: bool,
    files_index: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    _ = dotenvy::dotenv();
    tracing_subscriber::fmt::init();
    let args = Args::parse();
    if args.files_index && !args.serve_files {
        tracing::error!(
            "You cannot use files indexing (-i, --files-index) without enabling files serving (-f, --serve-files)!"
        );
        return Ok(());
    }

    loop {
        if let Err(e) = connector(&args).await {
            tracing::error!("Connector error: {e}");
        }

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }

    // Ok(())
}

async fn connector(args: &Args) -> Result<()> {
    let mut stream = if args.use_quic {
        let mut endpoint = Endpoint::client(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))?;
        endpoint.set_default_client_config(ClientConfig::new(Arc::new(
            QuicClientConfig::try_from(
                rustls::ClientConfig::builder()
                    .dangerous()
                    .with_custom_certificate_verifier(SkipServerVerification::new())
                    .with_no_client_auth(),
            )?,
        )));

        // TODO: add connection as Arc to be available for other threads (to open_bi in tasks),
        // also make socket inner data that will store it, and for example function to establish
        // connection on ConnectorStream
        let connection = endpoint
            .connect(args.proxy_addr, "proxy.lan")
            .unwrap()
            .await
            .unwrap();

        let quic_bi = connection
            .open_bi()
            .await
            .map_err(|e| anyhow!("failed to open stream: {}", e))?;
        ConnectorStream::Quic(quic_bi)
    } else {
        let CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec!["proxy.lan".to_string()])?;
        let crt = cert_from_str(&cert.pem())?;
        let key = key_from_str(&signing_key.serialize_pem())?;

        let config = tokio_rustls::rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(crt, key)?;

        let acceptor = Arc::new(tokio_rustls::TlsAcceptor::from(Arc::new(config)));

        let stream = TcpStream::connect(&args.proxy_addr).await?;
        ConnectorStream::TcpTlsServer(Box::new(acceptor.accept(stream).await?))
    };

    /*
     */
    let mut buf = [0; ConnectorPacket::buf_size()];

    let mut hello_packet = HelloPacket {
        hp_type: fkm_proxy::utils::HelloPacketType::Connector,
        token: args.token,
        own_ssl: args.ssl_addr.is_some(),
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

    hello_packet.hp_type = fkm_proxy::utils::HelloPacketType::Tunnel;

    let mut last_ping = tokio::time::interval_at(
        Instant::now() + Duration::from_secs(30),
        Duration::from_secs(30),
    );

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

                let domain = domain.to_string();
                //let acceptor = acceptor.clone();
                let requested_time = Instant::now();
                let settings = TunnelSettings {
                    proxy_addr: args.proxy_addr,
                    ssl_addr: args.ssl_addr.unwrap_or(args.addr),
                    nonssl_addr: args.addr,
                    redirect_ssl: args.redirect_ssl,

                    serve_files: args.serve_files,
                    files_index: args.files_index
                };

                hello_packet.tunnel_id = packet.tunnel_id;
                let hello_packet = hello_packet.to_buf();

                // FIXME: move it to spawn_tunnel, after TODO is done (from above)
                let quic_bi = connection
                    .open_bi()
                    .await
                    .map_err(|e| anyhow!("failed to open stream: {}", e))?;
                let stream = ConnectorStream::Quic(quic_bi);
                tokio::task::spawn(async move {
                    let res = spawn_tunnel(
                        stream,
                        hello_packet,
                        settings,
                        packet.ssl,
                        ssl_port,
                        domain,
                        //acceptor,
                        requested_time,
                    )
                        .await;

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

async fn spawn_tunnel(
    mut tunnel_stream: ConnectorStream,
    hello_packet: [u8; 80],
    settings: TunnelSettings,
    ssl: bool,
    ssl_port: u16,
    domain: String,
    //acceptor: Arc<tokio_rustls::TlsAcceptor>,
    request_time: Instant,
) -> Result<()> {
    if request_time.elapsed().as_millis() > MAX_REQUEST_TIME {
        return Err(anyhow!("Requested time exceeded max request time."));
    }

    /*
    let tunnel_stream = TcpStream::connect(settings.proxy_addr).await?;
    tunnel_stream.set_nodelay(true)?;
    let mut tunnel_stream = acceptor.accept(tunnel_stream).await?;
    */
    tunnel_stream.write_all(&hello_packet).await?;

    if settings.serve_files {
        _ = serve::serve_files(&mut tunnel_stream, settings.files_index).await;
        tunnel_stream.flush().await?;
        _ = tunnel_stream.shutdown().await;
        return Ok(());
    }

    let redirect_to_ssl = settings.redirect_ssl && !ssl;
    if redirect_to_ssl {
        // for example: "GET / HTTP1.1"
        let mut buffer = [0u8; 1];
        let mut parts = String::new();
        loop {
            tunnel_stream.read_exact(&mut buffer).await?;
            if buffer[0] == 0x0A {
                break;
            }
            parts.push(buffer[0] as char);
        }

        let parts = parts.trim().split(" ").collect::<Vec<&str>>();
        let path = parts[1];
        let redirect = construct_http_redirect(&format!("https://{domain}:{ssl_port}/{path}"));
        tunnel_stream.write_all(redirect.as_bytes()).await?;
    } else {
        let local_addr = match ssl {
            true => settings.ssl_addr,
            false => settings.nonssl_addr,
        };

        let Ok(mut local_stream) = TcpStream::connect(local_addr).await else {
            write_http_resp(
                &mut tunnel_stream,
                500,
                &ERROR_HTML.replace("{MSG}", "Local server not running!"),
                "text/html",
            )
            .await?;
            _ = tunnel_stream.shutdown().await;

            return Ok(());
        };

        local_stream.set_nodelay(true)?;
        _ = tokio::io::copy_bidirectional(&mut local_stream, &mut tunnel_stream).await;
        _ = local_stream.shutdown().await;
    }

    _ = tunnel_stream.shutdown().await;
    Ok(())
}

#[derive(Debug)]
struct SkipServerVerification(Arc<rustls::crypto::CryptoProvider>);

impl SkipServerVerification {
    fn new() -> Arc<Self> {
        Arc::new(Self(Arc::new(rustls::crypto::ring::default_provider())))
    }
}

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}
