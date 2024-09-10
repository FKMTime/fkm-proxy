use anyhow::{anyhow, Result};
use clap::{command, Parser};
use rcgen::CertifiedKey;
use std::{net::SocketAddr, sync::Arc};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::Instant,
};
use utils::{
    certs::{cert_from_str, key_from_str},
    generate_hello_packet,
    http::construct_http_redirect,
    parse_socketaddr, read_string_from_stream,
};

const MAX_REQUEST_TIME: u128 = 1000;

#[derive(Parser, Debug, Clone)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short, long, value_parser = parse_socketaddr, default_value = "v1.filipton.space:6969", env = "PROXY")]
    proxy_addr: SocketAddr,

    #[arg(short, long, value_parser = parse_socketaddr, default_value = "127.0.0.1:80", env = "ADDR")]
    addr: SocketAddr,

    #[arg(long, value_parser = parse_socketaddr, env = "SSL_ADDR")]
    ssl_addr: Option<SocketAddr>,

    #[arg(long, env = "HASH")]
    hash: u64,

    #[arg(short, long, env = "TOKEN")]
    token: u128,

    #[arg(short, long, action, env = "REDIRECT_SSL")]
    redirect_ssl: bool,
}

#[derive(Debug)]
struct TunnelSettings {
    proxy_addr: SocketAddr,
    ssl_addr: SocketAddr,
    nonssl_addr: SocketAddr,
    redirect_ssl: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    _ = dotenvy::dotenv();
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    loop {
        if let Err(e) = connector(&args).await {
            tracing::error!("Connector error: {e}");
        }

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }

    // Ok(())
}

async fn connector(args: &Args) -> Result<()> {
    let CertifiedKey { cert, key_pair } =
        rcgen::generate_simple_self_signed(vec!["proxy.lan".to_string()])?;
    let crt = cert_from_str(&cert.pem())?;
    let key = key_from_str(&key_pair.serialize_pem())?;

    let config = tokio_rustls::rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(crt, key)?;

    let acceptor = Arc::new(tokio_rustls::TlsAcceptor::from(Arc::new(config)));

    let stream = TcpStream::connect(&args.proxy_addr).await?;
    let mut stream = acceptor.accept(stream).await?;
    let mut hello_packet =
        generate_hello_packet(0, &args.token, &args.hash, args.ssl_addr.is_some())?;

    stream.write_all(&hello_packet).await?;
    let nonssl_port = stream.read_u16().await?;
    let ssl_port = stream.read_u16().await?;
    let domain = read_string_from_stream(&mut stream).await?;
    tracing::info!(
        "Access through:\n - http://{domain}:{nonssl_port}\n - https://{domain}:{ssl_port}"
    );

    hello_packet[0] = 0x01; // 0x01 - tunnel

    let mut buf = [0; 16];
    loop {
        let first_byte = stream.read_u8().await?;
        if first_byte == 0x69 {
            stream.write_u8(0x69).await?;
            continue; // ping/pong
        }

        stream.read_exact(&mut buf).await?;
        let ssl = first_byte == 0x01;
        let domain = domain.to_string();
        let acceptor = acceptor.clone();
        let requested_time = Instant::now();
        let settings = TunnelSettings {
            proxy_addr: args.proxy_addr,
            ssl_addr: args.ssl_addr.unwrap_or(args.addr),
            nonssl_addr: args.addr,
            redirect_ssl: args.redirect_ssl,
        };

        hello_packet[26..42].copy_from_slice(&buf[0..16]);
        tokio::task::spawn(async move {
            let res = spawn_tunnel(
                hello_packet,
                settings,
                ssl,
                ssl_port,
                domain,
                acceptor,
                requested_time,
            )
            .await;

            if let Err(e) = res {
                tracing::error!("Tunnel Error: {e}");
            }
        });
    }
}

async fn spawn_tunnel(
    hello_packet: [u8; 80],
    settings: TunnelSettings,
    ssl: bool,
    ssl_port: u16,
    domain: String,
    acceptor: Arc<tokio_rustls::TlsAcceptor>,
    request_time: Instant,
) -> Result<()> {
    if request_time.elapsed().as_millis() > MAX_REQUEST_TIME {
        return Err(anyhow!("Requested time exceeded max request time."));
    }

    let tunnel_stream = TcpStream::connect(settings.proxy_addr).await?;
    tunnel_stream.set_nodelay(true)?;
    let mut tunnel_stream = acceptor.accept(tunnel_stream).await?;
    tunnel_stream.write_all(&hello_packet).await?;

    let local_addr = match ssl {
        true => settings.ssl_addr,
        false => settings.nonssl_addr,
    };
    let mut local_stream = TcpStream::connect(local_addr).await?;
    local_stream.set_nodelay(true)?;

    let redirect_to_ssl = settings.redirect_ssl && !ssl;
    if redirect_to_ssl {
        // for example: "GET / HTTP1.1"
        let mut buffer = [0u8; 1];
        let mut parts = String::new();
        loop {
            tunnel_stream.read(&mut buffer).await?;
            if buffer[0] == 0x0A {
                break;
            }
            parts.push(buffer[0] as char);
        }

        let parts = parts.trim().split(" ").collect::<Vec<&str>>();
        let path = parts[1].trim_end_matches('/');
        let redirect = construct_http_redirect(&format!("https://{domain}{path}:{ssl_port}"));
        tunnel_stream.write_all(redirect.as_bytes()).await?;
    } else {
        _ = tokio::io::copy_bidirectional(&mut local_stream, &mut tunnel_stream).await;
    }

    _ = tunnel_stream.shutdown().await;
    _ = local_stream.shutdown().await;

    Ok(())
}
