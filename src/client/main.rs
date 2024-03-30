use anyhow::Result;
use clap::{command, Parser};
use rcgen::CertifiedKey;
use std::sync::Arc;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use utils::{
    certs::{cert_from_str, key_from_str},
    generate_hello_packet,
    http::construct_http_redirect,
    read_string_from_stream,
};

#[derive(Parser, Debug, Clone)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short, long, default_value = "v1.filipton.space:6969", env = "PROXY")]
    proxy_addr: String,

    #[arg(short, long, default_value = "127.0.0.1:80", env = "ADDR")]
    addr: String,

    #[arg(long, env = "HASH")]
    hash: u64,

    #[arg(short, long, env = "TOKEN")]
    token: u128,

    #[arg(short, long, action, env = "REDIRECT_SSL")]
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
    let CertifiedKey { cert, key_pair } = rcgen::generate_simple_self_signed(vec!["proxy.lan".to_string()])?;
    let crt = cert_from_str(&cert.pem())?;
    let key = key_from_str(&key_pair.serialize_pem())?;

    let config = tokio_rustls::rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(crt, key)?;

    let acceptor = Arc::new(tokio_rustls::TlsAcceptor::from(Arc::new(config)));

    let stream = TcpStream::connect(&args.proxy_addr).await?;
    let mut stream = acceptor.accept(stream).await?;
    let mut hello_packet = generate_hello_packet(0, &args.token, &args.hash)?;

    stream.write_all(&hello_packet).await?;
    let domain = read_string_from_stream(&mut stream).await?;
    tracing::info!("Access through: http://{}", domain);

    hello_packet[0] = 0x01; // 0x01 - tunnel

    let mut void = [0u8; 1000];
    loop {
        let n = stream.read(&mut void).await?;
        for i in 0..n {
            let ssl = void[i] == 0x01;

            let addr = args.addr.to_string();
            let proxy_addr = args.proxy_addr.to_string();
            let redirect_to_ssl = args.redirect_ssl && !ssl;
            let domain = domain.to_string();
            let acceptor = acceptor.clone();

            tokio::task::spawn(async move {
                let res = spawn_tunnel(
                    hello_packet,
                    addr,
                    proxy_addr,
                    redirect_to_ssl,
                    domain,
                    acceptor,
                )
                .await;

                if let Err(e) = res {
                    tracing::error!("Tunnel Error: {e}");
                }
            });
        }
    }
}

async fn spawn_tunnel(
    hello_packet: [u8; 80],
    local_addr: String,
    proxy_addr: String,
    redirect_to_ssl: bool,
    domain: String,
    acceptor: Arc<tokio_rustls::TlsAcceptor>,
) -> Result<()> {
    let tunnel_stream = TcpStream::connect(proxy_addr).await?;
    tunnel_stream.set_nodelay(true)?;
    let mut tunnel_stream = acceptor.accept(tunnel_stream).await?;
    tunnel_stream.write_all(&hello_packet).await?;

    let mut local_stream = TcpStream::connect(local_addr).await?;
    local_stream.set_nodelay(true)?;

    if redirect_to_ssl {
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
        let path = parts[1];
        let redirect = construct_http_redirect(&format!("https://{domain}{path}"));
        tunnel_stream.write_all(redirect.as_bytes()).await?;
        _ = tunnel_stream.shutdown().await;
    } else {
        _ = tokio::io::copy_bidirectional(&mut local_stream, &mut tunnel_stream).await;
        _ = tunnel_stream.shutdown().await;
        _ = local_stream.shutdown().await;
    }

    Ok(())
}
