use anyhow::Result;
use clap::{command, Parser};
use std::sync::Arc;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

#[derive(Parser, Debug, Clone)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short, long, default_value = "v1.filipton.space:6969", env = "PROXY")]
    proxy_addr: String,

    #[arg(short, long, default_value = "127.0.0.1:80", env = "LOCAL_ADDR")]
    addr: String,

    /*
    For now its not supported

    #[arg(short, long, default_value = "127.0.0.1:443", env = "LOCAL_SSL")]
    ssl: String,
    */
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
    let args = Args::parse();

    let cert = rcgen::generate_simple_self_signed(vec!["proxy.lan".to_string()])?;
    println!("params: {:?}", cert.get_params().alg);
    let crt = ::utils::certs::cert_from_str(&cert.serialize_pem()?)?;
    let key = ::utils::certs::key_from_str(&cert.serialize_private_key_pem())?;

    let config = tokio_rustls::rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(crt, key)?;

    let acceptor = Arc::new(tokio_rustls::TlsAcceptor::from(Arc::new(config)));

    let stream = TcpStream::connect(&args.proxy_addr).await?;
    let mut stream = acceptor.accept(stream).await?;
    let mut hello_packet = ::utils::generate_hello_packet(0, &args.token, &args.hash)?;

    stream.write_all(&hello_packet).await?;
    let domain = ::utils::read_string_from_stream(&mut stream).await?;
    println!("Access through: http://{}", domain);

    hello_packet[0] = 0x01; // 0x01 - tunnel
    loop {
        // TODO: make this as normal read, then iterate over res (n) times
        _ = stream.read_u8().await?;
        //let ssl = res == 0x01;

        tokio::task::spawn(spawn_tunnel(
            hello_packet,
            args.addr.to_string(),
            args.proxy_addr.to_string(),
            args.redirect_ssl,
            domain.to_string(),
            acceptor.clone(),
        ));
    }

    // Ok(())
}

async fn spawn_tunnel(
    hello_packet: [u8; 80],
    local_addr: String,
    proxy_addr: String,
    redirect_ssl: bool,
    domain: String,
    acceptor: Arc<tokio_rustls::TlsAcceptor>,
) -> Result<()> {
    let tunnel_stream = TcpStream::connect(proxy_addr).await?;
    tunnel_stream.set_nodelay(true)?;
    let mut tunnel_stream = acceptor.accept(tunnel_stream).await?;
    tunnel_stream.write_all(&hello_packet).await?;

    let mut local_stream = TcpStream::connect(local_addr).await?;
    local_stream.set_nodelay(true)?;

    if redirect_ssl {
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
        let redirect = ::utils::http::construct_http_redirect(&format!("https://{domain}{path}"));
        tunnel_stream.write_all(redirect.as_bytes()).await?;
    } else {
        tokio::io::copy_bidirectional(&mut local_stream, &mut tunnel_stream).await?;
    }

    Ok(())
}
