use anyhow::Result;
use clap::{command, Parser};
use std::{path::Path, sync::Arc};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use tokio_rustls::TlsAcceptor;
use utils::generate_hello_packet;

mod cert;
mod utils;

#[derive(Parser, Debug, Clone)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short, long, default_value = "v1.filipton.space:6969", env = "PROXY")]
    proxy_addr: String,

    #[arg(short, long, default_value = "127.0.0.1:80", env = "LOCAL_NOSSL")]
    nossl: String,

    /*
    For now its not supported

    #[arg(short, long, default_value = "127.0.0.1:443", env = "LOCAL_SSL")]
    ssl: String,
    */
    #[arg(long, env = "HASH")]
    hash: u64,

    #[arg(short, long, env = "TOKEN")]
    token: u128,

    #[arg(short, long, env = "EMAIL")]
    email: String,

    #[arg(short, long, action, env = "REDIRECT_SSL")]
    redirect_ssl: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    _ = dotenvy::dotenv();
    let args = Args::parse();

    let (key, crt) = cert::cert_loader(
        args.token,
        args.hash,
        &args.proxy_addr,
        "/tmp/acme",
        &args.email,
    )
    .await?;

    let certs = cert::load_certs(Path::new(&crt))?;
    let privkey = cert::load_keys(Path::new(&key))?;
    let config = tokio_rustls::rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, privkey)?;

    let acceptor = TlsAcceptor::from(Arc::new(config));

    let domain = utils::get_domain_by_hash(args.hash, args.proxy_addr.to_string()).await?;

    let mut connector = TcpStream::connect(&args.proxy_addr).await?;
    let hello_packet = generate_hello_packet(0, &args.token, &args.hash);

    connector.write_all(&hello_packet).await?;

    loop {
        let res = connector.read_u8().await?;
        let ssl = res == 0x01;
        /*
        let local_addr = if res == 0x00 {
            args.nossl.to_string()
        } else if res == 0x01 {
            args.ssl.to_string()
        } else {
            continue;
        };
        */

        let conn_buff = generate_hello_packet(1, &args.token, &args.hash);
        tokio::task::spawn(spawn_tunnel(
            conn_buff,
            args.nossl.to_string(),
            args.proxy_addr.to_string(),
            ssl,
            args.redirect_ssl,
            domain.clone(),
            acceptor.clone(),
        ));
    }

    // Ok(())
}

async fn spawn_tunnel(
    conn_buff: [u8; 80],
    local_addr: String,
    proxy_addr: String,
    ssl: bool,
    redirect_ssl: bool,
    domain: String,
    acceptor: TlsAcceptor,
) -> Result<()> {
    let mut tunnel_stream = TcpStream::connect(proxy_addr).await?;
    tunnel_stream.set_nodelay(true)?;
    tunnel_stream.write_all(&conn_buff).await?;

    let mut local_stream = TcpStream::connect(local_addr).await?;
    local_stream.set_nodelay(true)?;

    if ssl {
        let mut stream = acceptor.accept(tunnel_stream).await?;
        tokio::io::copy_bidirectional(&mut local_stream, &mut stream).await?;
    } else if redirect_ssl {
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
        let redirect = utils::construct_http_redirect(&format!("https://{domain}{path}"));
        tunnel_stream.write_all(redirect.as_bytes()).await?;
    } else {
        tokio::io::copy_bidirectional(&mut local_stream, &mut tunnel_stream).await?;
    }

    Ok(())
}
