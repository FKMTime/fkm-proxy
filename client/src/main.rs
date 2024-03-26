use anyhow::Result;
use clap::{command, Parser};
use futures_util::StreamExt;
use std::{path::Path, sync::Arc};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use tokio_rustls_acme::{
    caches::DirCache, tokio_rustls::rustls::ServerConfig, AcmeAcceptor, AcmeConfig,
};

//mod acme;
mod utils;

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

    #[arg(short, long, env = "EMAIL")]
    email: String,

    #[arg(short, long, action, env = "REDIRECT_SSL")]
    redirect_ssl: bool,

    #[arg(short, long, env = "CERT_PATH")]
    cert_path: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    _ = dotenvy::dotenv();
    let args = Args::parse();

    /*
    let (key, crt) = acme::cert_loader(
        args.token,
        args.hash,
        &args.proxy_addr,
        "/tmp/acme",
        &args.email,
    )
    .await?;
    */

    let domain = utils::get_domain_by_hash(args.hash, args.proxy_addr.to_string())
        .await?
        .trim()
        .to_string();

    let path = args.cert_path.unwrap_or_else(|| format!("/tmp/acme"));
    let mut acme = AcmeConfig::new([&domain])
        .contact_push(format!("mailto:{}", args.email))
        .cache(DirCache::new(path))
        .directory_lets_encrypt(true)
        .state();

    let rustls_config = Arc::new(
        ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_cert_resolver(acme.resolver()),
    );

    let acceptor = acme.acceptor();

    tokio::spawn(async move {
        loop {
            match acme.next().await.unwrap() {
                Ok(ok) => println!("acme event: {:?}", ok),
                Err(err) => println!("acme error: {:?}", err),
            }
        }
    });

    println!("Access through: http://{}", domain);
    let mut connector = TcpStream::connect(&args.proxy_addr).await?;
    let hello_packet = ::utils::generate_hello_packet(0, &args.token, &args.hash)?;

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

        let conn_buff = ::utils::generate_hello_packet(1, &args.token, &args.hash)?;
        tokio::task::spawn(spawn_tunnel(
            conn_buff,
            args.addr.to_string(),
            args.proxy_addr.to_string(),
            ssl,
            args.redirect_ssl,
            domain.clone(),
            acceptor.clone(),
            rustls_config.clone(),
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
    acceptor: AcmeAcceptor,
    config: Arc<ServerConfig>,
) -> Result<()> {
    let mut tunnel_stream = TcpStream::connect(proxy_addr).await?;
    tunnel_stream.set_nodelay(true)?;
    tunnel_stream.write_all(&conn_buff).await?;

    let mut local_stream = TcpStream::connect(local_addr).await?;
    local_stream.set_nodelay(true)?;

    if ssl {
        let handshake = acceptor.accept(tunnel_stream).await?;
        if let Some(handshake) = handshake {
            let mut tls = handshake.into_stream(config).await?;
            tokio::io::copy_bidirectional(&mut local_stream, &mut tls).await?;
        }
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
        let redirect = ::utils::http::construct_http_redirect(&format!("https://{domain}{path}"));
        tunnel_stream.write_all(redirect.as_bytes()).await?;
    } else {
        tokio::io::copy_bidirectional(&mut local_stream, &mut tunnel_stream).await?;
    }

    Ok(())
}
