use crate::{cert::NoCertVerification, structs::SharedProxyState};
use anyhow::Result;
use clap::{command, Parser};
use rcgen::CertifiedKey;
use std::{net::SocketAddr, path::PathBuf, sync::Arc};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use utils::parse_socketaddr;

mod cert;
mod structs;
mod tunnel;

#[derive(Parser, Debug, Clone)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short, long, default_value = "cert.pem", env = "CERT_PATH")]
    cert_path: PathBuf,

    #[arg(short, long, default_value = "privkey.pem", env = "PRIVKEY_PATH")]
    privkey_path: PathBuf,

    #[arg(long, value_parser = parse_socketaddr, default_value = "127.0.0.1:80", env = "BIND_NONSSL")]
    bind_nonssl: SocketAddr,

    #[arg(long, value_parser = parse_socketaddr, default_value = "127.0.0.1:443", env = "BIND_SSL")]
    bind_ssl: SocketAddr,

    #[arg(long, value_parser = parse_socketaddr, default_value = "0.0.0.0:6969", env = "BIND_CONNECTOR")]
    bind_connector: SocketAddr,

    #[arg(short, long, env = "DOMAIN")]
    domain: String,

    #[arg(long, env = "PANEL_DOMAIN")]
    panel_domain: Option<String>,

    #[arg(short, long, default_value = "./domain.json", env = "SAVE_PATH")]
    save_path: String,

    #[arg(short, long, default_value_t = 2500, env = "TUNNEL_TIMEOUT")]
    tunnel_timeout: u64,

    #[arg(long)]
    generate_cert: bool,

    #[arg(long, action, env = "HTTP3")]
    http3: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    _ = dotenvy::dotenv();
    tracing_subscriber::fmt::init();

    let args = Args::parse();

    let cert = if args.generate_cert {
        let CertifiedKey { cert, key_pair } =
            rcgen::generate_simple_self_signed(vec![args.domain.clone()])?;
        let crt = utils::certs::cert_from_str(&cert.pem())?;
        let key = utils::certs::key_from_str(&key_pair.serialize_pem())?;
        (crt, key)
    } else {
        let certs = ::utils::certs::load_certs(&args.cert_path)?;
        let privkey = ::utils::certs::load_keys(&args.privkey_path)?;
        (certs, privkey)
    };

    let config = tokio_rustls::rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert.0, cert.1)?;
    let acceptor = TlsAcceptor::from(Arc::new(config));

    let config = tokio_rustls::rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoCertVerification))
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));

    let shared_proxy_state = SharedProxyState::new(
        acceptor,
        connector,
        args.domain.clone(),
        args.panel_domain.unwrap_or(args.domain),
        args.save_path,
        args.tunnel_timeout,
        args.bind_nonssl.port(),
        args.bind_ssl.port(),
    );

    _ = shared_proxy_state.load_domains().await;

    let addrs = vec![(args.bind_nonssl, false), (args.bind_ssl, true)];
    tunnel::spawn_tunnel_connector(addrs, args.bind_connector, shared_proxy_state.clone()).await?;

    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {
        _ = sigterm.recv() => {
            tracing::info!("Received SIGTERM, stopping server!");
        }
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("Received SIGINT, stopping server!");
        }
    }
    Ok(())
}
