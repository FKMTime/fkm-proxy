use crate::{cert::NoCertVerification, structs::SharedProxyState};
use anyhow::Result;
use clap::{command, Parser};
use std::{path::Path, sync::Arc};
use tokio_rustls::{TlsAcceptor, TlsConnector};

mod cert;
mod structs;
mod tunnel;

#[derive(Parser, Debug, Clone)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(long, default_value = "127.0.0.1:80", env = "BIND_NONSSL")]
    bind_nonssl: String,

    #[arg(long, default_value = "127.0.0.1:443", env = "BIND_SSL")]
    bind_ssl: String,

    #[arg(long, default_value = "0.0.0.0:6969", env = "BIND_CONNECTOR")]
    bind_connector: String,

    #[arg(short, long, env = "DOMAIN")]
    domain: String,

    #[arg(short, long, default_value = "./domain.json", env = "SAVE_PATH")]
    save_path: String,

    #[arg(short, long, default_value_t = 2500, env = "TUNNEL_TIMEOUT")]
    tunnel_timeout: u64,
}

#[tokio::main]
async fn main() -> Result<()> {
    _ = dotenvy::dotenv();
    tracing_subscriber::fmt::init();

    let args = Args::parse();

    let addrs = vec![
        (args.bind_nonssl.as_ref(), false),
        (args.bind_ssl.as_ref(), true),
    ];

    let certs = ::utils::certs::load_certs(Path::new("key.crt"))?;
    let privkey = ::utils::certs::load_keys(Path::new("priv.key"))?;

    let config = tokio_rustls::rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, privkey)?;
    let acceptor = TlsAcceptor::from(Arc::new(config));

    let config = tokio_rustls::rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoCertVerification))
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));

    let shared_proxy_state = SharedProxyState::new(
        acceptor,
        connector,
        args.domain,
        args.save_path,
        args.tunnel_timeout,
    );

    _ = shared_proxy_state.load_domains().await;
    tunnel::spawn_tunnel_connector(addrs, &args.bind_connector, shared_proxy_state.clone()).await?;

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
