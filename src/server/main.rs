use crate::structs::SharedProxyState;
use anyhow::Result;
use clap::{Parser, command};
use fkm_proxy::utils::{
    certs::{cert_from_str, key_from_str},
    parse_socketaddr,
};
use rcgen::CertifiedKey;
use std::{net::SocketAddr, path::PathBuf, sync::Arc};
use tokio_rustls::TlsAcceptor;

mod ssh;
mod structs;
mod tunnel;

#[derive(Parser, Debug, Clone)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short, long, default_value = "./data", env = "CONFIG_PATH")]
    config_path: PathBuf,

    #[arg(long, value_parser = parse_socketaddr, default_value = "127.0.0.1:2222", env = "BIND_SSH")]
    bind_ssh: Option<SocketAddr>,

    #[arg(long, value_parser = parse_socketaddr, default_value = "127.0.0.1:80", env = "BIND_NONSSL")]
    bind_nonssl: SocketAddr,

    #[arg(long, value_parser = parse_socketaddr, default_value = "127.0.0.1:443", env = "BIND_SSL")]
    bind_ssl: SocketAddr,

    #[arg(long, env = "DISPLAY_SSL_PORT")]
    display_ssl_port: Option<u16>,

    #[arg(long, env = "DISPLAY_NONSSL_PORT")]
    display_nonssl_port: Option<u16>,

    #[arg(long, value_parser = parse_socketaddr, default_value = "0.0.0.0:6969", env = "BIND_CONNECTOR")]
    bind_connector: SocketAddr,

    #[arg(short, long, env = "DOMAIN")]
    domain: String,

    #[arg(long, env = "PANEL_DOMAIN")]
    panel_domain: Option<String>,

    #[arg(short, long, default_value_t = 2500, env = "TUNNEL_TIMEOUT")]
    tunnel_timeout: u64,

    #[arg(long)]
    generate_cert: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    _ = dotenvy::dotenv();
    tracing_subscriber::fmt::init();

    let args = Args::parse();
    if !args.config_path.exists() {
        tokio::fs::create_dir_all(&args.config_path).await?;
    }

    let cert = if args.generate_cert {
        let CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec![args.domain.clone()])?;
        let crt = fkm_proxy::utils::certs::cert_from_str(&cert.pem())?;
        let key = fkm_proxy::utils::certs::key_from_str(&signing_key.serialize_pem())?;
        (crt, key)
    } else {
        let certs = ::fkm_proxy::utils::certs::load_certs(&args.config_path.join("certs.pem"))?;
        let privkey = ::fkm_proxy::utils::certs::load_keys(&args.config_path.join("privkey.pem"))?;
        (certs, privkey)
    };

    let config = tokio_rustls::rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert.0, cert.1)?;
    let remote_acceptor = TlsAcceptor::from(Arc::new(config));

    let CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["proxy.lan".to_string()])?;
    let crt = cert_from_str(&cert.pem())?;
    let key = key_from_str(&signing_key.serialize_pem())?;
    let config = tokio_rustls::rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(crt, key)?;
    let acceptor = TlsAcceptor::from(Arc::new(config));

    let shared_proxy_state = SharedProxyState::new(
        remote_acceptor,
        acceptor,
        args.domain.clone(),
        args.panel_domain.unwrap_or(args.domain),
        args.config_path.join("domains.json"),
        args.tunnel_timeout,
        args.display_nonssl_port.unwrap_or(args.bind_nonssl.port()),
        args.display_ssl_port.unwrap_or(args.bind_ssl.port()),
    );

    _ = shared_proxy_state.load_domains().await;

    let addrs = vec![(args.bind_nonssl, false), (args.bind_ssl, true)];
    tunnel::spawn_tunnel_connector(addrs, args.bind_connector, shared_proxy_state.clone()).await?;

    if let Some(ssh_bind) = args.bind_ssh {
        let ssh_path = args.config_path.join("ssh.key");
        let ssh_key = if !ssh_path.exists() {
            let key = russh::keys::PrivateKey::random(
                &mut russh::keys::ssh_key::rand_core::OsRng,
                russh::keys::Algorithm::Ed25519,
            )?;

            let key_data = key.to_openssh(russh::keys::ssh_key::LineEnding::LF)?;
            tokio::fs::write(&ssh_path, key_data).await?;

            key
        } else {
            let key_data = tokio::fs::read(&ssh_path).await?;
            russh::keys::PrivateKey::from_openssh(&key_data)?
        };

        ssh::spawn_ssh_server(ssh_bind, ssh_key, shared_proxy_state).await?;
    }

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
