use std::{path::Path, sync::Arc};

use crate::structs::SharedProxyState;
use anyhow::Result;
use tokio_rustls::TlsAcceptor;

mod structs;
mod tunnel;
mod utils;

#[tokio::main]
async fn main() -> Result<()> {
    let addrs = std::env::args()
        .nth(1)
        .unwrap_or("0.0.0.0:1337".to_string());
    let connector_addr = "0.0.0.0:6969".to_string();

    let addrs = addrs.split(',').collect::<Vec<_>>();
    let addrs = addrs
        .iter()
        .map(|s| (*s, s.ends_with("443")))
        .collect::<Vec<_>>();

    let certs = crate::utils::load_certs(Path::new("cert.pem"))?;
    let privkey = crate::utils::load_keys(Path::new("key.pem"))?;

    let config = tokio_rustls::rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, privkey)?;

    let acceptor = TlsAcceptor::from(Arc::new(config));
    let shared_proxy_state = SharedProxyState::new(acceptor);

    shared_proxy_state
        .insert_client("test2.fkm.filipton.space", 0x6942069420)
        .await;

    shared_proxy_state
        .insert_client("dsa.fkm.filipton.space", 0x69420)
        .await;

    shared_proxy_state
        .insert_client("sls.fkm.filipton.space", 0x69420)
        .await;

    tunnel::spawn_tunnel_connector(addrs, &connector_addr, shared_proxy_state.clone()).await?;

    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {
        _ = sigterm.recv() => {
            println!("Received SIGTERM, stopping server!");
        }
        _ = tokio::signal::ctrl_c() => {
            println!("Received SIGINT, stopping server!");
        }
    }
    Ok(())
}
