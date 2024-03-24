use anyhow::Result;

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
    let addrs = addrs.iter().map(|s| (*s, s.ends_with("443"))).collect::<Vec<_>>();

    tunnel::spawn_tunnel_connector(addrs, &connector_addr).await?;

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
