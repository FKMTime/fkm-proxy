use highway::{HighwayHash, HighwayHasher};
use kanal::{AsyncReceiver, AsyncSender};
use std::{collections::HashMap, sync::Arc};
use thiserror::Error;
use tokio::{net::TcpStream, sync::RwLock};

pub type TunnelEntry = (
    AsyncSender<u8>,
    AsyncSender<TcpStream>,
    AsyncReceiver<TcpStream>,
);

pub struct ProxyState {
    pub tunnels: HashMap<u128, TunnelEntry>,
    pub clients: HashMap<u64, u128>, // url(hashed) -> token
}

#[derive(Clone)]
pub struct SharedProxyState(Arc<RwLock<ProxyState>>);

impl SharedProxyState {
    pub fn new() -> Self {
        SharedProxyState(Arc::new(RwLock::new(ProxyState {
            tunnels: HashMap::new(),
            clients: HashMap::new(),
        })))
    }

    pub async fn insert_client(&self, url: &str, token: u128) {
        let mut state = self.0.write().await;
        let hash = HighwayHasher::default().hash64(url.as_bytes());
        println!("New url: {url} with hash: {hash}");

        state.clients.insert(hash, token);
    }

    pub async fn insert_tunnel_connector(&self, token: u128, tunnel: TunnelEntry) {
        let mut state = self.0.write().await;
        let old = state.tunnels.insert(token, tunnel);

        if let Some(old) = old {
            _ = old.0.send(u8::MAX).await; // close old connector
        }
    }

    pub async fn get_client_token(&self, url: &str) -> Option<u128> {
        let state = self.0.read().await;
        let hash = HighwayHasher::default().hash64(url.as_bytes());
        state.clients.get(&hash).copied()
    }

    pub async fn get_token_by_url_hash(&self, url_hash: u64) -> Option<u128> {
        let state = self.0.read().await;
        state.clients.get(&url_hash).copied()
    }

    pub async fn get_tunnel_entry(&self, token: u128) -> Option<TunnelEntry> {
        let state = self.0.read().await;
        state.tunnels.get(&token).cloned()
    }

    pub async fn get_tunnel_tx(&self, token: u128) -> Option<AsyncSender<TcpStream>> {
        let state = self.0.read().await;
        state.tunnels.get(&token).map(|x| x.1.clone())
    }

    pub async fn remove_tunnel(&self, token: u128) {
        let mut state = self.0.write().await;
        state.tunnels.remove(&token);
    }
}

#[derive(Error, Debug)]
pub enum TunnelError {
    #[error("Tunnel does not exist!")]
    TunnelDoesNotExist,

    #[error("No connector for this tunnel!")]
    NoConnectorForTunnel,

    #[error(transparent)]
    Anyhow(#[from] anyhow::Error),
}
