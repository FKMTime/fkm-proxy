use highway::{HighwayHash, HighwayHasher};
use kanal::{AsyncReceiver, AsyncSender};
use std::{collections::HashMap, sync::Arc};
use thiserror::Error;
use tokio::{net::TcpStream, sync::RwLock};
use tokio_rustls::{client::TlsStream, rustls::crypto::ring, TlsAcceptor, TlsConnector};

pub type TunnelEntry = (
    AsyncSender<u8>,
    AsyncSender<TlsStream<TcpStream>>,
    AsyncReceiver<TlsStream<TcpStream>>,
);

pub struct ProxyState {
    pub top_domain: String,

    pub tls_acceptor: Arc<TlsAcceptor>,
    pub tls_connector: Arc<TlsConnector>,

    pub tunnels: HashMap<u128, TunnelEntry>,
    pub tokens: HashMap<u64, u128>,    // url(hashed) -> token
    pub domains: HashMap<u64, String>, // url(hashed) -> domain
}

#[derive(Clone)]
pub struct SharedProxyState(Arc<RwLock<ProxyState>>);

impl SharedProxyState {
    pub fn new(tls_acceptor: TlsAcceptor, tls_connector: TlsConnector, top_domain: String) -> Self {
        SharedProxyState(Arc::new(RwLock::new(ProxyState {
            top_domain,

            tls_acceptor: Arc::new(tls_acceptor),
            tls_connector: Arc::new(tls_connector),

            tunnels: HashMap::new(),
            tokens: HashMap::new(),
            domains: HashMap::new(),
        })))
    }

    pub async fn generate_new_client(&self, subdomain: &str) -> anyhow::Result<(u64, u128)> {
        let rng = ring::default_provider().secure_random;
        let mut token = [0u8; 16];
        rng.fill(&mut token).unwrap();
        let token = u128::from_be_bytes(token);

        let url_hash = self.insert_client(subdomain, token).await?;
        Ok((url_hash, token))
    }

    pub async fn insert_client(&self, subdomain: &str, token: u128) -> anyhow::Result<u64> {
        let mut state = self.0.write().await;
        let url = format!("{}.{}", subdomain, state.top_domain);
        if state.domains.values().any(|x| x == &url) {
            return Err(anyhow::anyhow!("Domain already exists!"));
        }

        let hash = HighwayHasher::default().hash64(url.as_bytes());
        tracing::info!("New url: {url} with hash: {hash}");
        tracing::info!("New token: {token}");

        state.domains.insert(hash, url.to_string());
        state.tokens.insert(hash, token);
        Ok(hash)
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
        state.tokens.get(&hash).copied()
    }

    pub async fn get_token_by_url_hash(&self, url_hash: u64) -> Option<u128> {
        let state = self.0.read().await;
        state.tokens.get(&url_hash).copied()
    }

    pub async fn get_tunnel_entry(&self, token: u128) -> Option<TunnelEntry> {
        let state = self.0.read().await;
        state.tunnels.get(&token).cloned()
    }

    pub async fn get_tunnel_tx(&self, token: u128) -> Option<AsyncSender<TlsStream<TcpStream>>> {
        let state = self.0.read().await;
        state.tunnels.get(&token).map(|x| x.1.clone())
    }

    pub async fn remove_tunnel(&self, token: u128) {
        let mut state = self.0.write().await;
        state.tunnels.remove(&token);
    }

    pub async fn get_tls_acceptor(&self) -> Arc<TlsAcceptor> {
        let state = self.0.read().await;
        state.tls_acceptor.clone()
    }

    pub async fn get_tls_connector(&self) -> Arc<TlsConnector> {
        let state = self.0.read().await;
        state.tls_connector.clone()
    }

    pub async fn get_domain_by_hash(&self, hash: u64) -> Option<String> {
        let state = self.0.read().await;
        state.domains.get(&hash).cloned()
    }

    pub async fn get_top_domain(&self) -> String {
        let state = self.0.read().await;
        state.top_domain.clone()
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
