use highway::{HighwayHash, HighwayHasher};
use kanal::{AsyncReceiver, AsyncSender};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Arc};
use thiserror::Error;
use tokio::{net::TcpStream, sync::RwLock};
use tokio_rustls::{client::TlsStream, rustls::crypto::ring, TlsAcceptor, TlsConnector};

pub type TunnelEntry = (
    AsyncSender<u8>,
    AsyncSender<TlsStream<TcpStream>>,
    AsyncReceiver<TlsStream<TcpStream>>,
);

pub struct InnerProxyState {
    pub tunnels: HashMap<u128, TunnelEntry>,
    pub domains: HashMap<u64, (u128, String)>, // url(hashed) -> domain
}

pub struct ConstProxyState {
    pub panel_domain: String,
    pub top_domain: String,
    pub save_path: String,
    pub tunnel_timeout: u64,

    pub tls_acceptor: Arc<TlsAcceptor>,
    pub tls_connector: Arc<TlsConnector>,
}

#[derive(Clone)]
pub struct SharedProxyState {
    pub consts: Arc<ConstProxyState>,
    pub inner: Arc<RwLock<InnerProxyState>>,
}

#[allow(dead_code)]
impl SharedProxyState {
    pub fn new(
        tls_acceptor: TlsAcceptor,
        tls_connector: TlsConnector,
        top_domain: String,
        panel_domain: String,
        save_path: String,
        tunnel_timeout: u64,
    ) -> Self {
        SharedProxyState {
            consts: Arc::new(ConstProxyState {
                panel_domain,
                top_domain,
                save_path,
                tunnel_timeout,

                tls_acceptor: Arc::new(tls_acceptor),
                tls_connector: Arc::new(tls_connector),
            }),

            inner: Arc::new(RwLock::new(InnerProxyState {
                tunnels: HashMap::new(),
                domains: HashMap::new(),
            })),
        }
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
        let mut state = self.inner.write().await;
        let url = format!("{}.{}", subdomain, self.consts.top_domain);
        if state.domains.values().any(|x| x.1 == url) {
            return Err(anyhow::anyhow!("Domain already exists!"));
        }

        let hash = HighwayHasher::default().hash64(url.as_bytes());
        state.domains.insert(hash, (token, url));
        drop(state);

        self.save_domains().await?;
        Ok(hash)
    }

    pub async fn insert_tunnel_connector(&self, token: u128, tunnel: TunnelEntry) {
        let mut state = self.inner.write().await;
        let old = state.tunnels.insert(token, tunnel);

        if let Some(old) = old {
            _ = old.0.send(u8::MAX).await; // close old connector
        }
    }

    pub async fn get_client_token(&self, url: &str) -> Option<u128> {
        let state = self.inner.read().await;
        let hash = HighwayHasher::default().hash64(url.as_bytes());
        state.domains.get(&hash).map(|x| x.0)
    }

    pub async fn get_tunnel_timeout(&self) -> u64 {
        self.consts.tunnel_timeout
    }

    pub async fn get_token_by_url_hash(&self, url_hash: u64) -> Option<u128> {
        let state = self.inner.read().await;
        state.domains.get(&url_hash).map(|x| x.0)
    }

    pub async fn get_tunnel_entry(&self, token: u128) -> Option<TunnelEntry> {
        let state = self.inner.read().await;
        state.tunnels.get(&token).cloned()
    }

    pub async fn get_tunnel_tx(&self, token: u128) -> Option<AsyncSender<TlsStream<TcpStream>>> {
        let state = self.inner.read().await;
        state.tunnels.get(&token).map(|x| x.1.clone())
    }

    pub async fn remove_tunnel(&self, token: u128) {
        let mut state = self.inner.write().await;
        state.tunnels.remove(&token);
    }

    pub async fn get_tls_acceptor(&self) -> Arc<TlsAcceptor> {
        self.consts.tls_acceptor.clone()
    }

    pub async fn get_tls_connector(&self) -> Arc<TlsConnector> {
        self.consts.tls_connector.clone()
    }

    pub async fn get_domain_by_hash(&self, hash: u64) -> Option<String> {
        let state = self.inner.read().await;
        state.domains.get(&hash).map(|x| x.1.clone())
    }

    #[inline(always)]
    pub fn is_host_panel(&self, host: &str) -> bool {
        host == self.consts.panel_domain
    }

    pub async fn save_domains(&self) -> anyhow::Result<()> {
        let state = self.inner.read().await;
        let saved = SavedDomains {
            domains: state.domains.clone(),
        };

        let data = serde_json::to_string(&saved)?;
        tokio::fs::write(&self.consts.save_path, data).await?;
        Ok(())
    }

    pub async fn load_domains(&self) -> anyhow::Result<()> {
        let mut state = self.inner.write().await;

        let data = tokio::fs::read_to_string(&self.consts.save_path).await?;
        let saved: SavedDomains = serde_json::from_str(&data)?;

        state.domains = saved.domains;
        Ok(())
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

#[derive(Debug, Serialize, Deserialize)]
pub struct SavedDomains {
    pub domains: HashMap<u64, (u128, String)>,
}
