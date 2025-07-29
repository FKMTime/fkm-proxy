use kanal::AsyncSender;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Arc, time::Duration};
use thiserror::Error;
use tokio::{
    net::TcpStream,
    sync::{RwLock, oneshot::Sender},
};
use tokio_rustls::{TlsAcceptor, TlsConnector, client::TlsStream, rustls::crypto::CryptoProvider};

/// Enum used to request tunnel from connector
pub enum TunnelRequest {
    Close(String),
    Request { ssl: bool, tunnel_id: u128 },
}

pub type TunnelSender = AsyncSender<TunnelRequest>;

pub struct InnerProxyState {
    pub tunnels: HashMap<u128, (bool, TunnelSender)>,
    pub requests: HashMap<u128, Sender<TlsStream<TcpStream>>>,
    pub domains: HashMap<String, u128>, // domain -> token
}

pub struct ConstProxyState {
    pub panel_domain: String,
    pub top_domain: String,
    pub save_path: String,
    pub tunnel_timeout: u64,

    pub tls_acceptor: Arc<TlsAcceptor>,
    pub tls_connector: Arc<TlsConnector>,
    pub rng: Arc<CryptoProvider>,

    pub nonssl_port: u16,
    pub ssl_port: u16,
}

#[derive(Clone)]
pub struct SharedProxyState {
    pub consts: Arc<ConstProxyState>,
    pub inner: Arc<RwLock<InnerProxyState>>,
}

#[allow(dead_code)]
impl SharedProxyState {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tls_acceptor: TlsAcceptor,
        tls_connector: TlsConnector,
        top_domain: String,
        panel_domain: String,
        save_path: String,
        tunnel_timeout: u64,
        nonssl_port: u16,
        ssl_port: u16,
    ) -> Self {
        let rng = tokio_rustls::rustls::crypto::ring::default_provider();

        SharedProxyState {
            consts: Arc::new(ConstProxyState {
                panel_domain,
                top_domain,
                save_path,
                tunnel_timeout,

                tls_acceptor: Arc::new(tls_acceptor),
                tls_connector: Arc::new(tls_connector),
                rng: Arc::new(rng),

                nonssl_port,
                ssl_port,
            }),

            inner: Arc::new(RwLock::new(InnerProxyState {
                tunnels: HashMap::new(),
                requests: HashMap::new(),
                domains: HashMap::new(),
            })),
        }
    }

    pub async fn generate_new_client(&self, subdomain: &str) -> anyhow::Result<u128> {
        let rng = self.consts.rng.secure_random;
        let mut token = [0u8; 16];
        rng.fill(&mut token).unwrap();
        let token = u128::from_be_bytes(token);

        self.insert_client(subdomain, token).await?;
        Ok(token)
    }

    pub async fn insert_client(&self, subdomain: &str, token: u128) -> anyhow::Result<()> {
        let mut state = self.inner.write().await;
        let url = if subdomain.contains('.') {
            subdomain.to_string()
        } else {
            format!("{}.{}", subdomain, self.consts.top_domain)
        };

        if state.domains.contains_key(&url) {
            return Err(anyhow::anyhow!("Domain already exists!"));
        }

        state.domains.insert(url, token);
        drop(state);

        self.save_domains().await?;
        Ok(())
    }

    pub async fn insert_tunnel_connector(&self, token: u128, tunnel: TunnelSender, own_ssl: bool) {
        let mut state = self.inner.write().await;
        let old = state.tunnels.insert(token, (own_ssl, tunnel));

        if let Some(old) = old {
            _ = old
                .1
                .send(TunnelRequest::Close("Other tunnel connected!".to_string()))
                .await;

            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    pub async fn get_client_token(&self, url: &str) -> Option<u128> {
        let state = self.inner.read().await;
        state.domains.get(url).copied()
    }

    pub async fn get_tunnel_timeout(&self) -> u64 {
        self.consts.tunnel_timeout
    }

    pub async fn get_tunnel_entry(&self, token: u128) -> Option<(bool, TunnelSender)> {
        let state = self.inner.read().await;
        state.tunnels.get(&token).cloned()
    }

    pub async fn insert_tunnel_oneshot(&self, tunnel_id: u128, tx: Sender<TlsStream<TcpStream>>) {
        let mut state = self.inner.write().await;
        state.requests.insert(tunnel_id, tx);
    }

    pub async fn get_tunnel_oneshot(
        &self,
        tunnel_id: u128,
    ) -> Option<Sender<TlsStream<TcpStream>>> {
        let mut state = self.inner.write().await;
        state.requests.remove(&tunnel_id)
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

    pub async fn get_domain_by_token(&self, token: u128) -> Option<String> {
        let state = self.inner.read().await;
        state
            .domains
            .iter()
            .enumerate()
            .find(|(_, (_, v))| **v == token)
            .map(|(_, (k, _))| k)
            .cloned()
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
    pub domains: HashMap<String, u128>,
}
