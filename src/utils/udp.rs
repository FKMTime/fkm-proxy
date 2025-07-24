use anyhow::Result;
use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
    sync::{
        mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender},
        RwLock,
    },
};

type TunnelMapTest = Arc<RwLock<HashMap<SocketAddr, UnboundedSender<Vec<u8>>>>>;
pub async fn server_accept(
    listener: &Arc<UdpSocket>,
    recv_buf: &mut [u8],
    tunnel_map: &TunnelMapTest,
) -> Result<(UdpClient, SocketAddr)> {
    loop {
        let (n, addr) = listener.recv_from(recv_buf).await?;
        let rx = {
            let mut tunnel_map_rw = tunnel_map.write().await;
            if let Some(sock) = tunnel_map_rw.get_mut(&addr) {
                if sock.is_closed() {
                    let (tx, rx) = unbounded_channel();
                    *sock = tx;
                    sock.send(recv_buf[..n].to_vec())?;

                    return Ok((UdpClient::new(tunnel_map, rx, addr), addr));
                }

                sock.send(recv_buf[..n].to_vec())?;
                continue;
            } else {
                let (tx, rx) = unbounded_channel();
                tx.send(recv_buf[..n].to_vec())?;
                tunnel_map_rw.insert(addr, tx);

                rx
            }
        };

        return Ok((UdpClient::new(tunnel_map, rx, addr), addr));
    }
}

pub struct UdpClient {
    tunnel_map: TunnelMapTest,
    rx: UnboundedReceiver<Vec<u8>>,
    addr: SocketAddr,
}

impl UdpClient {
    pub fn new(
        tunnel_map: &TunnelMapTest,
        rx: UnboundedReceiver<Vec<u8>>,
        addr: SocketAddr,
    ) -> Self {
        Self {
            tunnel_map: tunnel_map.clone(),
            rx,
            addr,
        }
    }

    async fn recv(&mut self) -> Option<Vec<u8>> {
        let timeout = tokio::time::timeout(Duration::from_secs(45), self.rx.recv()).await;
        timeout.unwrap_or_default()
    }

    pub async fn copy_bidirectional_udp(
        &mut self,
        listener: &Arc<UdpSocket>,
        sock: UdpSocket,
    ) -> Result<()> {
        let mut recv_buf = [0; 65536];
        loop {
            tokio::select! {
                res = self.recv() => {
                    match res {
                        Some(res) => sock.send(&res).await?,
                        None => break
                    };
                }
                res = sock.recv(&mut recv_buf) => {
                    let n = res?;
                    listener.send_to(&recv_buf[..n], self.addr).await?;
                }
            }
        }

        self.remove().await;
        Ok(())
    }

    pub async fn copy_bidirectional_tcp(
        &mut self,
        listener: &Arc<UdpSocket>,
        mut sock: TcpStream,
    ) -> Result<()> {
        let mut recv_buf = [0; 65536];
        loop {
            tokio::select! {
                res = self.recv() => {
                    match res {
                        Some(res) => {
                            sock.write_u16(res.len() as u16).await?;
                            sock.write_all(&res).await?;
                        },
                        None => break
                    };
                }
                n = sock.read_u16() => {
                    let n = n?;
                    sock.read_exact(&mut recv_buf[..n as usize]).await?;
                    listener.send_to(&recv_buf[..n as usize], self.addr).await?;
                }
            }
        }

        self.remove().await;
        Ok(())
    }

    async fn remove(&self) {
        self.tunnel_map.write().await.remove(&self.addr);
    }
}
