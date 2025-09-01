use crate::structs::{SharedProxyState, TunnelRequest};
use anyhow::Result;
use fkm_proxy::utils::ConnectorStream;
use fkm_proxy::utils::ssh::SshPacketHeader;
use russh::keys::PrivateKey;
use russh::server::{Auth, Msg, Server as _, Session};
use russh::{Channel, ChannelId, Disconnect, MethodKind, MethodSet, Preferred, Pty};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

pub async fn spawn_ssh_server(
    bind: SocketAddr,
    key: PrivateKey,
    state: SharedProxyState,
) -> Result<()> {
    tokio::task::spawn(async move {
        loop {
            let res = ssh_server(&bind, key.clone(), state.clone()).await;
            if let Err(e) = res {
                println!("[SSH] SSH Server error {e:?}");
            }

            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    });

    Ok(())
}

async fn ssh_server(bind: &SocketAddr, key: PrivateKey, state: SharedProxyState) -> Result<()> {
    let mut methods = MethodSet::empty();
    methods.push(MethodKind::Password);

    let config = russh::server::Config {
        inactivity_timeout: Some(std::time::Duration::from_secs(3600)),
        auth_rejection_time: std::time::Duration::from_secs(3),
        auth_rejection_time_initial: Some(std::time::Duration::from_secs(0)),
        keys: vec![key],
        preferred: Preferred {
            // kex: std::borrow::Cow::Owned(vec![russh::kex::DH_GEX_SHA256]),
            ..Preferred::default()
        },
        methods,
        ..Default::default()
    };
    let config = Arc::new(config);
    let mut sh = Server {
        state,
        stream: None,
        pipe: None,
    };

    let socket = TcpListener::bind(bind).await.unwrap();
    let server = sh.run_on_socket(config, &socket);

    /*
       let handle = server.handle();
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(600)).await;
        handle.shutdown("Server shutting down after 10 minutes".into());
    });
    */

    server.await?;
    Ok(())
}

struct Server {
    state: SharedProxyState,
    stream: Option<ConnectorStream>,
    pipe: Option<tokio_pipe::PipeWrite>,
}

impl russh::server::Server for Server {
    type Handler = Self;
    fn new_client(&mut self, _: Option<std::net::SocketAddr>) -> Self {
        Server {
            state: self.state.clone(),
            stream: None,
            pipe: None,
        }
    }

    fn handle_session_error(&mut self, _error: <Self::Handler as russh::server::Handler>::Error) {
        eprintln!("Session error: {:#?}", _error);
    }
}

impl russh::server::Handler for Server {
    type Error = russh::Error;

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        let ret = (channel.id(), session.handle());
        if let Some(mut stream) = self.stream.take() {
            let (mut rx, tx) = tokio_pipe::pipe().unwrap();
            self.pipe = Some(tx);

            tokio::task::spawn(async move {
                let mut header_buf = [0; SshPacketHeader::HEADER_LENGTH];
                let mut buf = [0; 4096];
                let mut pipe_buf = [0; 512];

                loop {
                    tokio::select! {
                        res = stream.read_exact(&mut header_buf) => {
                            if res.is_err() {
                                _ = ret.1
                                    .disconnect(
                                        Disconnect::ConnectionLost,
                                        "Connection Lost".to_string(),
                                        "en".to_string(),
                                    )
                                    .await;

                                break;
                            }

                            let header = SshPacketHeader::from_buf(&header_buf);

                            if let fkm_proxy::utils::ssh::SshPacketType::Data = header.packet_type {
                                let mut rem = header.length as usize;

                                while rem > 0 {
                                    let read_n = rem.min(4096);
                                    stream.read_exact(&mut buf[..read_n]).await.unwrap();
                                    ret.1.data(ret.0, buf[..read_n].into()).await.unwrap();

                                    rem -= read_n;
                                }
                            }
                        }
                        res = rx.read(&mut pipe_buf) => {
                            if let Ok(n) = res {
                                stream.write_all(&pipe_buf[..n]).await.unwrap();
                            }
                        }
                    }
                }
            });

            Ok(true)
        } else {
            _ = ret
                .1
                .disconnect(
                    Disconnect::ConnectionLost,
                    "Cannot access tunnel!".to_string(),
                    "en".to_string(),
                )
                .await;

            Ok(false)
        }
    }

    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        let mut methods = MethodSet::empty();
        methods.push(MethodKind::Password);

        if let Ok(token) = password.parse()
            && let Some(tunn) = self.state.get_tunnel_entry(token).await
        {
            let mut generated_tunnel_id = [0u8; 16];
            self.state
                .consts
                .rng
                .secure_random
                .fill(&mut generated_tunnel_id)
                .unwrap();

            let generated_tunnel_id = u128::from_be_bytes(generated_tunnel_id);

            let (tx, rx) = tokio::sync::oneshot::channel();
            self.state
                .insert_tunnel_oneshot(generated_tunnel_id, tx)
                .await;

            tunn.sender
                .send(TunnelRequest::Request {
                    ssl: false,
                    ssh: true,
                    tunnel_id: generated_tunnel_id,
                })
                .await
                .unwrap();

            let tunnel_res = tokio::time::timeout(
                Duration::from_millis(self.state.get_tunnel_timeout().await),
                rx,
            )
            .await;

            if tunnel_res.is_err() {
                _ = self.state.get_tunnel_oneshot(generated_tunnel_id).await;
                return Ok(Auth::Accept); // this is not really accepted,
                // will disconnect when channel is opened
            }

            let mut stream = tunnel_res.unwrap().unwrap();
            stream
                .write_all(
                    &SshPacketHeader {
                        packet_type: fkm_proxy::utils::ssh::SshPacketType::User,
                        length: user.len() as u32,
                    }
                    .to_buf(),
                )
                .await
                .unwrap();
            stream.write_all(user.as_bytes()).await.unwrap();

            self.stream = Some(stream);
            return Ok(Auth::Accept);
        }

        Ok(Auth::Reject {
            proceed_with_methods: Some(methods),
            partial_success: false,
        })
    }

    async fn data(
        &mut self,
        _channel: ChannelId,
        data: &[u8],
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        // Sending Ctrl+C ends the session and disconnects the client
        /*
        if data == [3] {
            return Err(russh::Error::Disconnect);
        }
        */

        if let Some(pipe) = self.pipe.as_mut() {
            pipe.write_all(
                &SshPacketHeader {
                    packet_type: fkm_proxy::utils::ssh::SshPacketType::Data,
                    length: data.len() as u32,
                }
                .to_buf(),
            )
            .await
            .unwrap();
            pipe.write_all(data).await.unwrap();
        }
        Ok(())
    }

    async fn pty_request(
        &mut self,
        _channel: ChannelId,
        _term: &str,
        col_width: u32,
        row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        _modes: &[(Pty, u32)],
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some(pipe) = self.pipe.as_mut() {
            pipe.write_all(
                &SshPacketHeader {
                    packet_type: fkm_proxy::utils::ssh::SshPacketType::PtyResize,
                    length: 4,
                }
                .to_buf(),
            )
            .await
            .unwrap();

            pipe.write_u16(row_height as u16).await.unwrap();
            pipe.write_u16(col_width as u16).await.unwrap();
        }

        Ok(())
    }

    async fn window_change_request(
        &mut self,
        _channel: ChannelId,
        col_width: u32,
        row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some(pipe) = self.pipe.as_mut() {
            pipe.write_all(
                &SshPacketHeader {
                    packet_type: fkm_proxy::utils::ssh::SshPacketType::PtyResize,
                    length: 4,
                }
                .to_buf(),
            )
            .await
            .unwrap();

            pipe.write_u16(row_height as u16).await.unwrap();
            pipe.write_u16(col_width as u16).await.unwrap();
        }

        Ok(())
    }
}

impl Drop for Server {
    fn drop(&mut self) {}
}
