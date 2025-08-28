use anyhow::Result;
use kanal::AsyncSender;
use russh::keys::PrivateKey;
use russh::server::{Auth, Msg, Server as _, Session};
use russh::{Channel, ChannelId, MethodKind, MethodSet, Preferred, Pty};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

pub async fn spawn_ssh_server(key: PrivateKey) -> Result<()> {
    tokio::task::spawn(async move {
        loop {
            let res = ssh_server(key.clone()).await;
            if let Err(e) = res {
                println!("[SSH] SSH Server error {e:?}");
            }

            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    });

    Ok(())
}

async fn ssh_server(key: PrivateKey) -> Result<()> {
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
    let mut sh = Server { tx: None };

    let socket = TcpListener::bind(("0.0.0.0", 2222)).await.unwrap();
    let server = sh.run_on_socket(config, &socket);
    let handle = server.handle();

    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(600)).await;
        handle.shutdown("Server shutting down after 10 minutes".into());
    });

    server.await?;
    Ok(())
}

struct Server {
    tx: Option<AsyncSender<ChannelData>>,
}

enum ChannelData {
    PtyResize { rows: u16, cols: u16 },
    Data(Vec<u8>),
}

impl Server {}

impl russh::server::Server for Server {
    type Handler = Self;
    fn new_client(&mut self, _: Option<std::net::SocketAddr>) -> Self {
        Server { tx: None }
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
        let (tx, rx) = kanal::unbounded_async::<ChannelData>();

        self.tx = Some(tx);
        let ret = (channel.id(), session.handle());
        tokio::task::spawn(async move {
            let mut stream = TcpStream::connect("127.0.0.1:5321").await.unwrap();

            loop {
                tokio::select! {
                    recv = rx.recv() => {
                        if let Ok(recv) = recv {
                            match recv {
                                ChannelData::PtyResize { rows, cols } => {
                                    stream.write_u8(2).await.unwrap();
                                    stream.write_u16(rows as u16).await.unwrap();
                                    stream.write_u16(cols as u16).await.unwrap();
                                },
                                ChannelData::Data(data) => {
                                    stream.write_u8(1).await.unwrap();
                                    stream.write_u16(data.len() as u16).await.unwrap();
                                    stream.write_all(&data).await.unwrap();
                                }
                            }
                        }
                    }
                    recv = stream.read_u8() => {
                        if let Ok(recv) = recv {
                            if recv == 1 {
                                let n = stream.read_u16().await.unwrap() as usize;
                                let mut buf = vec![0; n];
                                stream.read_exact(&mut buf[..n]).await.unwrap();
                                ret.1.data(ret.0, buf[..n].into()).await.unwrap();
                            }
                        }
                    }
                }
            }
        });

        Ok(true)
    }

    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        let mut methods = MethodSet::empty();
        methods.push(MethodKind::Password);
        println!("{user} {password}");

        if password == "123" {
            Ok(Auth::Accept)
        } else {
            Ok(Auth::Reject {
                proceed_with_methods: Some(methods),
                partial_success: false,
            })
        }
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        // Sending Ctrl+C ends the session and disconnects the client
        /*
        if data == [3] {
            return Err(russh::Error::Disconnect);
        }
        */

        /*
        let data = CryptoVec::from(format!("Got data: {:x?}\r\n", data));
        session.data(channel, data)?;
        */

        if let Some(tx) = &mut self.tx {
            tx.send(ChannelData::Data(data.to_vec())).await.unwrap();
        }
        Ok(())
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        term: &str,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        modes: &[(Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some(tx) = &mut self.tx {
            tx.send(ChannelData::PtyResize {
                rows: row_height as u16,
                cols: col_width as u16,
            })
            .await
            .unwrap();
        }

        println!("pty req {term} {col_width} {row_height} {pix_width}px {pix_height}px");
        Ok(())
    }

    async fn window_change_request(
        &mut self,
        channel: ChannelId,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some(tx) = &mut self.tx {
            tx.send(ChannelData::PtyResize {
                rows: row_height as u16,
                cols: col_width as u16,
            })
            .await
            .unwrap();
        }

        println!("chg {col_width} {row_height} {pix_width}px {pix_height}px");
        Ok(())
    }
}

impl Drop for Server {
    fn drop(&mut self) {}
}
