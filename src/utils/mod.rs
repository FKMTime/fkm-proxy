use anyhow::Result;
use quinn::VarInt;
use std::{
    net::{SocketAddr, ToSocketAddrs},
    pin::Pin,
    task::Context,
    time::Duration,
};
use thiserror::Error;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
};

pub mod certs;
pub mod http;
pub mod udp;

#[derive(Debug)]
pub struct HelloPacket {
    pub hp_type: HelloPacketType,
    //pub hash: u64,
    pub token: u128,
    pub own_ssl: bool,
    pub tunnel_id: u128,
}

#[derive(Debug, PartialEq)]
pub enum HelloPacketType {
    Connector = 0,
    Tunnel = 1,

    Invalid,
}

impl HelloPacketType {
    pub fn to_u8(&self) -> u8 {
        match self {
            HelloPacketType::Connector => 0,
            HelloPacketType::Tunnel => 1,
            HelloPacketType::Invalid => u8::MAX,
        }
    }

    pub fn from_u8(val: u8) -> Self {
        match val {
            0 => HelloPacketType::Connector,
            1 => HelloPacketType::Tunnel,
            _ => HelloPacketType::Invalid,
        }
    }
}

impl HelloPacket {
    pub const fn buf_size() -> usize {
        80
    }

    pub fn to_buf(&self) -> [u8; 80] {
        let mut tmp = [0; 80];
        tmp[0] = self.hp_type.to_u8();
        //tmp[1..9].copy_from_slice(&self.hash.to_be_bytes());
        tmp[10..26].copy_from_slice(&self.token.to_be_bytes());
        tmp[26] = self.own_ssl as u8;
        tmp[27..43].copy_from_slice(&self.tunnel_id.to_be_bytes());

        tmp
    }

    pub fn from_buf(buf: &[u8; 80]) -> Self {
        Self {
            hp_type: HelloPacketType::from_u8(buf[0]),
            //hash: u64::from_be_bytes(buf[1..9].try_into().unwrap()),
            token: u128::from_be_bytes(buf[10..26].try_into().unwrap()),
            own_ssl: buf[26] != 0,
            tunnel_id: u128::from_be_bytes(buf[27..43].try_into().unwrap()),
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum ConnectorPacketType {
    Ping = 0,
    TunnelRequest = 1,
    Close = 2,
    ConnectorConnected = 3,

    Invalid,
}

impl ConnectorPacketType {
    pub fn to_u8(&self) -> u8 {
        match self {
            ConnectorPacketType::Ping => 0,
            ConnectorPacketType::TunnelRequest => 1,
            ConnectorPacketType::Close => 2,
            ConnectorPacketType::ConnectorConnected => 3,
            ConnectorPacketType::Invalid => u8::MAX,
        }
    }

    pub fn from_u8(val: u8) -> Self {
        match val {
            0 => ConnectorPacketType::Ping,
            1 => ConnectorPacketType::TunnelRequest,
            2 => ConnectorPacketType::Close,
            3 => ConnectorPacketType::ConnectorConnected,
            _ => ConnectorPacketType::Invalid,
        }
    }
}

#[derive(Debug)]
pub struct ConnectorPacket {
    pub packet_type: ConnectorPacketType,
    pub tunnel_id: u128,
    pub ssl: bool,
}

impl ConnectorPacket {
    pub const fn buf_size() -> usize {
        20
    }

    pub fn to_buf(&self) -> [u8; 20] {
        let mut tmp = [0; 20];
        tmp[0] = self.packet_type.to_u8();
        tmp[1..17].copy_from_slice(&self.tunnel_id.to_be_bytes());
        tmp[17] = self.ssl as u8;

        tmp
    }

    pub fn from_buf(buf: &[u8; 20]) -> Self {
        Self {
            packet_type: ConnectorPacketType::from_u8(buf[0]),
            tunnel_id: u128::from_be_bytes(buf[1..17].try_into().unwrap()),
            ssl: buf[17] != 0,
        }
    }
}

pub fn parse_socketaddr(arg: &str) -> Result<SocketAddr> {
    for i in 0..10 {
        let res = arg.to_socket_addrs();

        match res {
            Ok(addrs) => {
                for addr in addrs {
                    if addr.is_ipv4() {
                        return Ok(addr);
                    }
                }
            }
            Err(e) => {
                println!("[clap parse_socketaddr] (Try: {}) {e:?}", i + 1);
                std::thread::sleep(Duration::from_millis(5000));
            }
        }
    }

    Err(anyhow::anyhow!("No ipv4 socketaddr found!"))
}

pub fn generate_string_packet(string: &str) -> Result<Vec<u8>> {
    let mut bytes = string.as_bytes().to_vec();
    bytes.push(0); // null terminator

    Ok(bytes)
}

pub async fn send_string_to_stream<T>(stream: &mut T, string: &str) -> Result<()>
where
    T: AsyncWrite + Unpin,
{
    let bytes = generate_string_packet(string)?;
    stream.write_all(&bytes).await?;

    Ok(())
}

pub async fn read_string_from_stream<T>(stream: &mut T) -> Result<String>
where
    T: AsyncRead + Unpin,
{
    let mut buffer = Vec::new();
    loop {
        let byte = stream.read_u8().await?;
        if byte == 0 {
            break;
        }

        buffer.push(byte);
    }

    Ok(String::from_utf8(buffer)?)
}

#[derive(Error, Debug)]
pub enum HelloPacketError {
    #[error("Token mismatch!")]
    TokenMismatch,

    #[error(transparent)]
    TryFromSlice(#[from] std::array::TryFromSliceError),

    #[error(transparent)]
    Anyhow(#[from] anyhow::Error),
}

pub fn read_http_host(in_buffer: &[u8]) -> Result<String> {
    let mut lines = in_buffer.split(|&x| x == b'\n');
    let host = lines
        .find(|x| x.to_ascii_lowercase().starts_with(b"host:"))
        .ok_or_else(|| anyhow::anyhow!("No host"))?;

    let host = String::from_utf8_lossy(&host[5..]).trim().to_string();
    Ok(host)
}

pub enum ConnectorStream {
    TcpTlsClient(Box<tokio_rustls::client::TlsStream<TcpStream>>),
    TcpTlsServer(Box<tokio_rustls::server::TlsStream<TcpStream>>),
    Quic((quinn::SendStream, quinn::RecvStream)),
}

impl ConnectorStream {
    pub async fn shutdown(&mut self) {
        tokio::time::sleep(Duration::from_millis(100)).await;
        match self {
            ConnectorStream::TcpTlsClient(stream) => {
                _ = stream.flush().await;
                _ = stream.shutdown().await;
            }
            ConnectorStream::TcpTlsServer(stream) => {
                _ = stream.flush().await;
                _ = stream.shutdown().await;
            }
            ConnectorStream::Quic((send, recv)) => {
                _ = send.flush().await;
                _ = send.shutdown().await;
                _ = recv.stop(VarInt::from_u32(0));
            }
        }
    }
}

impl AsyncWrite for ConnectorStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::result::Result<usize, std::io::Error>> {
        match self.get_mut() {
            ConnectorStream::TcpTlsClient(stream) => Pin::new(stream).poll_write(cx, buf),
            ConnectorStream::TcpTlsServer(stream) => Pin::new(stream).poll_write(cx, buf),
            ConnectorStream::Quic((stream, _)) => {
                Pin::new(stream).poll_write(cx, buf).map(|r| match r {
                    Ok(n) => std::io::Result::Ok(n),
                    Err(e) => std::io::Result::Err(e.into()),
                })
            }
        }
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> std::task::Poll<std::result::Result<(), std::io::Error>> {
        match self.get_mut() {
            ConnectorStream::TcpTlsClient(stream) => Pin::new(stream).poll_flush(cx),
            ConnectorStream::TcpTlsServer(stream) => Pin::new(stream).poll_flush(cx),
            ConnectorStream::Quic((stream, _)) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> std::task::Poll<std::result::Result<(), std::io::Error>> {
        match self.get_mut() {
            ConnectorStream::TcpTlsClient(stream) => Pin::new(stream).poll_shutdown(cx),
            ConnectorStream::TcpTlsServer(stream) => Pin::new(stream).poll_shutdown(cx),
            ConnectorStream::Quic((stream, _)) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}

impl AsyncRead for ConnectorStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            ConnectorStream::TcpTlsClient(stream) => Pin::new(stream).poll_read(cx, buf),
            ConnectorStream::TcpTlsServer(stream) => Pin::new(stream).poll_read(cx, buf),
            ConnectorStream::Quic((_, stream)) => Pin::new(stream).poll_read(cx, buf),
        }
    }
}
