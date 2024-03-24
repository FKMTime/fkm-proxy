use std::{fs::File, io::BufReader, path::Path};

use anyhow::Result;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};

pub async fn write_raw_http_resp<T>(
    stream: &mut T,
    status: u32,
    status_str: &str,
    content: &str,
    ssl: bool,
    shared_proxy_state: &crate::structs::SharedProxyState,
) -> Result<()>
where
    T: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let resp = format!(
        "HTTP/1.1 {status} {status_str}\r\n\
        Content-Length: {content_len}\r\n\
        Connection: close\r\n\
        \r\n\
        {content}",
        status = status,
        content_len = content.len(),
        content = content
    );

    if ssl {
        let mut stream = shared_proxy_state
            .get_tls_acceptor()
            .await
            .accept(stream)
            .await?;

        stream.write_all(resp.as_bytes()).await?;
    } else {
        stream.write_all(resp.as_bytes()).await?;
    }
    Ok(())
}

pub fn get_raw_http_resp(status: u32, status_str: &str, content: &str) -> String {
    format!(
        "HTTP/1.1 {status} {status_str}\r\n\
        Content-Length: {content_len}\r\n\
        Connection: close\r\n\
        \r\n\
        {content}",
        status = status,
        content_len = content.len(),
        content = content
    )
}

pub fn load_certs(path: &Path) -> std::io::Result<Vec<CertificateDer<'static>>> {
    rustls_pemfile::certs(&mut BufReader::new(File::open(path)?)).collect()
}

pub fn load_keys(path: &Path) -> std::io::Result<PrivateKeyDer<'static>> {
    let key = rustls_pemfile::private_key(&mut BufReader::new(File::open(path)?))?.unwrap();
    Ok(key)
}
