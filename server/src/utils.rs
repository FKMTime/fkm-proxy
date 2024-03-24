use anyhow::Result;
use tokio::{io::AsyncWriteExt, net::TcpStream};

pub async fn write_raw_http_resp(
    stream: &mut TcpStream,
    status: u32,
    status_str: &str,
    content: &str,
) -> Result<()> {
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

    stream.write_all(resp.as_bytes()).await?;
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
