use anyhow::Result;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub async fn write_raw_http_resp<T>(
    stream: &mut T,
    status: u16,
    status_str: &str,
    content: &str,
) -> Result<()>
where
    T: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let resp = construct_http_resp(status, status_str, content);
    stream.write_all(resp.as_bytes()).await?;
    Ok(())
}

/// cotent type: text/html
pub fn construct_http_resp(status: u16, status_str: &str, content: &str) -> String {
    format!(
        "HTTP/1.1 {status} {status_str}\r\n\
        Content-Length: {content_len}\r\n\
        Content-Type: text/html\r\n\
        Connection: close\r\n\
        \r\n\
        {content}",
        status = status,
        content_len = content.len(),
        content = content
    )
}

pub fn construct_http_redirect(url: &str) -> String {
    format!(
        "HTTP/1.1 301 Moved Permanently\r\nLocation: {}\r\nContent-Length: 0\r\n\r\n",
        url
    )
}
