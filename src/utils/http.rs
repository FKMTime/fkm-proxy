use anyhow::Result;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub async fn write_http_resp<T>(
    stream: &mut T,
    status: u16,
    status_str: &str,
    content: &str,
    content_type: &str,
) -> Result<()>
where
    T: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let resp = construct_http_resp(status, status_str, content, content_type);
    stream.write_all(resp.as_bytes()).await?;
    Ok(())
}

pub fn construct_http_resp(
    status: u16,
    status_str: &str,
    content: &str,
    content_type: &str,
) -> String {
    format!(
        "HTTP/1.1 {status} {status_str}\r\n\
        Content-Length: {content_len}\r\n\
        Content-Type: {content_type}\r\n\
        Connection: close\r\n\
        \r\n\
        {content}",
        content_len = content.len(),
    )
}

pub fn construct_raw_http_resp(
    status: u16,
    status_str: &str,
    content: &[u8],
    content_type: &str,
) -> Vec<u8> {
    let response = format!(
        "HTTP/1.1 {status} {status_str}\r\n\
        Content-Length: {content_len}\r\n\
        Content-Type: {content_type}\r\n\
        Connection: close\r\n\
        \r\n",
        content_len = content.len(),
    );

    let mut result = response.into_bytes();
    result.extend_from_slice(content);
    result
}

pub fn construct_http_redirect(url: &str) -> String {
    format!(
        "HTTP/1.1 301 Moved Permanently\r\nLocation: {}\r\nContent-Length: 0\r\n\r\n",
        url
    )
}
