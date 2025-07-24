use anyhow::Result;
use http::StatusCode;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub async fn write_http_resp<T>(
    stream: &mut T,
    status: u16,
    content: &str,
    content_type: &str,
) -> Result<()>
where
    T: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let resp = construct_http_resp(status, content, content_type);
    stream.write_all(resp.as_bytes()).await?;
    Ok(())
}

pub fn construct_http_resp(status: u16, content: &str, content_type: &str) -> String {
    let status_str = StatusCode::from_u16(status)
        .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR)
        .canonical_reason()
        .unwrap_or("Internal Server Error");

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

pub fn construct_raw_http_resp(status: u16, content: &[u8], content_type: &str) -> Vec<u8> {
    let status_str = StatusCode::from_u16(status)
        .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR)
        .canonical_reason()
        .unwrap_or("Internal Server Error");

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
    format!("HTTP/1.1 301 Moved Permanently\r\nLocation: {url}\r\nContent-Length: 0\r\n\r\n",)
}
