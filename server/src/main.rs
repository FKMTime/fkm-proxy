use anyhow::Result;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

#[tokio::main]
async fn main() -> Result<()> {
    let listener = TcpListener::bind("0.0.0.0:1337").await?;
    loop {
        let (mut stream, _) = listener.accept().await?;
        let mut client = TcpStream::connect("127.0.0.1:1069").await?;
        let mut in_buffer = [0; 8192];

        let n = stream.read(&mut in_buffer).await?;
        let mut start = 0;
        let mut stop = 0;
        for i in 0..n {
            if in_buffer[i] == b'\n' {
                if start == 0 {
                    start = i + 1;
                    continue;
                } else if stop == 0 {
                    stop = i - 1;
                    break;
                }
            }
        }

        // Skip "Host: " part of host header (to get host only)
        start += 6;

        let str = String::from_utf8_lossy(&in_buffer[start..stop]);
        println!("str: |{str}|");

        client.write(&in_buffer).await?;
        tokio::io::copy_bidirectional(&mut stream, &mut client).await?;
    }

    Ok(())
}
