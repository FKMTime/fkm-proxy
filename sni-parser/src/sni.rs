use anyhow::{anyhow, bail, Result};
use rustls::server::Acceptor;

pub fn parse_sni(buf: &[u8]) -> Result<String> {
    if buf.len() == 0 {
        bail!("Buf len 0");
    }

    let content_type = buf[0]; // 2bytes
    let version = &buf[1..3]; // 2bytes
    let len: u16 = u16::from_be_bytes([buf[3], buf[4]]); // 2bytes
    println!("content_type: {content_type}, version: {version:02X?}, len: {len}");
    if content_type != 22 || len == 0 {
        bail!("[ERROR] not handshake packet or len 0");
    }

    let handshake_type = buf[5]; // 1byte
    if handshake_type != 1 {
        bail!("[ERROR] not client hello");
    }

    let len = buf[8] as u32 + ((buf[7] as u32) << 8) + ((buf[6] as u32) << 16); // 3bytes (be)
    println!("client_hello_len: {len}");

    let version = &buf[9..11]; // 2bytes
    let random = &buf[11..43]; // 32bytes(always)
    let session_id_length = buf[43] as usize; // 1byte
    let session_id = &buf[44..(44 + session_id_length)]; //32 bytes in my testing (need to parse)

    println!("ver: {version:02X?}, random: {random:02X?}, session_id_len: {session_id_length}, session_id: {session_id:02X?}");

    let cipher_suites_len: u16 = u16::from_be_bytes([
        buf[44 + session_id_length + 0],
        buf[44 + session_id_length + 1],
    ]); // 2bytes
    println!("cip_len: {cipher_suites_len}");

    let mut offset: usize = 44 + session_id_length + 2 + cipher_suites_len as usize;
    let compression_methods_len = buf[offset] as usize; // 1byte
    offset += 1 + compression_methods_len;

    let mut extensions_len: u16 = u16::from_be_bytes([buf[offset], buf[offset + 1]]); // 2bytes
    println!("extensions_len: {extensions_len}");

    offset += 2;
    while extensions_len > 0 {
        let ext_type: u16 = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
        let ext_len: u16 = u16::from_be_bytes([buf[offset + 2], buf[offset + 3]]);
        offset += 4;

        if ext_type == 0 {
            // server_name

            let server_name_list_length: u16 = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
            println!("server_name_list_length: {server_name_list_length}");

            // is this shit a list????? (parse with loop???)
            let server_name_type = buf[offset + 2];
            let server_name_length: u16 = u16::from_be_bytes([buf[offset + 3], buf[offset + 4]]);
            let server_name = &buf[(offset + 5)..(offset + 5 + server_name_length as usize)];
            let server_name = core::str::from_utf8(server_name)?;
            println!("server_name_type: {server_name_type}, server_name_length: {server_name_length}, server_name: {server_name:?}");

            if server_name_type == 0 {
                return Ok(server_name.to_string());
            }
        }

        println!("ext_type: {ext_type}, ext_len: {ext_len}");
        offset += ext_len as usize;

        extensions_len -= 4 + ext_len;
    }

    bail!("[ERROR] SNI NOT FOUND!")
}

pub fn rustls_parse_sni(buf: &[u8]) -> Result<String> {
    let mut acceptor = Acceptor::default();
    let mut n_buf = &buf[..];
    acceptor.read_tls(&mut n_buf)?;

    let accepted = acceptor
        .accept()
        .map_err(|e| anyhow!("{e:?}"))?
        .ok_or_else(|| anyhow!("No tls msg"))?;

    Ok(accepted
        .client_hello()
        .server_name()
        .ok_or_else(|| anyhow!("No server name"))?
        .to_string())
}
