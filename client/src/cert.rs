use std::{fs::File, io::BufReader, path::Path};

use crate::utils::generate_hello_packet;
use acme_lib::{persist::FilePersist, Directory, DirectoryUrl};
use anyhow::Result;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};

pub async fn cert_loader(
    token: u128,
    hash: u64,
    proxy_addr: &str,
    cert_path: &str,
    email: &str,
) -> Result<(String, String)> {
    if let Ok((key, crt)) = get_crt_key(Path::new(cert_path)) {
        return Ok((key, crt));
    }

    println!("Certificate not found, generating new one");
    let url = DirectoryUrl::LetsEncryptStaging;
    let persist = FilePersist::new(cert_path);
    let dir = Directory::from_url(persist, url)?;

    let acc = dir.account(email)?;
    let domain = crate::utils::get_domain_by_hash(hash, proxy_addr.to_string()).await?;
    let mut ord_new = acc.new_order(&domain, &[])?;

    let ord_csr = loop {
        if let Some(ord_csr) = ord_new.confirm_validations() {
            break ord_csr;
        }

        println!("Starting acme challenge responder");

        let auths = ord_new.authorizations()?;
        let chall = auths[0].http_challenge();
        let acme_token = chall.http_token();
        let path = format!("/.well-known/acme-challenge/{}", acme_token);
        let proof = chall.http_proof();

        let task = tokio::task::spawn(spawn_acme_responder(
            token,
            hash,
            proxy_addr.to_string(),
            proof,
            path,
        ));

        chall.validate(5000)?;
        task.abort();

        ord_new.refresh()?;
    };

    let pkey_pri = acme_lib::create_p384_key();
    let ord_cert = ord_csr.finalize_pkey(pkey_pri, 5000)?;
    _ = ord_cert.download_and_save_cert()?;

    println!("Certificate generated successfully");
    get_crt_key(Path::new(cert_path))
}

async fn spawn_acme_responder(
    token: u128,
    hash: u64,
    proxy_addr: String,
    acme_proof: String,
    acme_url: String,
) -> Result<()> {
    let mut connector = TcpStream::connect(&proxy_addr).await?;
    let hello_packet = generate_hello_packet(0, &token, &hash);
    connector.write_all(&hello_packet).await?;

    loop {
        _ = connector.read_u8().await?;
        let hello_packet = generate_hello_packet(1, &token, &hash);

        let mut tunnel_stream = TcpStream::connect(&proxy_addr).await?;
        tunnel_stream.set_nodelay(true)?;
        tunnel_stream.write_all(&hello_packet).await?;

        let mut parts = String::new();
        let mut buffer = [0u8; 1];
        loop {
            tunnel_stream.read(&mut buffer).await?;
            if buffer[0] == 0x0A {
                break;
            }
            parts.push(buffer[0] as char);
        }

        let parts = parts.trim().split(" ").collect::<Vec<&str>>();
        let url = parts[1];

        if url == acme_url {
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
                acme_proof.len(),
                acme_proof
            );

            tunnel_stream.write_all(response.as_bytes()).await?;
        }
    }

    // Ok(())
}

fn get_crt_key(cert_path: &Path) -> Result<(String, String)> {
    let cert_path = Path::new(cert_path);
    if cert_path.exists() {
        let files = std::fs::read_dir(cert_path)?;

        // filter out key_acme_account and directories
        let files = files.filter(|x| {
            !x.as_ref()
                .unwrap()
                .file_name()
                .to_str()
                .unwrap()
                .contains("key_acme_account")
                && !x.as_ref().unwrap().metadata().unwrap().is_dir()
        });

        let mut crt = None;
        let mut key = None;

        for file in files {
            let file = file.unwrap();
            let path = file.path();
            let ext = path.extension().unwrap();
            match ext.to_str().unwrap() {
                "crt" => {
                    crt = Some(path.to_str().unwrap().to_string());
                }
                "key" => {
                    key = Some(path.to_str().unwrap().to_string());
                }
                _ => {}
            }
        }

        if key.is_some() && crt.is_some() {
            return Ok((key.unwrap(), crt.unwrap()));
        }
    }

    Err(anyhow::anyhow!("Certificate not found"))
}

pub fn load_certs(path: &Path) -> std::io::Result<Vec<CertificateDer<'static>>> {
    rustls_pemfile::certs(&mut BufReader::new(File::open(path)?)).collect()
}

pub fn load_keys(path: &Path) -> std::io::Result<PrivateKeyDer<'static>> {
    let key = rustls_pemfile::private_key(&mut BufReader::new(File::open(path)?))?.unwrap();
    Ok(key)
}
