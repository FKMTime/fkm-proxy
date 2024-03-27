use std::{fs::File, io::BufReader, path::Path};
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};

pub fn load_certs(path: &Path) -> std::io::Result<Vec<CertificateDer<'static>>> {
    rustls_pemfile::certs(&mut BufReader::new(File::open(path)?)).collect()
}

pub fn load_keys(path: &Path) -> std::io::Result<PrivateKeyDer<'static>> {
    let key = rustls_pemfile::private_key(&mut BufReader::new(File::open(path)?))?.unwrap();
    Ok(key)
}

pub fn cert_from_str(cert: &str) -> std::io::Result<Vec<CertificateDer<'static>>> {
    rustls_pemfile::certs(&mut cert.as_bytes()).collect()
}

pub fn key_from_str(key: &str) -> std::io::Result<PrivateKeyDer<'static>> {
    let key = rustls_pemfile::private_key(&mut key.as_bytes())?.unwrap();
    Ok(key)
}
