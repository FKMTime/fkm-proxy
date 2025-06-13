use anyhow::Result;
use std::{fs::File, io::BufReader, path::Path};
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};

pub fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    if !path.exists() {
        return Err(anyhow::anyhow!("Cert not found in path: {path:?}"));
    }

    rustls_pemfile::certs(&mut BufReader::new(File::open(path)?))
        .collect::<std::io::Result<_>>()
        .map_err(anyhow::Error::from)
}

pub fn load_keys(path: &Path) -> Result<PrivateKeyDer<'static>> {
    if !path.exists() {
        return Err(anyhow::anyhow!("Private key not found in path: {path:?}"));
    }

    rustls_pemfile::private_key(&mut BufReader::new(File::open(path)?))?
        .ok_or_else(|| anyhow::anyhow!("Private key returned None"))
}

pub fn cert_from_str(cert: &str) -> Result<Vec<CertificateDer<'static>>> {
    rustls_pemfile::certs(&mut cert.as_bytes())
        .collect::<std::io::Result<_>>()
        .map_err(anyhow::Error::from)
}

pub fn key_from_str(key: &str) -> Result<PrivateKeyDer<'static>> {
    rustls_pemfile::private_key(&mut key.as_bytes())?
        .ok_or_else(|| anyhow::anyhow!("Private ket returned None"))
}
