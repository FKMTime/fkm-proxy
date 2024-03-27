use aes_gcm::{
    aead::{Aead, OsRng},
    AeadCore, Aes128Gcm, KeyInit, Nonce,
};
use anyhow::Result;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const BUF_SIZE: usize = 8192;

pub async fn copy_bidirectional_enc<T1, T2>(
    encrypted: &mut T1,
    decrypted: &mut T2,
    token: u128,
) -> Result<()>
where
    T1: AsyncRead + AsyncWrite + Unpin,
    T2: AsyncRead + AsyncWrite + Unpin,
{
    let mut enc_buf = [0u8; BUF_SIZE];
    let mut dec_buf = [0u8; BUF_SIZE];

    let cipher = Aes128Gcm::new_from_slice(token.to_be_bytes().as_ref()).unwrap();
    loop {
        tokio::select! {
            n = encrypted.read_u32() => {
                let n = n? as usize;
                encrypted.read_exact(&mut enc_buf[0..12]).await?; // read nonce
                let nonce = enc_buf[0..12].to_vec();
                let nonce = Nonce::from_slice(&nonce);

                encrypted.read_exact(&mut enc_buf[..n]).await?;
                let decrypted_buff = cipher
                    .decrypt(nonce, &enc_buf[..n])
                    .map_err(|_| anyhow::anyhow!("Cant decrypt!"))?;

                decrypted.write_all(&decrypted_buff).await?;
            }
            n = decrypted.read(&mut dec_buf) => {
                let n = n? as usize;
                let nonce = Aes128Gcm::generate_nonce(&mut OsRng); // 12 bytes

                let encrypted_buff = cipher
                    .encrypt(&nonce, &dec_buf[..n])
                    .map_err(|_| anyhow::anyhow!("Encryptione error!"))?;

                encrypted.write_u32(encrypted_buff.len() as u32).await?;
                encrypted.write_all(nonce.as_ref()).await?;
                encrypted.write_all(&encrypted_buff).await?;
            }
        }
    }

    //Ok(())
}
