use crate::error::ServiceError;
use sodiumoxide::crypto::secretstream::{Stream, Tag, Key, Header};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use futures::StreamExt;

pub struct SecureKey {
    key: Key,
}

impl SecureKey {
    pub fn new(passphrase: &str) -> Self {
        // Derive key using sodiumoxide's key derivation
        let salt = sodiumoxide::crypto::pwhash::gen_salt();
        let key = sodiumoxide::crypto::pwhash::derive_key(
            passphrase.as_bytes(),
            &salt,
            sodiumoxide::crypto::pwhash::OPSLIMIT_INTERACTIVE,
            sodiumoxide::crypto::pwhash::MEMLIMIT_INTERACTIVE,
        ).expect("Key derivation failed");

        // Protect memory pages
        unsafe {
            let ptr = &key as *const _ as *const libc::c_void;
            libc::mlock(ptr, std::mem::size_of_val(&key));
            libc::madvise(
                ptr,
                std::mem::size_of_val(&key),
                libc::MADV_DONTDUMP
            );
        }

        Self { key }
    }
}

impl Drop for SecureKey {
    fn drop(&mut self) {
        // Securely zero memory before unlocking
        unsafe {
            let ptr = &mut self.key as *mut _ as *mut libc::c_void;
            libc::explicit_bzero(ptr, std::mem::size_of_val(&self.key));
            libc::munlock(ptr, std::mem::size_of_val(&self.key));
        }
    }
}

pub async fn encrypt_stream<R, W>(
    key: Arc<SecureKey>,
    mut reader: R,
    mut writer: W,
) -> Result<(), ServiceError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let (mut stream, header) = Stream::init_push(&key.key)
        .map_err(|e| ServiceError::Encryption(e.to_string()))?;

    // Write header
    tokio::io::AsyncWriteExt::write_all(&mut writer, header.as_ref()).await?;

    let mut buffer = [0u8; 16384];
    loop {
        let n = tokio::io::AsyncReadExt::read(&mut reader, &mut buffer).await?;
        if n == 0 {
            // End of input
            let final_chunk = stream.push_last(&[], Tag::Final)
                .map_err(|e| ServiceError::Encryption(e.to_string()))?;
            tokio::io::AsyncWriteExt::write_all(&mut writer, &final_chunk).await?;
            break;
        }

        let encrypted = stream.push(&buffer[..n], Tag::Message)
            .map_err(|e| ServiceError::Encryption(e.to_string()))?;
        tokio::io::AsyncWriteExt::write_all(&mut writer, &encrypted).await?;
    }

    Ok(())
}

pub async fn decrypt_stream<R, W>(
    key: Arc<SecureKey>,
    mut reader: R,
    mut writer: W,
) -> Result<(), ServiceError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    // Read header
    let mut header = Header::default();
    tokio::io::AsyncReadExt::read_exact(&mut reader, header.as_mut()).await?;

    let mut stream = Stream::init_pull(&header, &key.key)
        .map_err(|e| ServiceError::Encryption(e.to_string()))?;

    let mut buffer = [0u8; 16384 + sodiumoxide::crypto::secretstream::ABYTES];
    loop {
        let n = tokio::io::AsyncReadExt::read(&mut reader, &mut buffer).await?;
        if n == 0 {
            break;
        }

        let (decrypted, tag) = stream.pull(&buffer[..n])
            .map_err(|e| ServiceError::Encryption(e.to_string()))?;
        
        tokio::io::AsyncWriteExt::write_all(&mut writer, &decrypted).await?;

        if tag == Tag::Final {
            break;
        }
    }

    Ok(())
}
