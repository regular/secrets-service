use crate::error::ServiceError;
use sodiumoxide::crypto::secretstream::{Stream, Tag, Key, Header};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use base64::{Engine as _, engine::general_purpose::STANDARD as base64_engine};

pub struct SecureKey {
    key: Key,
}

impl SecureKey {
    // A 32-byte salt encoded in base64
    const STATIC_SALT_B64: &'static str = "c2VjcmV0cy1zZXJ2aWNlLXN0YXRpYy1zYWx0MTIzNDU=";

    pub fn new(passphrase: &str) -> Self {
        // Decode the static salt using the standard base64 engine
        let salt_bytes = base64_engine
            .decode(Self::STATIC_SALT_B64)
            .expect("Invalid static salt base64");
        
        // Convert to sodiumoxide Salt type
        let salt = sodiumoxide::crypto::pwhash::Salt::from_slice(&salt_bytes)
            .expect("Invalid salt length");

        // Create a buffer for the key
        let mut key_bytes = [0u8; sodiumoxide::crypto::secretstream::KEYBYTES];
        
        // Derive the key using static salt
        sodiumoxide::crypto::pwhash::derive_key(
            &mut key_bytes,
            passphrase.as_bytes(),
            &salt,
            sodiumoxide::crypto::pwhash::OPSLIMIT_INTERACTIVE,
            sodiumoxide::crypto::pwhash::MEMLIMIT_INTERACTIVE,
        ).expect("Key derivation failed");

        // Convert to secretstream Key
        let key = Key::from_slice(&key_bytes)
            .expect("Invalid key length");

        // Protect memory pages
        unsafe {
            let ptr = &key as *const _ as *mut libc::c_void;
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
    path: &str,
    mut reader: R,
    mut writer: W,
) -> Result<(), ServiceError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let (mut stream, header) = Stream::init_push(&key.key)
        .map_err(|_| ServiceError::Encryption("Failed to initialize encryption stream".to_string()))?;

    // Write header
    tokio::io::AsyncWriteExt::write_all(&mut writer, header.as_ref()).await?;

    let mut buffer = [0u8; 16384];
    loop {
        let n = tokio::io::AsyncReadExt::read(&mut reader, &mut buffer).await?;
        if n == 0 {
            // End of input
            let final_chunk = stream.push(&[], Some(path.as_bytes()), Tag::Final)
                .map_err(|_| ServiceError::Encryption("Failed to write final encrypted chunk".to_string()))?;
            tokio::io::AsyncWriteExt::write_all(&mut writer, &final_chunk).await?;
            break;
        }

        let encrypted = stream.push(&buffer[..n], Some(path.as_bytes()), Tag::Message)
            .map_err(|_| ServiceError::Encryption("Failed to encrypt data chunk".to_string()))?;
        tokio::io::AsyncWriteExt::write_all(&mut writer, &encrypted).await?;
    }

    Ok(())
}
pub async fn decrypt_stream<R, W>(
    key: Arc<SecureKey>,
    path: &str,
    mut reader: R,
    mut writer: W,
) -> Result<(), ServiceError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    // Read header bytes
    let mut header_bytes = [0u8; sodiumoxide::crypto::secretstream::HEADERBYTES];
    tokio::io::AsyncReadExt::read_exact(&mut reader, &mut header_bytes).await?;

    // Create header from bytes
    let header = Header::from_slice(&header_bytes)
        .ok_or_else(|| ServiceError::Encryption("Invalid header".to_string()))?;

    let mut stream = Stream::init_pull(&header, &key.key)
        .map_err(|_| ServiceError::Encryption("Failed to initialize decryption stream".to_string()))?;

    let mut buffer = [0u8; 16384 + sodiumoxide::crypto::secretstream::ABYTES];
    loop {
        let n = tokio::io::AsyncReadExt::read(&mut reader, &mut buffer).await?;
        if n == 0 {
            break;
        }

        let (decrypted, tag) = stream.pull(&buffer[..n], Some(path.as_bytes()))
            .map_err(|_| ServiceError::Encryption("Failed to decrypt data chunk".to_string()))?;
        
        tokio::io::AsyncWriteExt::write_all(&mut writer, &decrypted).await?;

        if tag == Tag::Final {
            break;
        }
    }

    Ok(())
}
