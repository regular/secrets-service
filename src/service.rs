use std::path::{PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UnixListener;
use tokio::sync::Mutex;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, AsyncBufReadExt};
use std::path::Path;

use crate::crypto::{SecureKey, encrypt_stream, decrypt_stream};
use crate::error::ServiceError;
use crate::protocol::Command;
use crate::store::{mkdir_within, join_within};

struct KeyCache {
    key: Option<Arc<SecureKey>>,
    generation: u64,  // Track key generations for cleanup
}

pub struct SecretsService {
    store_path: PathBuf,
    timeout: Duration,
    key_cache: Arc<Mutex<KeyCache>>,
    cleanup_task: Mutex<Option<tokio::task::JoinHandle<()>>>,  // Track cleanup task
}

impl SecretsService {
    pub fn new(store_path: PathBuf, timeout: Duration) -> Self {
        Self {
            store_path,
            timeout,
            key_cache: Arc::new(Mutex::new(KeyCache {
                key: None,
                generation: 0,
            })),
            cleanup_task: Mutex::new(None),
        }
    }

    pub async fn run(self, listener: UnixListener) {
        let service = Arc::new(self);

        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    let service = service.clone();
                    tokio::spawn(async move {
                        if let Err(e) = service.handle_connection(stream).await {
                            tracing::error!("Connection error: {}", e);
                        }
                    });
                }
                Err(e) => {
                    tracing::error!("Accept error: {}", e);
                }
            }
        }
    }

    async fn handle_connection(
        &self,
        mut stream: tokio::net::UnixStream,
    ) -> Result<(), ServiceError> {
        use tokio::io::{BufReader};

        // Split stream for concurrent read/write
        let (reader, mut writer) = stream.split();
        let mut reader = BufReader::new(reader);
        
        // Read command line
        let mut command_line = String::new();
        reader.read_line(&mut command_line).await?;
        
        
        let command = command_line.trim().parse::<Command>()?;
        
        match command {
            Command::SetPassphrase(passphrase) => {
                self.set_passphrase(passphrase).await?;
                writer.write_all(b"ok\n").await?;
                writer.flush().await?;
            }
            Command::Encrypt(path) => {
                // Use reader stream directly as input
                self.encrypt_stream(&path, reader).await?;
                writer.write_all(b"ok\n").await?;
                writer.flush().await?;
            }
            Command::Decrypt(path) => {
                // Use writer stream directly as output
                self.decrypt_stream(&path, writer).await?;
                //writer.flush().await?;
            }
        }

        Ok(())
    }

    async fn set_passphrase(&self, passphrase: String) -> Result<(), ServiceError> {
        // Cancel any existing cleanup task
        if let Some(task) = self.cleanup_task.lock().await.take() {
            task.abort();
        }

        let key = SecureKey::new(&passphrase);
        let mut cache = self.key_cache.lock().await;
        
        // Increment generation and set new key
        cache.generation += 1;
        let current_gen = cache.generation;
        cache.key = Some(Arc::new(key));
        
        // Spawn cleanup task
        let cache_clone = self.key_cache.clone();
        let timeout = self.timeout;
        let cleanup_task = tokio::spawn(async move {
            tokio::time::sleep(timeout).await;
            
            let mut cache = cache_clone.lock().await;
            // Only clear if we're still on the same key generation
            if cache.generation == current_gen {
                cache.key = None;
                tracing::info!("Key automatically cleared after timeout");
            }
        });

        // Store cleanup task
        *self.cleanup_task.lock().await = Some(cleanup_task);
        
        Ok(())
    }

    async fn get_key(&self) -> Result<Arc<SecureKey>, ServiceError> {
        let cache = self.key_cache.lock().await;
        cache.key.clone().ok_or(ServiceError::NoKey)
    }

    async fn encrypt_stream<R>(&self, path: &str, reader: R) -> Result<(), ServiceError>
    where
        R: AsyncRead + Unpin,
    {
        let key = self.get_key().await?;
        let file_path = mkdir_within(&self.store_path, Path::new(path))?;
        let writer = tokio::fs::File::create(file_path).await?;
        
        encrypt_stream(key, path, reader, writer).await
    }

    async fn decrypt_stream<W>(&self, path: &str, writer: W) -> Result<(), ServiceError>
    where
        W: AsyncWrite + Unpin,
    {
        let key = self.get_key().await?;
        let file_path = join_within(&self.store_path, Path::new(path))?;
        let reader = tokio::fs::File::open(file_path).await?;
        
        decrypt_stream(key, path, reader, writer).await
    }
}
