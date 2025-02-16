use thiserror::Error;

#[derive(Error, Debug)]
pub enum ServiceError {
    #[error("No key in cache")]
    NoKey,
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Encryption error: {0}")]
    Encryption(String),
    #[error("Protocol error: {0}")]
    Protocol(String),
}
