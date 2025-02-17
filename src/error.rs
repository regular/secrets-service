use thiserror::Error;

#[derive(Error, Debug)]
pub enum ServiceError {
    #[error("No key in cache")]
    NoKey,

    #[error("Store error: {0}")]
    Store(#[from] std::io::Error),

    #[error("Encryption error: {0}")]
    Encryption(String),

    #[error("Protocol error: {0}")]
    Protocol(String),
}
