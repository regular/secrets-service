use std::{env, time::Duration, path::PathBuf};
use tokio::net::UnixListener;
use std::os::unix::fs::PermissionsExt;

mod crypto;
mod error;
mod protocol;
mod service;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    // Initialize sodiumoxide
    sodiumoxide::init().expect("Failed to initialize sodiumoxide");

    let socket_path = env::var("SECRETS_SOCKET")
        .expect("SECRETS_SOCKET must be set");
    let store_path = env::var("SECRETS_STORE")
        .expect("SECRETS_STORE must be set");
    let timeout = env::var("SECRETS_TIMEOUT")
        .map(|s| s.parse::<u64>().expect("Invalid SECRETS_TIMEOUT"))
        .expect("SECRETS_TIMEOUT must be set");

    let service = service::SecretsService::new(
        PathBuf::from(store_path),
        Duration::from_secs(timeout),
    );

    // Remove existing socket if any
    let _ = std::fs::remove_file(&socket_path);

    let listener = UnixListener::bind(&socket_path)
        .expect("Failed to bind to socket");

    // Set socket permissions
    std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600))
        .expect("Failed to set socket permissions");

    service.run(listener).await;
}
