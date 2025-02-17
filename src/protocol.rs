use std::str::FromStr;
use crate::error::ServiceError;

pub enum Command {
    SetPassphrase(String),
    Encrypt(String),
    Decrypt(String),
}

impl FromStr for Command {
    type Err = ServiceError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut parts = s.splitn(2, " ");
            match (parts.next(), parts.next()) {
            (Some("set-passphrase"), Some(passphrase)) => Ok(Command::SetPassphrase(passphrase.to_string())),

            (Some("encrypt"), Some(path)) => Ok(Command::Encrypt(path.to_string())),
            (Some("decrypt"), Some(path)) => Ok(Command::Decrypt(path.to_string())),
            _ => Err(ServiceError::Protocol("Invalid command format".to_string())),
        }
    }
}
