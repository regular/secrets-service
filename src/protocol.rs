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
        let parts: Vec<&str> = s.split_whitespace().collect();
        match parts.as_slice() {
            ["set-passphrase", passphrase] => Ok(Command::SetPassphrase(passphrase.to_string())),
            ["encrypt", path] => Ok(Command::Encrypt(path.to_string())),
            ["decrypt", path] => Ok(Command::Decrypt(path.to_string())),
            _ => Err(ServiceError::Protocol("Invalid command format".to_string())),
        }
    }
}
