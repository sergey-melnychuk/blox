#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("malformed input: {0}")]
    Malformed(&'static str),
    #[error("unsupported version {0}")]
    Version(u8),
    #[error("plaintext too large")]
    TooLarge,
    #[error("decryption or authentication failed")]
    Crypto,
    #[error("replayed message")]
    Replay,
    #[error("stale message")]
    Stale,
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
