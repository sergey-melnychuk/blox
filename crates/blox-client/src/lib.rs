//! Adapter-side client for the Blox relay (BLOX.md §5, §8.2, §9.9).
//!
//! [`RelayClient`] speaks the relay's HTTP API; [`Signer`] opens a one-shot
//! session and [`Session`] sends signing requests over it.

mod relay;
mod session;

pub use relay::{Delivery, RelayClient, Subscription};
pub use session::{Session, Signer};

use blox_proto::message::CloseReason;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("relay: {0}")]
    Relay(String),
    #[error("relay rejected the read secret")]
    Unauthorized,
    #[error("no signer joined")]
    NoSignerJoined,
    #[error("session aborted: another device joined")]
    Contested,
    #[error("session closed ({0:?})")]
    Closed(CloseReason),
    #[error("timed out waiting for the signer")]
    Timeout,
    #[error(transparent)]
    Proto(#[from] blox_proto::Error),
}

impl From<reqwest::Error> for Error {
    fn from(e: reqwest::Error) -> Self {
        // reqwest errors can include the URL, which contains a mailbox id; keep only the kind.
        let kind = if e.is_timeout() {
            "timeout"
        } else if e.is_connect() {
            "connect"
        } else if e.is_status() {
            "status"
        } else if e.is_body() || e.is_decode() {
            "body"
        } else {
            "request"
        };
        Error::Relay(kind.into())
    }
}

pub type Result<T> = std::result::Result<T, Error>;
