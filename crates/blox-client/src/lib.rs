//! Rust requester for Blox (BLOX.md §9): connects to a phone keystore once with a QR code,
//! keeps the connection, and sends signing requests through the relay.

mod calls;
mod relay;
mod requester;
mod store;

pub use calls::{MessageSignature, Sent, SignedTx, TxCall};
pub use relay::{Delivery, RelayClient, Subscription, WriteAuth};
pub use requester::{Config, MAX_REQUEST_SECS, QrCallback, Requester, verify_connection};
pub use store::{ConnectionStore, FileStore, MemoryStore, StoredConnection};

use blox_proto::api::ErrorCode;
use blox_proto::message::RejectReason;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The relay refused the request (`relay_error`).
    #[error("relay refused the request: {0:?}")]
    Relay(ErrorCode),
    /// The relay couldn't be reached.
    #[error("network: {0}")]
    Network(String),
    #[error("no phone answered the QR code in time")]
    NoSigner,
    #[error("a second device answered the QR code; someone may have seen it")]
    Contested,
    #[error("the request expired before the phone answered")]
    Timeout,
    #[error("the connection was ended or has expired")]
    Disconnected,
    #[error("cancelled")]
    Cancelled,
    /// The phone refused the request (§6.4).
    #[error("rejected: {0:?}")]
    Rejected(RejectReason),
    /// Signed, but the endpoint refused it or didn't answer; look the hash up.
    #[error("failed ({tx_hash}): {error}")]
    Failed {
        tx_hash: blox_evm::B256,
        error: String,
    },
    /// A response failed the checks of §9.5.
    #[error("bad response: {0}")]
    BadResponse(String),
    #[error("connection store: {0}")]
    Store(std::io::Error),
    #[error(transparent)]
    Proto(#[from] blox_proto::Error),
}

impl From<reqwest::Error> for Error {
    fn from(e: reqwest::Error) -> Self {
        // reqwest errors can include the URL, which contains an inbox id; keep only the kind.
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
        Error::Network(kind.into())
    }
}

pub type Result<T> = std::result::Result<T, Error>;
