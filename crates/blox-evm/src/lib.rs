//! EVM support for Blox: request decoding, keystore-side filling and signing, and
//! requester-side checks (BLOX.md §6.3, §9.5, §10.4).

pub mod caip;
pub mod connect;
pub mod display;
pub mod rpc;
pub mod sign;
pub mod tx;

pub use alloy_primitives::{Address, B256, U256};

pub const KIND_TX: &str = "evm.tx";
pub const KIND_TYPED_DATA: &str = "evm.typed_data";
pub const KIND_PERSONAL_SIGN: &str = "evm.personal_sign";

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("malformed: {0}")]
    Malformed(String),
    #[error("unsupported: {0}")]
    Unsupported(String),
    #[error("chain mismatch")]
    ChainMismatch,
    #[error("verification failed: {0}")]
    Verification(&'static str),
}

impl Error {
    pub(crate) fn malformed(e: impl std::fmt::Display) -> Self {
        Error::Malformed(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, Error>;

pub(crate) fn hex_bytes(s: &str) -> Result<Vec<u8>> {
    let h = s
        .strip_prefix("0x")
        .ok_or_else(|| Error::Malformed("hex without 0x".into()))?;
    hex::decode(h).map_err(Error::malformed)
}

/// `0x`-prefixed lowercase hex.
pub fn to_hex(b: impl AsRef<[u8]>) -> String {
    format!("0x{}", hex::encode(b))
}
