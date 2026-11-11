//! Wire protocol for Blox (BLOX.md §2, §4, §5, §6).
//!
//! Everything here is transport-agnostic: the relay only ever sees the bytes
//! produced by [`envelope::Envelope::to_bytes`].

pub mod api;
pub mod b64;
pub mod base45;
pub mod envelope;
pub mod error;
pub mod ident;
pub mod keys;
pub mod mailbox;
pub mod message;
pub mod pad;
pub mod peer;
pub mod relay_url;
pub mod replay;
pub mod reqsig;
pub mod session;
pub mod statement;
pub mod token;

pub use error::{Error, Result};

/// Protocol version carried in the envelope header and the session payload.
pub const VERSION: u8 = 1;

#[cfg(test)]
mod vectors;
