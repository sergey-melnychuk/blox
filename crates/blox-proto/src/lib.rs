//! Wire protocol for Blox (BLOX.md §2, §4, §5, §6).
//!
//! Everything here is transport-agnostic: the relay only ever sees envelope bytes,
//! tokens, tickets and request signatures.

pub mod api;
pub mod b64;
pub mod base45;
pub mod connection;
pub mod envelope;
pub mod error;
pub mod ident;
pub mod keys;
pub mod message;
pub mod offer;
pub mod pad;
pub mod relay_url;
pub mod replay;
pub mod reqsig;
pub mod statement;
pub mod token;

pub use error::{Error, Result};

/// Protocol version carried in envelopes, tokens and offers.
pub const VERSION: u8 = 1;

#[cfg(test)]
mod vectors;
