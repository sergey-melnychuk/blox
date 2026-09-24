//! `blox rpc`: a local Ethereum JSON-RPC endpoint whose signing methods are
//! served by a phone keystore over a Blox relay (BLOX.md §9).

pub mod qr;
mod queue;
mod server;
mod upstream;

pub use server::{Config, serve};
pub use upstream::RpcError;

pub const DEFAULT_RELAY: &str = "https://relay.example.com";
