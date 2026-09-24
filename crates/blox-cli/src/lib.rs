//! `blox rpc`: a local Ethereum JSON-RPC endpoint whose signing methods are
//! served by a phone keystore over a Blox relay (BLOX.md §9). The signing logic
//! lives in `blox-adapter`; this crate adds the HTTP server and terminal output.

pub mod qr;
mod server;

pub use server::{Config, OnQr, serve};

pub const DEFAULT_RELAY: &str = blox_proto::session::DEFAULT_RELAY;
