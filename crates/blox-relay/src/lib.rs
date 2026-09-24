//! Blox relay (BLOX.md §8): a blind store-and-forward service for mailboxes.
//!
//! The relay never parses anything beyond the envelope header and never logs
//! mailbox ids, secrets, bodies or client addresses.

mod http;
mod limits;
mod store;

pub use http::{AppState, router};
pub use limits::Limits;
pub use store::Store;

/// Log filter for the relay: only the relay's own target, at `level`.
///
/// Dependencies are always silenced — `axum::serve` logs client addresses at
/// trace level, which §8.5 forbids — so operators can raise verbosity safely.
pub fn log_filter(level: &str) -> tracing_subscriber::EnvFilter {
    let level: tracing::Level = level.parse().unwrap_or(tracing::Level::INFO);
    tracing_subscriber::EnvFilter::new(format!("off,blox_relay={level}"))
}

/// Runs the periodic TTL / rate-limit sweep until the process exits.
pub async fn sweeper(state: AppState) {
    let mut tick = tokio::time::interval(std::time::Duration::from_secs(10));
    loop {
        tick.tick().await;
        state.sweep();
    }
}
