//! Blox relay (BLOX.md §8): blind store-and-forward between connected parties.
//!
//! The relay checks tokens, tickets and request signatures, looks at nothing in an
//! envelope beyond its header, and never logs inbox ids, tokens, bodies or client addresses.

mod http;
mod limits;
mod store;

pub use http::{AppState, router};
pub use limits::Limits;
pub use store::{Stats, Store};

/// Log filter for the relay: only the relay's own target, at `level`.
///
/// Dependencies are always silenced — `axum::serve` logs client addresses at
/// trace level, which §8.5 forbids — so operators can raise verbosity safely.
pub fn log_filter(level: &str) -> tracing_subscriber::EnvFilter {
    let level: tracing::Level = level.parse().unwrap_or(tracing::Level::INFO);
    tracing_subscriber::EnvFilter::new(format!("off,blox_relay={level}"))
}

/// Runs the periodic sweep (message TTL, tickets, revocations, rate windows) until exit.
pub async fn sweeper(state: AppState) {
    let mut tick = tokio::time::interval(std::time::Duration::from_secs(10));
    loop {
        tick.tick().await;
        state.sweep();
    }
}
