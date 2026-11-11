use std::net::SocketAddr;
use std::time::Duration;

use blox_relay::{AppState, Limits, router, sweeper};
use clap::Parser;

/// Blox relay: blind store-and-forward between connected parties (BLOX.md §8).
///
/// BLOX_LOG sets the relay's log level (error|warn|info|debug|trace); dependencies stay silent.
#[derive(Parser)]
#[command(version)]
struct Args {
    /// Address to listen on. Put TLS (e.g. Caddy) in front of it.
    #[arg(long, env = "BLOX_LISTEN", default_value = "localhost:8080")]
    listen: SocketAddr,
    /// Take the client IP from X-Forwarded-For (only behind a trusted reverse proxy).
    #[arg(long, env = "BLOX_TRUST_PROXY")]
    trust_proxy: bool,
    #[arg(long, env = "BLOX_MAX_ENVELOPE_BYTES", default_value_t = Limits::default().max_envelope_bytes)]
    max_envelope_bytes: usize,
    #[arg(long, env = "BLOX_MESSAGE_TTL_SECS", default_value_t = Limits::default().message_ttl.as_secs())]
    message_ttl_secs: u64,
    #[arg(long, env = "BLOX_INBOX_MAX_MESSAGES", default_value_t = Limits::default().inbox_max_messages)]
    inbox_max_messages: usize,
    #[arg(long, env = "BLOX_INBOX_MAX_BYTES", default_value_t = Limits::default().inbox_max_bytes)]
    inbox_max_bytes: usize,
    #[arg(long, env = "BLOX_WRITER_MAX_MESSAGES", default_value_t = Limits::default().writer_max_messages)]
    writer_max_messages: usize,
    #[arg(long, env = "BLOX_INBOX_MAX_READERS", default_value_t = Limits::default().inbox_max_readers)]
    inbox_max_readers: usize,
    #[arg(long, env = "BLOX_CLOCK_SKEW_SECS", default_value_t = Limits::default().clock_skew_secs)]
    clock_skew_secs: u64,
    #[arg(long, env = "BLOX_MAX_TOKEN_LIFETIME_SECS", default_value_t = Limits::default().max_token_lifetime_secs)]
    max_token_lifetime_secs: u64,
    #[arg(long, env = "BLOX_TICKET_MAX_LIFETIME_SECS", default_value_t = Limits::default().ticket_max_lifetime_secs)]
    ticket_max_lifetime_secs: u64,
    #[arg(long, env = "BLOX_INBOX_MAX_TICKETS", default_value_t = Limits::default().inbox_max_tickets)]
    inbox_max_tickets: usize,
    #[arg(long, env = "BLOX_MAX_REVOCATIONS", default_value_t = Limits::default().max_revocations)]
    max_revocations: usize,
    #[arg(long, env = "BLOX_WRITER_WRITES_PER_MINUTE", default_value_t = Limits::default().writer_writes_per_minute)]
    writer_writes_per_minute: u32,
    #[arg(long, env = "BLOX_IP_WRITES_PER_MINUTE", default_value_t = Limits::default().ip_writes_per_minute)]
    ip_writes_per_minute: u32,
    #[arg(long, env = "BLOX_IP_MAX_READERS", default_value_t = Limits::default().ip_max_readers)]
    ip_max_readers: usize,
    #[arg(long, env = "BLOX_GLOBAL_MAX_BYTES", default_value_t = Limits::default().global_max_bytes)]
    global_max_bytes: usize,
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let level = std::env::var("BLOX_LOG").unwrap_or_else(|_| "info".into());
    tracing_subscriber::fmt()
        .with_env_filter(blox_relay::log_filter(&level))
        .init();
    let a = Args::parse();
    let limits = Limits {
        max_envelope_bytes: a.max_envelope_bytes,
        message_ttl: Duration::from_secs(a.message_ttl_secs),
        inbox_max_messages: a.inbox_max_messages,
        inbox_max_bytes: a.inbox_max_bytes,
        writer_max_messages: a.writer_max_messages,
        inbox_max_readers: a.inbox_max_readers,
        clock_skew_secs: a.clock_skew_secs,
        max_token_lifetime_secs: a.max_token_lifetime_secs,
        ticket_max_lifetime_secs: a.ticket_max_lifetime_secs,
        inbox_max_tickets: a.inbox_max_tickets,
        max_revocations: a.max_revocations,
        writer_writes_per_minute: a.writer_writes_per_minute,
        ip_writes_per_minute: a.ip_writes_per_minute,
        ip_max_readers: a.ip_max_readers,
        global_max_bytes: a.global_max_bytes,
    };
    let state = AppState::new(limits, a.trust_proxy);
    tokio::spawn(sweeper(state.clone()));
    let listener = tokio::net::TcpListener::bind(a.listen).await?;
    tracing::info!(listen = %a.listen, "blox-relay started");
    axum::serve(
        listener,
        router(state).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
}
