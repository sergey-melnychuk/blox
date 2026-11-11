use std::time::Duration;

use serde::Serialize;

/// Defaults from BLOX.md §8.4. Published at `GET /v1/info`.
#[derive(Clone, Debug, Serialize)]
pub struct Limits {
    pub max_envelope_bytes: usize,
    #[serde(serialize_with = "secs")]
    pub message_ttl: Duration,
    pub inbox_max_messages: usize,
    pub inbox_max_bytes: usize,
    /// Messages one writer may have queued in one inbox.
    pub writer_max_messages: usize,
    pub inbox_max_readers: usize,
    /// Allowed clock difference for request signatures and a token's `issued_at`.
    pub clock_skew_secs: u64,
    pub max_token_lifetime_secs: u64,
    pub ticket_max_lifetime_secs: u64,
    pub inbox_max_tickets: usize,
    pub max_revocations: usize,
    pub writer_writes_per_minute: u32,
    pub ip_writes_per_minute: u32,
    pub ip_max_readers: usize,
    pub global_max_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_envelope_bytes: 272 << 10,
            message_ttl: Duration::from_secs(300),
            inbox_max_messages: 32,
            inbox_max_bytes: 2 << 20,
            writer_max_messages: 4,
            inbox_max_readers: 8,
            clock_skew_secs: 60,
            max_token_lifetime_secs: 90 * 24 * 3600,
            ticket_max_lifetime_secs: 180,
            inbox_max_tickets: 4,
            max_revocations: 100_000,
            writer_writes_per_minute: 60,
            ip_writes_per_minute: 60,
            ip_max_readers: 16,
            global_max_bytes: 512 << 20,
        }
    }
}

fn secs<S: serde::Serializer>(d: &Duration, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_u64(d.as_secs())
}
