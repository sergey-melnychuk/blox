use std::time::Duration;

use serde::Serialize;

/// Defaults from §8.4. Published at `GET /v1/info`.
#[derive(Clone, Debug, Serialize)]
pub struct Limits {
    pub max_envelope_bytes: usize,
    #[serde(serialize_with = "secs")]
    pub message_ttl: Duration,
    pub mailbox_max_messages: usize,
    pub mailbox_max_bytes: usize,
    pub ip_writes_per_minute: u32,
    pub ip_max_readers: usize,
    pub global_max_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_envelope_bytes: 272 << 10,
            message_ttl: Duration::from_secs(600),
            mailbox_max_messages: 32,
            mailbox_max_bytes: 2 << 20,
            ip_writes_per_minute: 60,
            ip_max_readers: 16,
            global_max_bytes: 512 << 20,
        }
    }
}

fn secs<S: serde::Serializer>(d: &Duration, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_u64(d.as_secs())
}
