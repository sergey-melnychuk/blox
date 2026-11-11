//! The relay's HTTP shapes (BLOX.md §8.2), shared by the relay and its clients.

use serde::{Deserialize, Serialize};

/// Header carrying a connection token.
pub const HEADER_TOKEN: &str = "blox-token";
/// Header carrying a one-time ticket.
pub const HEADER_TICKET: &str = "blox-ticket";

/// Machine-readable error codes in `{ "error": code }` bodies.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    Malformed,
    Unauthorized,
    /// The request's `ts` is too far from the relay's clock; resync and retry once.
    Clock,
    /// The token or the ticket has expired.
    Expired,
    Revoked,
    TicketUsed,
    TooLarge,
    RateLimited,
    QueueFull,
    WriterFull,
    ReadersFull,
    TicketsFull,
    Busy,
}

impl ErrorCode {
    pub fn status(self) -> u16 {
        match self {
            ErrorCode::Malformed => 400,
            ErrorCode::Unauthorized | ErrorCode::Clock | ErrorCode::Expired => 401,
            ErrorCode::Revoked => 403,
            ErrorCode::TicketUsed => 409,
            ErrorCode::TooLarge => 413,
            ErrorCode::RateLimited
            | ErrorCode::QueueFull
            | ErrorCode::WriterFull
            | ErrorCode::ReadersFull
            | ErrorCode::TicketsFull => 429,
            ErrorCode::Busy => 503,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorBody {
    pub error: ErrorCode,
}

/// `POST /v1/inbox/{id}` → 202.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Accepted {
    pub seq: u64,
}

/// `POST /v1/inbox/{id}/tickets` body.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TicketRegistration {
    #[serde(with = "crate::b64::array")]
    pub ticket_hash: [u8; 32],
    pub expires_at: u64,
}

/// One SSE `msg` event's data.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    pub seq: u64,
    /// Envelope bytes, unpadded base64url.
    pub body: String,
    pub age_ms: u64,
}

/// `GET /v1/info`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Info {
    pub version: String,
    /// The relay's clock (unix seconds). Clients sign with this time (§4.8).
    pub now: u64,
    pub limits: serde_json::Value,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_serialize_as_spec() {
        let v = serde_json::to_value(ErrorBody {
            error: ErrorCode::TicketUsed,
        })
        .unwrap();
        assert_eq!(v, serde_json::json!({"error": "ticket_used"}));
        assert_eq!(ErrorCode::WriterFull.status(), 429);
        assert_eq!(ErrorCode::Revoked.status(), 403);
    }
}
