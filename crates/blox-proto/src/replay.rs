//! Freshness and replay checks (BLOX.md §4.8), kept per connection.

use std::collections::HashMap;

use crate::message::{Message, MsgId};
use crate::{Error, Result};

/// Accepted difference between a message's `ts` and the receiver's (relay) time.
pub const MAX_SKEW_SECS: u64 = 300;
/// How long a seen id is remembered.
pub const RETENTION_SECS: u64 = 600;

#[derive(Default, Clone)]
pub struct Seen(HashMap<MsgId, u64>);

impl Seen {
    /// Accepts each message id once, and only if `ts` is within ±300 s of `now`.
    pub fn check(&mut self, msg: &Message, now: u64) -> Result<()> {
        if msg.ts.abs_diff(now) > MAX_SKEW_SECS {
            return Err(Error::Stale);
        }
        if self.0.len() > 64 {
            self.0
                .retain(|_, seen| now.saturating_sub(*seen) < RETENTION_SECS);
        }
        if self.0.insert(msg.id, now).is_some() {
            return Err(Error::Replay);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::{Body, Empty};

    #[test]
    fn rejects_replay_and_stale_and_forgets_old_ids() {
        let mut seen = Seen::default();
        let m = Message::at(Body::Unbind(Empty {}), 1000);
        seen.check(&m, 1000).unwrap();
        assert!(matches!(seen.check(&m, 1000), Err(Error::Replay)));
        let old = Message::at(Body::Unbind(Empty {}), 699);
        assert!(matches!(seen.check(&old, 1000), Err(Error::Stale)));
        for i in 0..100 {
            seen.check(&Message::at(Body::Unbind(Empty {}), 1000 + i), 1000 + i)
                .unwrap();
        }
        assert!(seen.0.len() <= 101);
        let later = 1000 + RETENTION_SECS + 200;
        for i in 0..70 {
            seen.check(&Message::at(Body::Unbind(Empty {}), later), later + i)
                .unwrap();
        }
        assert!(seen.0.len() < 101, "old ids are dropped");
    }
}
