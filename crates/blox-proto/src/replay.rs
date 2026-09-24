//! Freshness and replay checks (§4.6), kept per session.

use std::collections::HashSet;

use crate::message::{Message, MsgId};
use crate::{Error, Result};

pub const MAX_SKEW_SECS: u64 = 300;

#[derive(Default)]
pub struct Seen(HashSet<MsgId>);

impl Seen {
    /// Accepts each message id once, and only if `ts` is within ±300 s of `now`.
    pub fn check(&mut self, msg: &Message, now: u64) -> Result<()> {
        if msg.ts.abs_diff(now) > MAX_SKEW_SECS {
            return Err(Error::Stale);
        }
        if !self.0.insert(msg.id) {
            return Err(Error::Replay);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::{Body, Close, CloseReason};

    #[test]
    fn rejects_replay_and_stale() {
        let mut seen = Seen::default();
        let m = Message::new(Body::Close(Close {
            reason: CloseReason::Done,
        }));
        seen.check(&m, m.ts).unwrap();
        assert!(matches!(seen.check(&m, m.ts), Err(Error::Replay)));
        let old = Message {
            ts: m.ts - 301,
            ..Message::new(m.body.clone())
        };
        assert!(matches!(seen.check(&old, m.ts), Err(Error::Stale)));
    }
}
