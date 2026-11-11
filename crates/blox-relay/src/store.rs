//! In-memory inboxes, tickets and revocations (BLOX.md §8.3). Nothing is written to disk.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use blox_proto::api::ErrorCode;
use bytes::Bytes;
use tokio::sync::Notify;

use crate::Limits;

/// An inbox key or writer key: the raw Ed25519 public key.
pub type Key = [u8; 32];

/// Who wrote a message, for the per-writer limit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Writer {
    /// The token's other party.
    Key(Key),
    /// A ticket write (the first message of a connection).
    Ticket,
}

#[derive(Clone)]
pub struct Queued {
    pub seq: u64,
    pub body: Bytes,
    pub enqueued: Instant,
    writer: Writer,
}

struct Inbox {
    next_seq: u64,
    queue: VecDeque<Queued>,
    bytes: usize,
    readers: usize,
    notify: Arc<Notify>,
}

impl Default for Inbox {
    fn default() -> Self {
        Self {
            next_seq: 0,
            queue: VecDeque::new(),
            bytes: 0,
            readers: 0,
            notify: Arc::new(Notify::new()),
        }
    }
}

impl Inbox {
    fn is_idle(&self) -> bool {
        self.queue.is_empty() && self.readers == 0
    }
}

struct Ticket {
    inbox: Key,
    expires_at: u64,
    used: bool,
}

pub struct Store {
    inner: Mutex<Inner>,
    limits: Limits,
}

#[derive(Default)]
struct Inner {
    inboxes: HashMap<Key, Inbox>,
    total_bytes: usize,
    tickets: HashMap<[u8; 32], Ticket>,
    /// token_id → the token's `expires_at`.
    revoked: HashMap<[u8; 32], u64>,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Stats {
    pub inboxes: usize,
    pub messages: usize,
    pub bytes: usize,
    pub readers: usize,
    pub tickets: usize,
    pub revocations: usize,
}

impl Store {
    pub fn new(limits: Limits) -> Self {
        Self {
            inner: Mutex::default(),
            limits,
        }
    }

    /// Queues a message written with a token.
    pub fn push(&self, inbox: Key, body: Bytes, writer: Writer) -> Result<u64, ErrorCode> {
        let mut inner = self.inner.lock().unwrap();
        inner.push(&self.limits, inbox, body, writer)
    }

    /// Queues a `bind` written with a ticket, and marks the ticket used (atomically).
    pub fn push_with_ticket(
        &self,
        inbox: Key,
        ticket_hash: [u8; 32],
        body: Bytes,
        now: u64,
    ) -> Result<u64, ErrorCode> {
        let mut inner = self.inner.lock().unwrap();
        match inner.tickets.get(&ticket_hash) {
            Some(t) if t.inbox != inbox => return Err(ErrorCode::Unauthorized),
            Some(t) if t.used => return Err(ErrorCode::TicketUsed),
            Some(t) if t.expires_at <= now => return Err(ErrorCode::Expired),
            Some(_) => {}
            None => return Err(ErrorCode::Unauthorized),
        }
        let seq = inner.push(&self.limits, inbox, body, Writer::Ticket)?;
        inner.tickets.get_mut(&ticket_hash).unwrap().used = true;
        Ok(seq)
    }

    pub fn register_ticket(
        &self,
        inbox: Key,
        ticket_hash: [u8; 32],
        expires_at: u64,
        now: u64,
    ) -> Result<(), ErrorCode> {
        let mut inner = self.inner.lock().unwrap();
        if let Some(t) = inner.tickets.get(&ticket_hash) {
            // Re-registering the same live ticket is harmless; anything else is not allowed.
            return if t.inbox == inbox && !t.used && t.expires_at > now {
                Ok(())
            } else {
                Err(ErrorCode::Unauthorized)
            };
        }
        let live = inner
            .tickets
            .values()
            .filter(|t| t.inbox == inbox && !t.used && t.expires_at > now)
            .count();
        if live >= self.limits.inbox_max_tickets {
            return Err(ErrorCode::TicketsFull);
        }
        inner.tickets.insert(
            ticket_hash,
            Ticket {
                inbox,
                expires_at,
                used: false,
            },
        );
        Ok(())
    }

    /// Records a revoked token until it would have expired anyway.
    pub fn revoke(&self, token_id: [u8; 32], expires_at: u64) -> Result<(), ErrorCode> {
        let mut inner = self.inner.lock().unwrap();
        if !inner.revoked.contains_key(&token_id)
            && inner.revoked.len() >= self.limits.max_revocations
        {
            return Err(ErrorCode::Busy);
        }
        inner.revoked.insert(token_id, expires_at);
        Ok(())
    }

    pub fn is_revoked(&self, token_id: &[u8; 32]) -> bool {
        self.inner.lock().unwrap().revoked.contains_key(token_id)
    }

    /// Registers a reader. Every reader of an inbox gets every message.
    pub fn attach_reader(&self, inbox: Key) -> Result<Arc<Notify>, ErrorCode> {
        let mut inner = self.inner.lock().unwrap();
        let ib = inner.inboxes.entry(inbox).or_default();
        if ib.readers >= self.limits.inbox_max_readers {
            let idle = ib.is_idle();
            if idle {
                inner.inboxes.remove(&inbox);
            }
            return Err(ErrorCode::ReadersFull);
        }
        ib.readers += 1;
        Ok(ib.notify.clone())
    }

    pub fn detach_reader(&self, inbox: &Key) {
        let mut inner = self.inner.lock().unwrap();
        if let Some(ib) = inner.inboxes.get_mut(inbox) {
            ib.readers = ib.readers.saturating_sub(1);
            if ib.is_idle() {
                inner.inboxes.remove(inbox);
            }
        }
    }

    /// Queued messages after `after`, in sequence order.
    pub fn pending(&self, inbox: &Key, after: Option<u64>) -> Vec<Queued> {
        let inner = self.inner.lock().unwrap();
        inner.inboxes.get(inbox).map_or_else(Vec::new, |ib| {
            ib.queue
                .iter()
                .filter(|q| after.is_none_or(|a| q.seq > a))
                .cloned()
                .collect()
        })
    }

    pub fn ack(&self, inbox: &Key, seq: u64) {
        let mut inner = self.inner.lock().unwrap();
        let Some(ib) = inner.inboxes.get_mut(inbox) else {
            return;
        };
        let mut freed = 0;
        if let Some(pos) = ib.queue.iter().position(|q| q.seq == seq) {
            let q = ib.queue.remove(pos).unwrap();
            ib.bytes -= q.body.len();
            freed = q.body.len();
        }
        if ib.is_idle() {
            inner.inboxes.remove(inbox);
        }
        inner.total_bytes -= freed;
    }

    /// Drops expired messages, tickets and revocations, and idle inboxes.
    pub fn sweep(&self, now: Instant, now_unix: u64) {
        let ttl = self.limits.message_ttl;
        let mut inner = self.inner.lock().unwrap();
        let mut freed = 0;
        inner.inboxes.retain(|_, ib| {
            while ib
                .queue
                .front()
                .is_some_and(|q| now.duration_since(q.enqueued) >= ttl)
            {
                let q = ib.queue.pop_front().unwrap();
                ib.bytes -= q.body.len();
                freed += q.body.len();
            }
            !ib.is_idle()
        });
        inner.total_bytes -= freed;
        inner.tickets.retain(|_, t| t.expires_at > now_unix);
        inner.revoked.retain(|_, exp| *exp > now_unix);
    }

    pub fn stats(&self) -> Stats {
        let inner = self.inner.lock().unwrap();
        Stats {
            inboxes: inner.inboxes.len(),
            messages: inner.inboxes.values().map(|m| m.queue.len()).sum(),
            bytes: inner.total_bytes,
            readers: inner.inboxes.values().map(|m| m.readers).sum(),
            tickets: inner.tickets.len(),
            revocations: inner.revoked.len(),
        }
    }
}

impl Inner {
    fn push(
        &mut self,
        limits: &Limits,
        inbox: Key,
        body: Bytes,
        writer: Writer,
    ) -> Result<u64, ErrorCode> {
        if self.total_bytes + body.len() > limits.global_max_bytes {
            return Err(ErrorCode::Busy);
        }
        let ib = self.inboxes.entry(inbox).or_default();
        let full = ib.queue.len() >= limits.inbox_max_messages
            || ib.bytes + body.len() > limits.inbox_max_bytes;
        let writer_full = matches!(writer, Writer::Key(_))
            && ib.queue.iter().filter(|q| q.writer == writer).count() >= limits.writer_max_messages;
        if full || writer_full {
            if ib.is_idle() {
                self.inboxes.remove(&inbox);
            }
            return Err(if writer_full {
                ErrorCode::WriterFull
            } else {
                ErrorCode::QueueFull
            });
        }
        let seq = ib.next_seq;
        ib.next_seq += 1;
        ib.bytes += body.len();
        let len = body.len();
        ib.queue.push_back(Queued {
            seq,
            body,
            enqueued: Instant::now(),
            writer,
        });
        ib.notify.notify_waiters();
        self.total_bytes += len;
        Ok(seq)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn key(n: u8) -> Key {
        [n; 32]
    }

    #[test]
    fn push_read_ack_cleans_up() {
        let s = Store::new(Limits::default());
        let (m, w) = (key(1), Writer::Key(key(2)));
        assert_eq!(s.push(m, Bytes::from_static(b"a"), w).unwrap(), 0);
        assert_eq!(s.push(m, Bytes::from_static(b"b"), w).unwrap(), 1);
        let _n = s.attach_reader(m).unwrap();
        let p = s.pending(&m, None);
        assert_eq!(p.iter().map(|q| q.seq).collect::<Vec<_>>(), [0, 1]);
        assert_eq!(s.pending(&m, Some(0)).len(), 1);
        s.ack(&m, 0);
        s.ack(&m, 1);
        s.ack(&m, 1);
        s.detach_reader(&m);
        assert_eq!(s.stats(), Stats::default());
    }

    #[test]
    fn several_readers_and_their_limit() {
        let s = Store::new(Limits {
            inbox_max_readers: 2,
            ..Limits::default()
        });
        let m = key(1);
        s.attach_reader(m).unwrap();
        s.attach_reader(m).unwrap();
        assert_eq!(s.attach_reader(m).unwrap_err(), ErrorCode::ReadersFull);
        s.detach_reader(&m);
        s.attach_reader(m).unwrap();
        assert_eq!(s.stats().readers, 2);
    }

    #[test]
    fn per_writer_quota_and_ttl() {
        let s = Store::new(Limits {
            writer_max_messages: 2,
            message_ttl: Duration::from_secs(1),
            ..Limits::default()
        });
        let m = key(1);
        let (a, b) = (Writer::Key(key(2)), Writer::Key(key(3)));
        s.push(m, Bytes::from_static(b"1"), a).unwrap();
        s.push(m, Bytes::from_static(b"2"), a).unwrap();
        assert_eq!(
            s.push(m, Bytes::from_static(b"3"), a),
            Err(ErrorCode::WriterFull)
        );
        s.push(m, Bytes::from_static(b"4"), b).unwrap();
        s.sweep(Instant::now() + Duration::from_secs(2), 0);
        assert_eq!(s.stats(), Stats::default());
        let s = Store::new(Limits {
            global_max_bytes: 3,
            ..Limits::default()
        });
        s.push(key(1), Bytes::from_static(b"12"), a).unwrap();
        assert_eq!(
            s.push(key(5), Bytes::from_static(b"34"), a),
            Err(ErrorCode::Busy)
        );
    }

    #[test]
    fn tickets() {
        let s = Store::new(Limits {
            inbox_max_tickets: 1,
            ..Limits::default()
        });
        let (m, h) = (key(1), [9u8; 32]);
        s.register_ticket(m, h, 100, 10).unwrap();
        s.register_ticket(m, h, 100, 10).unwrap();
        assert_eq!(
            s.register_ticket(m, [8; 32], 100, 10),
            Err(ErrorCode::TicketsFull)
        );
        assert_eq!(
            s.register_ticket(key(2), h, 100, 10),
            Err(ErrorCode::Unauthorized)
        );
        let body = Bytes::from_static(b"bind");
        assert_eq!(
            s.push_with_ticket(key(2), h, body.clone(), 10),
            Err(ErrorCode::Unauthorized)
        );
        assert_eq!(
            s.push_with_ticket(m, h, body.clone(), 100),
            Err(ErrorCode::Expired)
        );
        s.push_with_ticket(m, h, body.clone(), 10).unwrap();
        assert_eq!(
            s.push_with_ticket(m, h, body.clone(), 10),
            Err(ErrorCode::TicketUsed)
        );
        assert_eq!(
            s.push_with_ticket(m, [7; 32], body, 10),
            Err(ErrorCode::Unauthorized)
        );
        s.sweep(Instant::now(), 100);
        assert_eq!(s.stats().tickets, 0);
    }

    #[test]
    fn revocations() {
        let s = Store::new(Limits {
            max_revocations: 1,
            ..Limits::default()
        });
        s.revoke([1; 32], 50).unwrap();
        s.revoke([1; 32], 50).unwrap();
        assert!(s.is_revoked(&[1; 32]));
        assert_eq!(s.revoke([2; 32], 50), Err(ErrorCode::Busy));
        s.sweep(Instant::now(), 50);
        assert!(!s.is_revoked(&[1; 32]));
    }
}
