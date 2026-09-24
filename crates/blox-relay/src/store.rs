//! In-memory mailbox store (§8.3). Nothing is ever written to disk.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use blox_proto::mailbox::MailboxId;
use bytes::Bytes;
use tokio::sync::Notify;

use crate::Limits;

#[derive(Clone)]
pub struct Queued {
    pub seq: u64,
    pub body: Bytes,
    pub enqueued: Instant,
}

#[derive(Default)]
struct Mailbox {
    next_seq: u64,
    queue: VecDeque<Queued>,
    bytes: usize,
    /// Generation of the single active reader and its wake-up handle.
    reader: Option<(u64, Arc<Notify>)>,
    generation: u64,
}

impl Mailbox {
    fn is_idle(&self) -> bool {
        self.queue.is_empty() && self.reader.is_none()
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum PushError {
    MailboxFull,
    RelayFull,
}

pub struct Store {
    inner: Mutex<Inner>,
    limits: Limits,
}

#[derive(Default)]
struct Inner {
    boxes: HashMap<MailboxId, Mailbox>,
    total_bytes: usize,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Stats {
    pub mailboxes: usize,
    pub messages: usize,
    pub bytes: usize,
    pub readers: usize,
}

impl Store {
    pub fn new(limits: Limits) -> Self {
        Self {
            inner: Mutex::default(),
            limits,
        }
    }

    pub fn push(&self, id: MailboxId, body: Bytes) -> Result<u64, PushError> {
        let mut inner = self.inner.lock().unwrap();
        if inner.total_bytes + body.len() > self.limits.global_max_bytes {
            return Err(PushError::RelayFull);
        }
        let mb = inner.boxes.entry(id).or_default();
        if mb.queue.len() >= self.limits.mailbox_max_messages
            || mb.bytes + body.len() > self.limits.mailbox_max_bytes
        {
            let idle = mb.is_idle();
            if idle {
                inner.boxes.remove(&id);
            }
            return Err(PushError::MailboxFull);
        }
        let seq = mb.next_seq;
        mb.next_seq += 1;
        mb.bytes += body.len();
        let len = body.len();
        mb.queue.push_back(Queued {
            seq,
            body,
            enqueued: Instant::now(),
        });
        if let Some((_, notify)) = &mb.reader {
            notify.notify_one();
        }
        inner.total_bytes += len;
        Ok(seq)
    }

    /// Registers a new reader, superseding (and waking) any previous one.
    pub fn attach_reader(&self, id: MailboxId) -> (u64, Arc<Notify>) {
        let mut inner = self.inner.lock().unwrap();
        let mb = inner.boxes.entry(id).or_default();
        mb.generation += 1;
        let notify = Arc::new(Notify::new());
        if let Some((_, old)) = mb.reader.replace((mb.generation, notify.clone())) {
            old.notify_one();
        }
        (mb.generation, notify)
    }

    /// Messages after `after`, or `None` if this reader has been superseded.
    pub fn pending(
        &self,
        id: &MailboxId,
        generation: u64,
        after: Option<u64>,
    ) -> Option<Vec<Queued>> {
        let inner = self.inner.lock().unwrap();
        let mb = inner.boxes.get(id)?;
        match &mb.reader {
            Some((g, _)) if *g == generation => {}
            _ => return None,
        }
        Some(
            mb.queue
                .iter()
                .filter(|q| after.is_none_or(|a| q.seq > a))
                .cloned()
                .collect(),
        )
    }

    pub fn detach_reader(&self, id: &MailboxId, generation: u64) {
        let mut inner = self.inner.lock().unwrap();
        if let Some(mb) = inner.boxes.get_mut(id) {
            if matches!(&mb.reader, Some((g, _)) if *g == generation) {
                mb.reader = None;
            }
            if mb.is_idle() {
                inner.boxes.remove(id);
            }
        }
    }

    pub fn ack(&self, id: &MailboxId, seq: u64) {
        let mut inner = self.inner.lock().unwrap();
        let Some(mb) = inner.boxes.get_mut(id) else {
            return;
        };
        let mut freed = 0;
        if let Some(pos) = mb.queue.iter().position(|q| q.seq == seq) {
            let q = mb.queue.remove(pos).unwrap();
            mb.bytes -= q.body.len();
            freed = q.body.len();
        }
        if mb.is_idle() {
            inner.boxes.remove(id);
        }
        inner.total_bytes -= freed;
    }

    /// Drops expired messages and idle mailboxes.
    pub fn sweep(&self, now: Instant) {
        let ttl = self.limits.message_ttl;
        let mut inner = self.inner.lock().unwrap();
        let mut freed = 0;
        inner.boxes.retain(|_, mb| {
            while mb
                .queue
                .front()
                .is_some_and(|q| now.duration_since(q.enqueued) >= ttl)
            {
                let q = mb.queue.pop_front().unwrap();
                mb.bytes -= q.body.len();
                freed += q.body.len();
            }
            !mb.is_idle()
        });
        inner.total_bytes -= freed;
    }

    pub fn stats(&self) -> Stats {
        let inner = self.inner.lock().unwrap();
        Stats {
            mailboxes: inner.boxes.len(),
            messages: inner.boxes.values().map(|m| m.queue.len()).sum(),
            bytes: inner.total_bytes,
            readers: inner.boxes.values().filter(|m| m.reader.is_some()).count(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use blox_proto::mailbox::ReadSecret;
    use std::time::Duration;

    fn id() -> MailboxId {
        ReadSecret::generate().mailbox_id()
    }

    #[test]
    fn push_read_ack_cleans_up() {
        let s = Store::new(Limits::default());
        let m = id();
        assert_eq!(s.push(m, Bytes::from_static(b"a")).unwrap(), 0);
        assert_eq!(s.push(m, Bytes::from_static(b"b")).unwrap(), 1);
        let (g, _) = s.attach_reader(m);
        let p = s.pending(&m, g, None).unwrap();
        assert_eq!(p.iter().map(|q| q.seq).collect::<Vec<_>>(), [0, 1]);
        assert_eq!(s.pending(&m, g, Some(0)).unwrap().len(), 1);
        s.ack(&m, 0);
        s.ack(&m, 1);
        s.ack(&m, 1);
        s.detach_reader(&m, g);
        assert_eq!(s.stats(), Stats::default());
    }

    #[test]
    fn new_reader_supersedes_old() {
        let s = Store::new(Limits::default());
        let m = id();
        let (g1, _) = s.attach_reader(m);
        let (g2, _) = s.attach_reader(m);
        assert!(s.pending(&m, g1, None).is_none());
        assert!(s.pending(&m, g2, None).is_some());
        s.detach_reader(&m, g1); // stale detach must not remove the new reader
        assert_eq!(s.stats().readers, 1);
    }

    #[test]
    fn limits_and_ttl() {
        let limits = Limits {
            mailbox_max_messages: 2,
            message_ttl: Duration::from_secs(1),
            ..Limits::default()
        };
        let s = Store::new(limits);
        let m = id();
        s.push(m, Bytes::from_static(b"1")).unwrap();
        s.push(m, Bytes::from_static(b"2")).unwrap();
        assert_eq!(
            s.push(m, Bytes::from_static(b"3")),
            Err(PushError::MailboxFull)
        );
        s.sweep(Instant::now() + Duration::from_secs(2));
        assert_eq!(s.stats(), Stats::default());

        let s = Store::new(Limits {
            global_max_bytes: 3,
            ..Limits::default()
        });
        s.push(id(), Bytes::from_static(b"12")).unwrap();
        assert_eq!(
            s.push(id(), Bytes::from_static(b"34")),
            Err(PushError::RelayFull)
        );
    }
}
