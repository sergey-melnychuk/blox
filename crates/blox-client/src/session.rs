use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use blox_proto::message::{CloseReason, MsgId, SignRequest, SignResponse, now};
use blox_proto::peer::{AdapterEvent, AdapterSession};
use tokio::sync::{oneshot, watch};

use crate::{Error, RelayClient, Result};

/// Opens one-shot signing sessions on a relay (§5.1).
pub struct Signer {
    relay: RelayClient,
    label: String,
}

impl Signer {
    pub fn new(relay_url: &str, label: &str) -> Self {
        Self {
            relay: RelayClient::new(relay_url),
            label: label.to_owned(),
        }
    }

    /// Creates a session, hands its `blox:s?p=…` string to `show_qr`, and waits
    /// up to `join_timeout` for a keystore to join.
    pub async fn connect(
        &self,
        show_qr: impl FnOnce(&str),
        join_timeout: Duration,
    ) -> Result<Session> {
        let core = AdapterSession::new(self.relay.base(), &self.label);
        let sub = self.relay.subscribe(core.read_secret().clone());
        show_qr(&core.uri());

        let (state_tx, mut state_rx) = watch::channel(Status::Waiting);
        let shared = Arc::new(Shared {
            core: Mutex::new(core),
            pending: Mutex::default(),
            status: state_tx,
        });
        let task = tokio::spawn(pump(self.relay.clone(), shared.clone(), sub));
        let session = Session {
            relay: self.relay.clone(),
            shared,
            task,
        };

        let joined =
            tokio::time::timeout(join_timeout, state_rx.wait_for(|s| *s != Status::Waiting)).await;
        match joined.map(|r| r.map(|s| *s)) {
            Ok(Ok(Status::Joined)) => Ok(session),
            Ok(Ok(Status::Closed(CloseReason::Contested))) => Err(Error::Contested),
            Ok(Ok(Status::Closed(reason))) => Err(Error::Closed(reason)),
            _ => {
                session.close().await;
                Err(Error::NoSignerJoined)
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Status {
    Waiting,
    Joined,
    Closed(CloseReason),
}

struct Shared {
    core: Mutex<AdapterSession>,
    pending: Mutex<HashMap<MsgId, oneshot::Sender<Result<SignResponse>>>>,
    status: watch::Sender<Status>,
}

impl Shared {
    fn fail_all(&self, reason: CloseReason) {
        let err = || {
            if reason == CloseReason::Contested {
                Error::Contested
            } else {
                Error::Closed(reason)
            }
        };
        for (_, tx) in self.pending.lock().unwrap().drain() {
            let _ = tx.send(Err(err()));
        }
        self.status.send_replace(Status::Closed(reason));
    }
}

/// A joined session. Dropping it without [`Session::close`] stops reading but
/// sends no `close`; the keystore then times out on its own.
pub struct Session {
    relay: RelayClient,
    shared: Arc<Shared>,
    task: tokio::task::JoinHandle<()>,
}

impl Session {
    pub fn is_open(&self) -> bool {
        *self.shared.status.borrow() == Status::Joined
    }

    /// Sends one request and waits for its response. The response is returned
    /// as sent by the keystore: callers must verify it (§9.5).
    pub async fn sign(&self, req: SignRequest, timeout: Duration) -> Result<SignResponse> {
        let (id, out, rx) = {
            let core = self.shared.core.lock().unwrap();
            if let Status::Closed(reason) = *self.shared.status.borrow() {
                return Err(if reason == CloseReason::Contested {
                    Error::Contested
                } else {
                    Error::Closed(reason)
                });
            }
            let (id, out) = core.request(req)?;
            let (tx, rx) = oneshot::channel();
            self.shared.pending.lock().unwrap().insert(id, tx);
            (id, out, rx)
        };
        if let Err(e) = self.relay.post(&out).await {
            self.shared.pending.lock().unwrap().remove(&id);
            return Err(e);
        }
        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err(Error::Closed(CloseReason::Shutdown)),
            Err(_) => {
                self.shared.pending.lock().unwrap().remove(&id);
                Err(Error::Timeout)
            }
        }
    }

    /// Sends `close(done)` if possible and stops reading.
    pub async fn close(self) {
        self.close_with(CloseReason::Done).await
    }

    pub async fn close_with(self, reason: CloseReason) {
        let out = self
            .shared
            .core
            .lock()
            .unwrap()
            .close(reason)
            .ok()
            .flatten();
        if let Some(out) = out {
            let _ = self.relay.post(&out).await;
        }
        self.shared.fail_all(reason);
        self.task.abort();
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Reads the adapter mailbox and routes events until the session closes.
async fn pump(relay: RelayClient, shared: Arc<Shared>, mut sub: crate::Subscription) {
    let secret = shared.core.lock().unwrap().read_secret().clone();
    while let Some(delivery) = sub.next().await {
        let Ok(d) = delivery else {
            shared.fail_all(CloseReason::Shutdown);
            return;
        };
        let event = shared.core.lock().unwrap().on_envelope(&d.body, now());
        let _ = relay.ack(&secret, d.seq).await;
        match event {
            Ok(AdapterEvent::Joined) => {
                shared.status.send_replace(Status::Joined);
            }
            Ok(AdapterEvent::Contested(out)) => {
                for o in &out {
                    let _ = relay.post(o).await;
                }
                tracing::warn!(
                    "a second device joined this session; someone may have seen the QR code"
                );
                shared.fail_all(CloseReason::Contested);
                return;
            }
            Ok(AdapterEvent::Response { re, response }) => {
                if let Some(tx) = shared.pending.lock().unwrap().remove(&re) {
                    let _ = tx.send(Ok(response));
                }
            }
            Ok(AdapterEvent::Closed(reason)) => {
                shared.fail_all(reason);
                return;
            }
            Ok(AdapterEvent::Ignored) => {}
            // Undecryptable, replayed or stale envelopes are dropped silently.
            Err(e) => tracing::debug!(error = %e, "dropped envelope"),
        }
    }
}
