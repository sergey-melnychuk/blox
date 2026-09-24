//! One signing request at the phone at a time, in `(from, nonce)` order (§9.3).

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use blox_client::{Error as ClientError, Session, Signer};
use blox_evm::Address;
use blox_evm::verify::{Verified, verify};
use blox_proto::message::{CloseReason, RejectReason, SignRequest, SignResponse};
use tokio::sync::{mpsc, oneshot};

use crate::{Event, Hooks, RpcError};

/// Wait after the first job of a burst, so concurrent requests are ordered by nonce.
const COALESCE: Duration = Duration::from_millis(200);
/// Hard cap on a session's lifetime (§5.4).
const MAX_SESSION: Duration = Duration::from_secs(15 * 60);

pub struct QueueConfig {
    pub relay: String,
    pub label: String,
    pub join_timeout: Duration,
    pub idle_timeout: Duration,
    pub hooks: Arc<dyn Hooks>,
}

struct Job {
    req: SignRequest,
    summary: String,
    deadline: Instant,
    reply: oneshot::Sender<Result<Verified, RpcError>>,
}

/// Ordering key: `(chain, from, nonce, arrival)`. Non-transaction jobs use nonce 0.
type Key = (u64, Address, u64, u64);

#[derive(Clone)]
pub struct Queue {
    tx: mpsc::UnboundedSender<(Key, Job)>,
    seq: Arc<std::sync::atomic::AtomicU64>,
}

impl Queue {
    pub fn spawn(cfg: QueueConfig) -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        tokio::spawn(
            Worker {
                signer: Signer::new(&cfg.relay, &cfg.label),
                cfg,
                session: None,
                pending: BTreeMap::new(),
                rx,
            }
            .run(),
        );
        Self {
            tx,
            seq: Arc::default(),
        }
    }

    pub async fn submit(
        &self,
        order: (u64, Address, u64),
        req: SignRequest,
        summary: String,
        timeout: Duration,
    ) -> Result<Verified, RpcError> {
        let (reply, rx) = oneshot::channel();
        let seq = self.seq.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let job = Job {
            req,
            summary,
            deadline: Instant::now() + timeout,
            reply,
        };
        self.tx
            .send(((order.0, order.1, order.2, seq), job))
            .map_err(|_| RpcError::internal("signer stopped"))?;
        rx.await.map_err(|_| RpcError::internal("signer stopped"))?
    }
}

struct Worker {
    cfg: QueueConfig,
    signer: Signer,
    session: Option<(Session, Instant)>,
    pending: BTreeMap<Key, Job>,
    rx: mpsc::UnboundedReceiver<(Key, Job)>,
}

impl Worker {
    async fn run(mut self) {
        loop {
            if self.pending.is_empty() {
                let next = match &self.session {
                    Some(_) => {
                        match tokio::time::timeout(self.cfg.idle_timeout, self.rx.recv()).await {
                            Ok(job) => job,
                            Err(_) => {
                                self.close(CloseReason::Timeout).await;
                                continue;
                            }
                        }
                    }
                    None => self.rx.recv().await,
                };
                let Some((key, job)) = next else {
                    self.close(CloseReason::Shutdown).await;
                    return;
                };
                self.pending.insert(key, job);
                tokio::time::sleep(COALESCE).await;
            }
            while let Ok((key, job)) = self.rx.try_recv() {
                self.pending.insert(key, job);
            }
            if !self.ensure_session().await {
                continue;
            }
            // Pull in anything that arrived while waiting for the phone.
            while let Ok((key, job)) = self.rx.try_recv() {
                self.pending.insert(key, job);
            }
            let Some((_, job)) = self.pending.pop_first() else {
                continue;
            };
            self.run_job(job).await;
        }
    }

    /// Opens a session if needed. On failure, fails every pending job.
    async fn ensure_session(&mut self) -> bool {
        if let Some((s, opened)) = &self.session {
            if s.is_open() && opened.elapsed() < MAX_SESSION {
                return true;
            }
            self.close(CloseReason::Timeout).await;
        }
        let hooks = self.cfg.hooks.clone();
        match self
            .signer
            .connect(|uri| hooks.show_qr(uri), self.cfg.join_timeout)
            .await
        {
            Ok(s) => {
                self.cfg.hooks.event(Event::Joined);
                self.session = Some((s, Instant::now()));
                true
            }
            Err(e) => {
                let err = client_error(&e);
                self.cfg.hooks.event(Event::Failed {
                    message: err.message.clone(),
                });
                for (_, job) in std::mem::take(&mut self.pending) {
                    let _ = job.reply.send(Err(err.clone()));
                }
                false
            }
        }
    }

    async fn run_job(&mut self, job: Job) {
        let Some(remaining) = job.deadline.checked_duration_since(Instant::now()) else {
            let _ = job.reply.send(Err(RpcError::internal("signer timeout")));
            return;
        };
        let (session, _) = self.session.as_ref().expect("ensured");
        self.cfg.hooks.event(Event::Sent {
            summary: job.summary.clone(),
        });
        let result = match session.sign(job.req.clone(), remaining).await {
            Ok(resp @ SignResponse::Approved { .. }) => match verify(&job.req, &resp) {
                Ok(v) => {
                    self.cfg.hooks.event(Event::Signed);
                    Ok(v)
                }
                Err(e) => {
                    self.cfg.hooks.event(Event::VerificationFailed {
                        detail: e.to_string(),
                    });
                    self.close(CloseReason::Done).await;
                    Err(RpcError::internal("signer response failed verification"))
                }
            },
            Ok(SignResponse::Rejected { reason }) => {
                self.cfg.hooks.event(Event::Rejected {
                    reason: format!("{reason:?}"),
                });
                Err(rejected(reason))
            }
            Err(e) => {
                let err = client_error(&e);
                self.cfg.hooks.event(Event::Failed {
                    message: err.message.clone(),
                });
                if !matches!(e, ClientError::Timeout) {
                    self.session = None;
                }
                Err(err)
            }
        };
        let _ = job.reply.send(result);
    }

    async fn close(&mut self, reason: CloseReason) {
        if let Some((s, _)) = self.session.take() {
            s.close_with(reason).await;
            self.cfg.hooks.event(Event::SessionClosed);
        }
    }
}

fn rejected(reason: RejectReason) -> RpcError {
    match reason {
        RejectReason::User => RpcError::new(4001, "User rejected the request."),
        RejectReason::AccountUnknown => {
            RpcError::new(4100, "The signer does not hold this account.")
        }
        RejectReason::Unsupported => {
            RpcError::new(4200, "The signer does not support this request.")
        }
        RejectReason::Expired => RpcError::internal("request expired before approval"),
        RejectReason::DecodeFailed => RpcError::internal("signer could not decode the request"),
    }
}

fn client_error(e: &ClientError) -> RpcError {
    match e {
        ClientError::NoSignerJoined => RpcError::internal("no signer joined"),
        ClientError::Contested => RpcError::internal(
            "session aborted: a second device joined. Someone may have seen your QR code",
        ),
        ClientError::Timeout => RpcError::internal("signer timeout"),
        other => RpcError::internal(other.to_string()),
    }
}
