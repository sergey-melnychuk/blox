//! The Rust requester (BLOX.md §9): connect once with a QR code, then send requests.

use std::sync::Arc;
use std::time::Duration;

use blox_proto::api::ErrorCode;
use blox_proto::connection::{BindCandidate, ConnectAttempt, Connection};
use blox_proto::ident::{InboxId, SigningKey, Ticket};
use blox_proto::message::{Body, Empty, Message, SignRequest, SignResponse};
use blox_proto::token::Token;
use blox_proto::{relay_url, statement};
use tokio::sync::Mutex;

use crate::relay::{RelayClient, WriteAuth};
use crate::store::{ConnectionStore, StoredConnection};
use crate::{Error, Result};

/// Requests may stay on the relay this long (§6.2).
pub const MAX_REQUEST_SECS: u64 = 300;
/// How long a ticket is registered for (§5.1).
const TICKET_SECS: u64 = 120;

pub struct Config {
    /// Relay URL (normalized by [`Requester::new`]).
    pub relay: String,
    /// The name shown on the phone (a claim).
    pub name: String,
    /// How long to wait for the QR code to be answered.
    pub connect_timeout: Duration,
    /// Test hook: pretend the local clock is this many seconds off (§4.8).
    pub local_clock_skew: i64,
}

impl Config {
    pub fn new(relay: &str, name: &str) -> Self {
        Self {
            relay: relay.to_owned(),
            name: name.to_owned(),
            connect_timeout: Duration::from_secs(120),
            local_clock_skew: 0,
        }
    }
}

/// Receives the `BLOX:…` string to show as a QR code.
pub type QrCallback = Arc<dyn Fn(&str) + Send + Sync>;

pub struct Requester {
    relay: RelayClient,
    config: Config,
    store: Arc<dyn ConnectionStore>,
    on_qr: QrCallback,
    live: Mutex<Option<Live>>,
    /// One request in flight per connection (§9.2).
    in_flight: Mutex<()>,
}

struct Live {
    conn: Connection,
    sig: SigningKey,
    account: String,
}

impl Requester {
    pub fn new(
        mut config: Config,
        store: Arc<dyn ConnectionStore>,
        on_qr: QrCallback,
    ) -> Result<Self> {
        config.relay = relay_url::normalize(&config.relay)?;
        let relay = RelayClient::new(&config.relay).with_local_skew(config.local_clock_skew);
        Ok(Self {
            relay,
            config,
            store,
            on_qr,
            live: Mutex::new(None),
            in_flight: Mutex::new(()),
        })
    }

    pub fn relay(&self) -> &RelayClient {
        &self.relay
    }

    /// The connected account, if any (checksummed).
    pub async fn account(&self) -> Option<String> {
        self.live.lock().await.as_ref().map(|l| l.account.clone())
    }

    /// Connects (showing the QR code) unless a stored connection is still valid.
    pub async fn connect(&self) -> Result<String> {
        self.connect_with(None).await
    }

    /// Like [`connect`](Self::connect), using the server's 16-byte nonce as the ticket, so
    /// the server can check the statement with [`verify_connection`] (§9.2).
    pub async fn connect_with(&self, nonce: Option<Ticket>) -> Result<String> {
        let mut live = self.live.lock().await;
        let now = self.relay.now();
        if let Some(l) = live.as_ref() {
            if l.conn.expires_at() > now {
                return Ok(l.account.clone());
            }
            *live = None;
        }
        if let Some(stored) = self.store.load()? {
            match stored.open() {
                Ok((conn, sig)) if conn.expires_at() > now && conn.relay() == self.config.relay => {
                    let account = stored.account.clone();
                    *live = Some(Live {
                        conn,
                        sig,
                        account: account.clone(),
                    });
                    return Ok(account);
                }
                _ => self.store.clear()?,
            }
        }
        let (l, stored) = self.connect_new(nonce).await?;
        self.store.save(&stored)?;
        let account = l.account.clone();
        *live = Some(l);
        Ok(account)
    }

    async fn connect_new(&self, nonce: Option<Ticket>) -> Result<(Live, StoredConnection)> {
        self.relay.sync_time().await?;
        let attempt = ConnectAttempt::new(&self.config.relay, &self.config.name, nonce)?;
        let keys = attempt.keys().clone();
        let ticket = attempt.offer().ticket;
        self.relay
            .register_ticket(&keys.sig, &ticket, self.relay.now() + TICKET_SECS)
            .await?;
        let mut sub = self.relay.subscribe(keys.sig.clone());
        (self.on_qr)(&attempt.uri());

        let deadline = tokio::time::Instant::now() + self.config.connect_timeout;
        loop {
            let d = match tokio::time::timeout_at(deadline, sub.next()).await {
                Err(_) => return Err(Error::NoSigner),
                Ok(None) => return Err(Error::Network("inbox stream ended".into())),
                Ok(Some(d)) => d?,
            };
            let now = self.relay.now();
            let first = match check_bind(&attempt, &d.body, now) {
                Ok(c) => c,
                Err(_) => {
                    self.relay.ack(&keys.sig, d.seq).await?;
                    continue;
                }
            };
            self.relay.ack(&keys.sig, d.seq).await?;
            // An honest relay delivers one bind per ticket; any other valid one waiting means
            // someone else answered the same QR code (§5.3).
            let mut others = Vec::new();
            while let Some(Ok(d2)) = sub.try_next() {
                if let Ok(c) = check_bind(&attempt, &d2.body, now) {
                    others.push(c);
                }
                self.relay.ack(&keys.sig, d2.seq).await?;
            }
            if !others.is_empty() {
                for c in std::iter::once(&first).chain(&others) {
                    let _ = self.relay.revoke(&c.token, &keys.sig).await;
                }
                return Err(Error::Contested);
            }
            let account = first.account.clone();
            let (conn, bound) = attempt.accept(first, now)?;
            self.relay
                .post(
                    &conn.peer_inbox(),
                    WriteAuth::Token {
                        token: conn.token(),
                        signer: &keys.sig,
                    },
                    &bound,
                )
                .await?;
            let stored = StoredConnection::new(&conn, &keys, &self.config.name, &account);
            return Ok((
                Live {
                    conn,
                    sig: keys.sig,
                    account,
                },
                stored,
            ));
        }
    }

    /// Sends one request and waits for its response (§6, §9.2). Connects first if needed.
    ///
    /// The request's `expires_at` is capped at 300 s from now (relay time); 0 means the max.
    pub async fn request(&self, mut req: SignRequest) -> Result<SignResponse> {
        self.connect().await?;
        let _one = self.in_flight.lock().await;
        let now = self.relay.now();
        if req.expires_at == 0 || req.expires_at > now + MAX_REQUEST_SECS {
            req.expires_at = now + MAX_REQUEST_SECS;
        }
        let expires_at = req.expires_at;
        let (sig, peer, token, bytes, id, cancel) = {
            let live = self.live.lock().await;
            let l = live.as_ref().ok_or(Error::Disconnected)?;
            let msg = Message::at(Body::SignRequest(req), now);
            let cancel = Message::reply_at(msg.id, Body::Cancel(Empty {}), now);
            (
                l.sig.clone(),
                l.conn.peer_inbox(),
                l.conn.token().clone(),
                l.conn.seal(&msg)?,
                msg.id,
                l.conn.seal(&cancel)?,
            )
        };
        // Read before posting, so the response can't arrive unseen.
        let mut sub = self.relay.subscribe(sig.clone());
        let auth = WriteAuth::Token {
            token: &token,
            signer: &sig,
        };
        if let Err(e) = self.relay.post(&peer, auth, &bytes).await {
            return Err(self.on_write_error(e).await);
        }
        let mut guard = CancelGuard {
            relay: self.relay.clone(),
            peer,
            token: token.clone(),
            sig: sig.clone(),
            cancel: Some(cancel),
        };

        let wait = expires_at.saturating_sub(self.relay.now());
        let deadline = tokio::time::Instant::now() + Duration::from_secs(wait);
        loop {
            let d = match tokio::time::timeout_at(deadline, sub.next()).await {
                Err(_) => {
                    guard.send_now().await;
                    return Err(Error::Timeout);
                }
                Ok(None) => return Err(Error::Network("inbox stream ended".into())),
                Ok(Some(d)) => d?,
            };
            let opened = {
                let mut live = self.live.lock().await;
                let l = live.as_mut().ok_or(Error::Disconnected)?;
                l.conn.open(&d.body, self.relay.now())
            };
            let msg = match opened {
                Ok(m) => m,
                // Seen before (a reconnect redelivered it): leave it.
                Err(blox_proto::Error::Replay) => continue,
                // Not from this connection's keystore, or stale: drop it.
                Err(_) => {
                    let _ = self.relay.ack(&sig, d.seq).await;
                    continue;
                }
            };
            match msg.body {
                Body::SignResponse(r) if msg.re == Some(id) => {
                    guard.disarm();
                    self.relay.ack(&sig, d.seq).await?;
                    return Ok(r);
                }
                Body::Unbind(_) => {
                    guard.disarm();
                    let _ = self.relay.ack(&sig, d.seq).await;
                    self.forget().await?;
                    return Err(Error::Disconnected);
                }
                // Another requester's response on the same connection (another tab): theirs.
                _ => {}
            }
        }
    }

    async fn on_write_error(&self, e: Error) -> Error {
        match e {
            Error::Relay(ErrorCode::Expired | ErrorCode::Revoked) => match self.forget().await {
                Ok(()) => Error::Disconnected,
                Err(e) => e,
            },
            e => e,
        }
    }

    async fn forget(&self) -> Result<()> {
        *self.live.lock().await = None;
        self.store.clear()
    }

    /// Ends the connection: `unbind` to the keystore, revoke the token, forget it (§5.5).
    pub async fn disconnect(&self) -> Result<()> {
        let taken = self.live.lock().await.take();
        let live = match taken {
            Some(l) => Some(l),
            None => self.store.load()?.and_then(|s| {
                s.open().ok().map(|(conn, sig)| Live {
                    conn,
                    sig,
                    account: s.account.clone(),
                })
            }),
        };
        if let Some(l) = live {
            let bye = Message::at(Body::Unbind(Empty {}), self.relay.now());
            if let Ok(bytes) = l.conn.seal(&bye) {
                let auth = WriteAuth::Token {
                    token: l.conn.token(),
                    signer: &l.sig,
                };
                let _ = self.relay.post(&l.conn.peer_inbox(), auth, &bytes).await;
            }
            let _ = self.relay.revoke(l.conn.token(), &l.sig).await;
        }
        self.store.clear()
    }
}

fn check_bind(attempt: &ConnectAttempt, bytes: &[u8], now: u64) -> Result<BindCandidate> {
    let c = attempt.open_bind(bytes, now)?;
    blox_evm::connect::verify_statement(&c.statement, &c.signature, &c.account)
        .map_err(|e| Error::BadResponse(e.to_string()))?;
    Ok(c)
}

/// Sends the pre-sealed `cancel` if the request is abandoned (§6.5), including when the
/// caller drops the future.
struct CancelGuard {
    relay: RelayClient,
    peer: InboxId,
    token: Token,
    sig: SigningKey,
    cancel: Option<Vec<u8>>,
}

impl CancelGuard {
    fn disarm(&mut self) {
        self.cancel = None;
    }

    async fn send_now(&mut self) {
        if let Some(bytes) = self.cancel.take() {
            let auth = WriteAuth::Token {
                token: &self.token,
                signer: &self.sig,
            };
            let _ = self.relay.post(&self.peer, auth, &bytes).await;
        }
    }
}

impl Drop for CancelGuard {
    fn drop(&mut self) {
        if let Some(bytes) = self.cancel.take()
            && let Ok(rt) = tokio::runtime::Handle::try_current()
        {
            let (relay, peer, token, sig) = (
                self.relay.clone(),
                self.peer,
                self.token.clone(),
                self.sig.clone(),
            );
            rt.spawn(async move {
                let auth = WriteAuth::Token {
                    token: &token,
                    signer: &sig,
                };
                let _ = relay.post(&peer, auth, &bytes).await;
            });
        }
    }
}

/// For a site's server: checks a connection statement against the nonce it issued
/// (§9.2). `now` is the server's clock; the statement must be at most 300 s old.
pub fn verify_connection(
    account: &str,
    statement_text: &str,
    signature: &str,
    nonce: &Ticket,
    now: u64,
) -> Result<()> {
    let bad = |why: &str| Err(Error::BadResponse(format!("connection statement: {why}")));
    if statement_text.split('\n').next() != Some("Blox connection") {
        return bad("not a Blox connection statement");
    }
    if statement::field(statement_text, "Account") != Some(account) {
        return bad("account");
    }
    if statement::field(statement_text, "Nonce") != Some(nonce.to_string().as_str()) {
        return bad("nonce");
    }
    let issued = statement::field(statement_text, "Issued").and_then(statement::parse_iso8601);
    let expires = statement::field(statement_text, "Expires").and_then(statement::parse_iso8601);
    match (issued, expires) {
        (Some(i), Some(e)) if i.abs_diff(now) <= 300 && e > now => {}
        _ => return bad("times"),
    }
    blox_evm::connect::verify_statement(statement_text, signature, account)
        .map_err(|e| Error::BadResponse(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use blox_proto::statement::Statement;

    #[test]
    fn verify_connection_checks_nonce_times_and_signature() {
        let signer = blox_evm::sign::signer_from_mnemonic(
            "test test test test test test test test test test test junk",
            0,
        )
        .unwrap();
        let account = signer.address().to_checksum(None);
        let nonce = Ticket([9; 16]);
        let (s, k) = (
            SigningKey::generate().public(),
            SigningKey::generate().public(),
        );
        let text = |issued: u64| {
            Statement {
                label: "Example",
                requester: &s,
                keystore: &k,
                account: &account,
                ticket: &nonce,
                relay: "https://relay.example.com",
                issued_at: issued,
                expires_at: issued + 86400,
            }
            .render()
        };
        let now = 1_762_776_000;
        let good = text(now);
        let sig = blox_evm::connect::sign_statement(&signer, &good);
        verify_connection(&account, &good, &sig, &nonce, now + 10).unwrap();
        assert!(verify_connection(&account, &good, &sig, &Ticket([8; 16]), now).is_err());
        assert!(verify_connection(&account, &good, &sig, &nonce, now + 400).is_err());
        let old = text(now - 1000);
        let old_sig = blox_evm::connect::sign_statement(&signer, &old);
        assert!(verify_connection(&account, &old, &old_sig, &nonce, now).is_err());
        let other = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";
        assert!(verify_connection(other, &good, &sig, &nonce, now).is_err());
        let tampered = good.replace("Example", "Exampl3");
        assert!(verify_connection(&account, &tampered, &sig, &nonce, now).is_err());
    }
}
