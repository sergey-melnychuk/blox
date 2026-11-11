//! HTTP client for the relay API (BLOX.md §8.2), with signed requests and relay time.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::time::Duration;

use blox_proto::api::{self, Accepted, ErrorBody, ErrorCode, Info, TicketRegistration};
use blox_proto::b64;
use blox_proto::ident::{InboxId, SigningKey, Ticket};
use blox_proto::reqsig;
use blox_proto::token::Token;
use futures::StreamExt;
use reqwest::{Method, StatusCode};
use tokio::sync::mpsc;

use crate::{Error, Result};

/// Longest wait for a relay call other than a read stream.
const CALL_TIMEOUT: Duration = Duration::from_secs(30);

/// How a write is authorized (§2.2).
pub enum WriteAuth<'a> {
    /// A token the recipient signed, with the request signed by the other party.
    Token {
        token: &'a Token,
        signer: &'a SigningKey,
    },
    /// The one-time ticket from the QR code (bind only).
    Ticket(&'a Ticket),
}

#[derive(Clone)]
pub struct RelayClient {
    base: String,
    http: reqwest::Client,
    /// Relay clock minus local clock, in seconds (§4.8).
    offset: Arc<AtomicI64>,
    synced: Arc<AtomicBool>,
    /// Test hook: pretend the local clock is off by this many seconds.
    local_skew: i64,
}

/// One message read from an inbox. Acknowledge it with [`RelayClient::ack`].
#[derive(Debug)]
pub struct Delivery {
    pub seq: u64,
    pub body: Vec<u8>,
}

/// Messages from one inbox. The reader reconnects on its own and stops when this is
/// dropped or the relay refuses the reader.
pub struct Subscription {
    rx: mpsc::Receiver<Result<Delivery>>,
    task: tokio::task::JoinHandle<()>,
}

impl Subscription {
    pub async fn next(&mut self) -> Option<Result<Delivery>> {
        self.rx.recv().await
    }

    /// A delivery that is already waiting, without blocking.
    pub fn try_next(&mut self) -> Option<Result<Delivery>> {
        self.rx.try_recv().ok()
    }
}

impl Drop for Subscription {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn local_now() -> u64 {
    blox_proto::message::now()
}

impl RelayClient {
    /// `base` is the normalized relay URL; API paths are appended to it.
    pub fn new(base: &str) -> Self {
        Self {
            base: base.trim_end_matches('/').to_owned(),
            // A fresh connection per request: with connection reuse (reqwest 0.13.5,
            // hyper-util 0.1.20), a request occasionally never reached the relay and hung —
            // about one in five runs of the anvil tests. Relay calls are few per request.
            http: reqwest::Client::builder()
                .pool_max_idle_per_host(0)
                .connect_timeout(Duration::from_secs(10))
                .build()
                .expect("http client"),
            offset: Arc::default(),
            synced: Arc::default(),
            local_skew: 0,
        }
    }

    /// Pretends the local clock is `secs` off (tests of §4.8).
    pub fn with_local_skew(mut self, secs: i64) -> Self {
        self.local_skew = secs;
        self
    }

    pub fn base(&self) -> &str {
        &self.base
    }

    fn local(&self) -> u64 {
        local_now().saturating_add_signed(self.local_skew)
    }

    /// Relay time: the local clock corrected by the last sync (§4.8).
    pub fn now(&self) -> u64 {
        self.local()
            .saturating_add_signed(self.offset.load(Ordering::Relaxed))
    }

    /// Reads the relay's clock from `/v1/info` and keeps the offset.
    pub async fn sync_time(&self) -> Result<()> {
        let info: Info = self
            .http
            .get(format!("{}/v1/info", self.base))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        self.offset
            .store(info.now as i64 - self.local() as i64, Ordering::Relaxed);
        self.synced.store(true, Ordering::Relaxed);
        Ok(())
    }

    async fn ensure_synced(&self) -> Result<()> {
        if !self.synced.load(Ordering::Relaxed) {
            self.sync_time().await?;
        }
        Ok(())
    }

    /// Sends a request signed by `signer` (if any), resyncing the clock and retrying once
    /// after `401 clock`.
    async fn send(
        &self,
        method: Method,
        path: &str,
        signer: Option<&SigningKey>,
        headers: &[(&str, String)],
        body: Vec<u8>,
    ) -> Result<reqwest::Response> {
        self.ensure_synced().await?;
        for attempt in 0..2 {
            let mut req = self
                .http
                .request(method.clone(), format!("{}{path}", self.base))
                .body(body.clone());
            // Reads are long-lived streams; everything else must answer promptly.
            if method != Method::GET {
                req = req.timeout(CALL_TIMEOUT);
            }
            if let Some(k) = signer {
                let auth = reqsig::sign(k, method.as_str(), path, self.now(), &body);
                req = req.header("authorization", auth);
            }
            for (name, value) in headers {
                req = req.header(*name, value);
            }
            let res = req.send().await?;
            if res.status().is_success() {
                return Ok(res);
            }
            let status = res.status();
            let code = res.json::<ErrorBody>().await.ok().map(|b| b.error);
            if code == Some(ErrorCode::Clock) && attempt == 0 {
                self.sync_time().await?;
                continue;
            }
            return Err(match code {
                Some(code) => Error::Relay(code),
                None => Error::Network(format!("status {}", status.as_u16())),
            });
        }
        unreachable!("loop returns")
    }

    /// Posts an envelope to `inbox`; returns its sequence number.
    pub async fn post(&self, inbox: &InboxId, auth: WriteAuth<'_>, envelope: &[u8]) -> Result<u64> {
        let path = format!("/v1/inbox/{inbox}");
        let mut headers = vec![("content-type", "application/octet-stream".to_owned())];
        let signer = match auth {
            WriteAuth::Token { token, signer } => {
                headers.push((api::HEADER_TOKEN, token.to_header()));
                Some(signer)
            }
            WriteAuth::Ticket(t) => {
                headers.push((api::HEADER_TICKET, t.to_string()));
                None
            }
        };
        let res = self
            .send(Method::POST, &path, signer, &headers, envelope.to_vec())
            .await?;
        Ok(res.json::<Accepted>().await?.seq)
    }

    pub async fn register_ticket(
        &self,
        owner: &SigningKey,
        ticket: &Ticket,
        expires_at: u64,
    ) -> Result<()> {
        let path = format!("/v1/inbox/{}/tickets", owner.public());
        let body = serde_json::to_vec(&TicketRegistration {
            ticket_hash: ticket.hash(),
            expires_at,
        })
        .expect("serializes");
        let headers = [("content-type", "application/json".to_owned())];
        self.send(Method::POST, &path, Some(owner), &headers, body)
            .await?;
        Ok(())
    }

    pub async fn revoke(&self, token: &Token, signer: &SigningKey) -> Result<()> {
        let headers = [(api::HEADER_TOKEN, token.to_header())];
        self.send(
            Method::POST,
            "/v1/revoke",
            Some(signer),
            &headers,
            Vec::new(),
        )
        .await?;
        Ok(())
    }

    pub async fn ack(&self, owner: &SigningKey, seq: u64) -> Result<()> {
        let path = format!("/v1/inbox/{}/{seq}", owner.public());
        self.send(Method::DELETE, &path, Some(owner), &[], Vec::new())
            .await?;
        Ok(())
    }

    /// Reads `owner`'s inbox until the subscription is dropped.
    pub fn subscribe(&self, owner: SigningKey) -> Subscription {
        let (tx, rx) = mpsc::channel(64);
        let client = self.clone();
        let task = tokio::spawn(async move { client.read_loop(owner, tx).await });
        Subscription { rx, task }
    }

    async fn read_loop(self, owner: SigningKey, tx: mpsc::Sender<Result<Delivery>>) {
        let mut backoff = Duration::from_millis(250);
        loop {
            match self.read_once(&owner, &tx).await {
                Ok(()) => backoff = Duration::from_millis(250),
                Err(Error::Relay(code))
                    if matches!(code, ErrorCode::Unauthorized | ErrorCode::Malformed) =>
                {
                    let _ = tx.send(Err(Error::Relay(code))).await;
                    return;
                }
                Err(_) if tx.is_closed() => return,
                Err(e) => tracing::debug!(error = %e, "relay stream interrupted; reconnecting"),
            }
            if tx.is_closed() {
                return;
            }
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(Duration::from_secs(5));
        }
    }

    /// Reads one SSE connection until it ends.
    async fn read_once(
        &self,
        owner: &SigningKey,
        tx: &mpsc::Sender<Result<Delivery>>,
    ) -> Result<()> {
        let path = format!("/v1/inbox/{}", owner.public());
        let res = self
            .send(
                Method::GET,
                &path,
                Some(owner),
                &[("accept", "text/event-stream".to_owned())],
                Vec::new(),
            )
            .await?;
        if res.status() != StatusCode::OK {
            return Err(Error::Network(format!(
                "read returned {}",
                res.status().as_u16()
            )));
        }
        let mut stream = res.bytes_stream();
        let mut buf = Vec::new();
        while let Some(chunk) = stream.next().await {
            buf.extend_from_slice(&chunk?);
            while let Some(end) = find_frame_end(&buf) {
                let frame: Vec<u8> = buf.drain(..end).collect();
                if let Some(d) = parse_frame(&frame)?
                    && tx.send(Ok(d)).await.is_err()
                {
                    return Ok(());
                }
            }
        }
        Ok(())
    }
}

/// Index just past the blank line that terminates an SSE frame.
fn find_frame_end(buf: &[u8]) -> Option<usize> {
    buf.windows(2).position(|w| w == b"\n\n").map(|i| i + 2)
}

fn parse_frame(frame: &[u8]) -> Result<Option<Delivery>> {
    let text = std::str::from_utf8(frame).map_err(|_| Error::Network("non-utf8 event".into()))?;
    let mut event = None;
    let mut data = None;
    for line in text.lines() {
        if let Some(v) = line.strip_prefix("event:") {
            event = Some(v.trim());
        } else if let Some(v) = line.strip_prefix("data:") {
            data = Some(v.trim());
        }
    }
    let (Some("msg"), Some(data)) = (event, data) else {
        return Ok(None);
    };
    let m: api::Event =
        serde_json::from_str(data).map_err(|_| Error::Network("malformed event".into()))?;
    Ok(Some(Delivery {
        seq: m.seq,
        body: b64::decode(&m.body)?,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_frames_and_skips_pings() {
        assert!(parse_frame(b": ping\n\n").unwrap().is_none());
        let d = parse_frame(b"event: msg\ndata: {\"seq\":3,\"body\":\"AQI\",\"age_ms\":1}\n\n")
            .unwrap()
            .unwrap();
        assert_eq!((d.seq, d.body), (3, vec![1, 2]));
        assert_eq!(find_frame_end(b"a\n\nb"), Some(3));
    }
}
