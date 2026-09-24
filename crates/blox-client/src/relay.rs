use std::time::Duration;

use blox_proto::b64;
use blox_proto::mailbox::{MailboxId, ReadSecret};
use blox_proto::peer::Outgoing;
use futures::StreamExt;
use reqwest::StatusCode;
use tokio::sync::mpsc;

use crate::{Error, Result};

#[derive(Clone)]
pub struct RelayClient {
    base: String,
    http: reqwest::Client,
}

/// One message read from a mailbox. Acknowledge it with [`RelayClient::ack`].
#[derive(Debug)]
pub struct Delivery {
    pub seq: u64,
    pub body: Vec<u8>,
}

/// Messages from one mailbox. The reader reconnects on its own and stops when
/// this is dropped or the relay rejects the secret.
pub struct Subscription {
    rx: mpsc::Receiver<Result<Delivery>>,
    task: tokio::task::JoinHandle<()>,
}

impl Subscription {
    pub async fn next(&mut self) -> Option<Result<Delivery>> {
        self.rx.recv().await
    }
}

impl Drop for Subscription {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl RelayClient {
    pub fn new(base: &str) -> Self {
        Self {
            base: base.trim_end_matches('/').to_owned(),
            http: reqwest::Client::new(),
        }
    }

    pub fn base(&self) -> &str {
        &self.base
    }

    fn url(&self, id: &MailboxId) -> String {
        format!("{}/v1/m/{id}", self.base)
    }

    pub async fn post(&self, (mailbox, bytes): &Outgoing) -> Result<()> {
        let res = self
            .http
            .post(self.url(mailbox))
            .header("content-type", "application/octet-stream")
            .body(bytes.clone())
            .send()
            .await?;
        match res.status() {
            StatusCode::ACCEPTED => Ok(()),
            s => Err(Error::Relay(format!("post returned {}", s.as_u16()))),
        }
    }

    pub async fn ack(&self, secret: &ReadSecret, seq: u64) -> Result<()> {
        let res = self
            .http
            .delete(format!("{}/{seq}", self.url(&secret.mailbox_id())))
            .bearer_auth(secret.to_bearer())
            .send()
            .await?;
        match res.status() {
            StatusCode::NO_CONTENT => Ok(()),
            StatusCode::UNAUTHORIZED => Err(Error::Unauthorized),
            s => Err(Error::Relay(format!("ack returned {}", s.as_u16()))),
        }
    }

    pub fn subscribe(&self, secret: ReadSecret) -> Subscription {
        let (tx, rx) = mpsc::channel(64);
        let client = self.clone();
        let task = tokio::spawn(async move { client.read_loop(secret, tx).await });
        Subscription { rx, task }
    }

    async fn read_loop(self, secret: ReadSecret, tx: mpsc::Sender<Result<Delivery>>) {
        let mut backoff = Duration::from_millis(250);
        loop {
            match self.read_once(&secret, &tx).await {
                Ok(()) => backoff = Duration::from_millis(250),
                Err(Error::Unauthorized) => {
                    let _ = tx.send(Err(Error::Unauthorized)).await;
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
        secret: &ReadSecret,
        tx: &mpsc::Sender<Result<Delivery>>,
    ) -> Result<()> {
        let res = self
            .http
            .get(self.url(&secret.mailbox_id()))
            .bearer_auth(secret.to_bearer())
            .header("accept", "text/event-stream")
            .send()
            .await?;
        match res.status() {
            StatusCode::OK => {}
            StatusCode::UNAUTHORIZED => return Err(Error::Unauthorized),
            s => return Err(Error::Relay(format!("read returned {}", s.as_u16()))),
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
    let text = std::str::from_utf8(frame).map_err(|_| Error::Relay("non-utf8 event".into()))?;
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
    #[derive(serde::Deserialize)]
    struct Msg<'a> {
        seq: u64,
        body: &'a str,
    }
    let m: Msg = serde_json::from_str(data).map_err(|_| Error::Relay("malformed event".into()))?;
    Ok(Some(Delivery {
        seq: m.seq,
        body: b64::decode(m.body)?,
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
