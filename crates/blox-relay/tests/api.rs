use std::net::SocketAddr;
use std::time::Duration;

use blox_proto::b64;
use blox_proto::mailbox::ReadSecret;
use blox_relay::{AppState, Limits, router};
use futures::StreamExt;
use serde_json::Value;

async fn start(limits: Limits) -> String {
    let listener = tokio::net::TcpListener::bind("localhost:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app =
        router(AppState::new(limits, false)).into_make_service_with_connect_info::<SocketAddr>();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{addr}")
}

/// A syntactically valid message envelope (the relay only checks the header).
fn envelope(tag: u8) -> Vec<u8> {
    let mut v = vec![1u8, 2];
    v.extend(std::iter::repeat_n(tag, 64));
    v
}

struct Sse {
    stream: futures::stream::BoxStream<'static, reqwest::Result<bytes::Bytes>>,
    buf: String,
}

impl Sse {
    async fn open(base: &str, secret: &ReadSecret) -> reqwest::Response {
        reqwest::Client::new()
            .get(format!("{base}/v1/m/{}", secret.mailbox_id()))
            .bearer_auth(secret.to_bearer())
            .send()
            .await
            .unwrap()
    }

    async fn connect(base: &str, secret: &ReadSecret) -> Self {
        let res = Self::open(base, secret).await;
        assert_eq!(res.status(), 200);
        Self {
            stream: res.bytes_stream().boxed(),
            buf: String::new(),
        }
    }

    /// Next `msg` event as JSON, or None on timeout / end of stream.
    async fn next(&mut self, wait: Duration) -> Option<Value> {
        let deadline = tokio::time::Instant::now() + wait;
        loop {
            if let Some(end) = self.buf.find("\n\n") {
                let frame: String = self.buf.drain(..end + 2).collect();
                if frame.lines().any(|l| l == "event: msg") {
                    let data = frame
                        .lines()
                        .find_map(|l| l.strip_prefix("data: "))
                        .unwrap();
                    return Some(serde_json::from_str(data).unwrap());
                }
                continue;
            }
            match tokio::time::timeout_at(deadline, self.stream.next()).await {
                Ok(Some(Ok(chunk))) => self.buf.push_str(std::str::from_utf8(&chunk).unwrap()),
                _ => return None,
            }
        }
    }
}

async fn post(base: &str, secret: &ReadSecret, body: Vec<u8>) -> reqwest::StatusCode {
    reqwest::Client::new()
        .post(format!("{base}/v1/m/{}", secret.mailbox_id()))
        .header("content-type", "application/octet-stream")
        .body(body)
        .send()
        .await
        .unwrap()
        .status()
}

async fn ack(base: &str, secret: &ReadSecret, seq: u64, bearer: &str) -> reqwest::StatusCode {
    reqwest::Client::new()
        .delete(format!("{base}/v1/m/{}/{seq}", secret.mailbox_id()))
        .bearer_auth(bearer)
        .send()
        .await
        .unwrap()
        .status()
}

const WAIT: Duration = Duration::from_secs(2);

#[tokio::test]
async fn deliver_ack_and_redeliver_unacked() {
    let base = start(Limits::default()).await;
    let s = ReadSecret::generate();

    assert_eq!(post(&base, &s, envelope(1)).await, 202);
    let mut r = Sse::connect(&base, &s).await;
    let m0 = r.next(WAIT).await.unwrap();
    assert_eq!(m0["seq"], 0);
    assert_eq!(
        b64::decode(m0["body"].as_str().unwrap()).unwrap(),
        envelope(1)
    );

    // Live delivery while connected.
    assert_eq!(post(&base, &s, envelope(2)).await, 202);
    assert_eq!(r.next(WAIT).await.unwrap()["seq"], 1);

    // Ack only seq 0, reconnect: seq 1 comes again, seq 0 does not.
    assert_eq!(ack(&base, &s, 0, &s.to_bearer()).await, 204);
    drop(r);
    let mut r = Sse::connect(&base, &s).await;
    assert_eq!(r.next(WAIT).await.unwrap()["seq"], 1);
    assert!(r.next(Duration::from_millis(300)).await.is_none());
}

#[tokio::test]
async fn new_reader_supersedes_old() {
    let base = start(Limits::default()).await;
    let s = ReadSecret::generate();
    let mut old = Sse::connect(&base, &s).await;
    let mut new = Sse::connect(&base, &s).await;
    assert_eq!(post(&base, &s, envelope(1)).await, 202);
    assert_eq!(new.next(WAIT).await.unwrap()["seq"], 0);
    assert!(old.next(Duration::from_millis(300)).await.is_none());
}

#[tokio::test]
async fn auth_and_validation() {
    let base = start(Limits {
        max_envelope_bytes: 1024,
        mailbox_max_messages: 2,
        ..Limits::default()
    })
    .await;
    let s = ReadSecret::generate();
    let other = ReadSecret::generate();

    let wrong = reqwest::Client::new()
        .get(format!("{base}/v1/m/{}", s.mailbox_id()))
        .bearer_auth(other.to_bearer())
        .send()
        .await
        .unwrap();
    assert_eq!(wrong.status(), 401);
    assert_eq!(ack(&base, &s, 0, &other.to_bearer()).await, 401);

    assert_eq!(post(&base, &s, vec![1, 2, 3]).await, 400);
    assert_eq!(post(&base, &s, vec![9; 64]).await, 400);
    assert_eq!(post(&base, &s, vec![0; 4096]).await, 413);
    let bad_id = reqwest::Client::new()
        .post(format!("{base}/v1/m/nope"))
        .body(envelope(0))
        .send()
        .await
        .unwrap();
    assert_eq!(bad_id.status(), 400);

    assert_eq!(post(&base, &s, envelope(1)).await, 202);
    assert_eq!(post(&base, &s, envelope(2)).await, 202);
    assert_eq!(post(&base, &s, envelope(3)).await, 429);
}

#[tokio::test]
async fn per_ip_write_rate_limit() {
    let base = start(Limits {
        ip_writes_per_minute: 3,
        ..Limits::default()
    })
    .await;
    let secrets: Vec<_> = (0..5).map(|_| ReadSecret::generate()).collect();
    let codes: Vec<u16> =
        futures::future::join_all(secrets.iter().map(|s| post(&base, s, envelope(0))))
            .await
            .into_iter()
            .map(|c| c.as_u16())
            .collect();
    assert_eq!(codes.iter().filter(|c| **c == 202).count(), 3);
    assert_eq!(codes.iter().filter(|c| **c == 429).count(), 2);
}

#[tokio::test]
async fn info_and_health() {
    let base = start(Limits::default()).await;
    let info: Value = reqwest::get(format!("{base}/v1/info"))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(info["limits"]["max_envelope_bytes"], 272 << 10);
    assert_eq!(info["limits"]["message_ttl"], 600);
    let health: Value = reqwest::get(format!("{base}/health"))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(health["ok"], true);
}
