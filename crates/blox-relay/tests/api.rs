//! Relay API (BLOX.md §8.2) and the relay gates of §13.2–§13.3.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use blox_proto::api::{ErrorBody, ErrorCode, TicketRegistration};
use blox_proto::ident::{SigningKey, Ticket, VerifyingKey};
use blox_proto::keys::KeyPair;
use blox_proto::reqsig;
use blox_proto::token::{PartyKeys, Token, TokenBody};
use blox_relay::{AppState, Limits, router};
use futures::StreamExt;
use reqwest::StatusCode;
use serde_json::Value;

async fn start(state: AppState) -> String {
    let listener = tokio::net::TcpListener::bind("localhost:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = router(state).into_make_service_with_connect_info::<SocketAddr>();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{addr}")
}

async fn relay(limits: Limits) -> String {
    start(AppState::new(limits, false)).await
}

fn now() -> u64 {
    blox_proto::message::now()
}

struct Party {
    sig: SigningKey,
    kem: KeyPair,
}

impl Party {
    fn new() -> Self {
        Self {
            sig: SigningKey::generate(),
            kem: KeyPair::generate(),
        }
    }
    fn id(&self) -> VerifyingKey {
        self.sig.public()
    }
    fn keys(&self) -> PartyKeys {
        PartyKeys {
            sig: self.sig.public(),
            kem: self.kem.public(),
        }
    }
}

fn token_with(s: &Party, k: &Party, issued_at: u64, expires_at: u64) -> Token {
    let body = TokenBody {
        requester: s.keys(),
        keystore: k.keys(),
        issued_at,
        expires_at,
        relay: "http://localhost".into(),
    };
    Token::issue(body, &k.sig).unwrap()
}

fn token(s: &Party, k: &Party) -> Token {
    token_with(s, k, now(), now() + 86400)
}

/// A syntactically valid envelope of `kind` (the relay only checks the header).
fn envelope(kind: u8, tag: u8) -> Vec<u8> {
    let mut v = vec![1u8, kind];
    v.extend(std::iter::repeat_n(tag, 96));
    v
}

fn http() -> reqwest::Client {
    reqwest::Client::new()
}

async fn code(res: reqwest::Response) -> (StatusCode, Option<ErrorCode>) {
    let status = res.status();
    let body: Option<ErrorBody> = res.json().await.ok();
    (status, body.map(|b| b.error))
}

async fn write_signed(
    base: &str,
    inbox: &VerifyingKey,
    token: &Token,
    signer: &SigningKey,
    ts: u64,
    body: Vec<u8>,
) -> (StatusCode, Option<ErrorCode>) {
    let path = format!("/v1/inbox/{inbox}");
    let auth = reqsig::sign(signer, "POST", &path, ts, &body);
    let res = http()
        .post(format!("{base}{path}"))
        .header("authorization", auth)
        .header("blox-token", token.to_header())
        .header("content-type", "application/octet-stream")
        .body(body)
        .send()
        .await
        .unwrap();
    code(res).await
}

async fn write(
    base: &str,
    inbox: &VerifyingKey,
    token: &Token,
    signer: &SigningKey,
    body: Vec<u8>,
) -> (StatusCode, Option<ErrorCode>) {
    write_signed(base, inbox, token, signer, now(), body).await
}

async fn write_ticket(
    base: &str,
    inbox: &VerifyingKey,
    ticket: &Ticket,
    body: Vec<u8>,
) -> (StatusCode, Option<ErrorCode>) {
    let res = http()
        .post(format!("{base}/v1/inbox/{inbox}"))
        .header("blox-ticket", ticket.to_string())
        .body(body)
        .send()
        .await
        .unwrap();
    code(res).await
}

async fn register(
    base: &str,
    inbox: &VerifyingKey,
    signer: &SigningKey,
    ticket: &Ticket,
    expires_at: u64,
) -> (StatusCode, Option<ErrorCode>) {
    let path = format!("/v1/inbox/{inbox}/tickets");
    let body = serde_json::to_vec(&TicketRegistration {
        ticket_hash: ticket.hash(),
        expires_at,
    })
    .unwrap();
    let res = http()
        .post(format!("{base}{path}"))
        .header(
            "authorization",
            reqsig::sign(signer, "POST", &path, now(), &body),
        )
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await
        .unwrap();
    code(res).await
}

async fn revoke(base: &str, token: &Token, signer: &SigningKey) -> (StatusCode, Option<ErrorCode>) {
    let res = http()
        .post(format!("{base}/v1/revoke"))
        .header(
            "authorization",
            reqsig::sign(signer, "POST", "/v1/revoke", now(), b""),
        )
        .header("blox-token", token.to_header())
        .send()
        .await
        .unwrap();
    code(res).await
}

async fn ack(base: &str, owner: &SigningKey, seq: u64) -> StatusCode {
    let path = format!("/v1/inbox/{}/{seq}", owner.public());
    http()
        .delete(format!("{base}{path}"))
        .header(
            "authorization",
            reqsig::sign(owner, "DELETE", &path, now(), b""),
        )
        .send()
        .await
        .unwrap()
        .status()
}

struct Sse {
    stream: futures::stream::BoxStream<'static, reqwest::Result<bytes::Bytes>>,
    buf: String,
}

impl Sse {
    async fn open(base: &str, inbox: &VerifyingKey, signer: &SigningKey) -> reqwest::Response {
        let path = format!("/v1/inbox/{inbox}");
        http()
            .get(format!("{base}{path}"))
            .header(
                "authorization",
                reqsig::sign(signer, "GET", &path, now(), b""),
            )
            .send()
            .await
            .unwrap()
    }

    async fn connect(base: &str, owner: &SigningKey) -> Self {
        let res = Self::open(base, &owner.public(), owner).await;
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

const T: Duration = Duration::from_secs(3);
const QUIET: Duration = Duration::from_millis(300);
const ACCEPTED: (StatusCode, Option<ErrorCode>) = (StatusCode::ACCEPTED, None);

fn err(status: u16, code: ErrorCode) -> (StatusCode, Option<ErrorCode>) {
    (StatusCode::from_u16(status).unwrap(), Some(code))
}

#[tokio::test]
async fn info_reports_time_and_limits() {
    let base = relay(Limits::default()).await;
    let v: Value = http()
        .get(format!("{base}/v1/info"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(v["now"].as_u64().unwrap().abs_diff(now()) <= 1);
    assert_eq!(v["limits"]["message_ttl"], 300);
    assert_eq!(v["limits"]["writer_max_messages"], 4);
}

#[tokio::test]
async fn no_anonymous_writes() {
    let base = relay(Limits::default()).await;
    let s = Party::new();
    let res = http()
        .post(format!("{base}/v1/inbox/{}", s.id()))
        .body(envelope(2, 0))
        .send()
        .await
        .unwrap();
    assert_eq!(code(res).await, err(401, ErrorCode::Unauthorized));
    let res = http()
        .post(format!("{base}/v1/inbox/not-a-key"))
        .body(envelope(2, 0))
        .send()
        .await
        .unwrap();
    assert_eq!(code(res).await, err(400, ErrorCode::Malformed));
}

#[tokio::test]
async fn tickets_work_once() {
    let base = relay(Limits::default()).await;
    let s = Party::new();
    let ticket = Ticket::generate();
    assert_eq!(
        register(&base, &s.id(), &s.sig, &ticket, now() + 120)
            .await
            .0,
        StatusCode::NO_CONTENT
    );
    // A message envelope can't use a ticket; only bind can.
    assert_eq!(
        write_ticket(&base, &s.id(), &ticket, envelope(2, 1)).await,
        err(400, ErrorCode::Malformed)
    );
    assert_eq!(
        write_ticket(&base, &s.id(), &ticket, envelope(1, 1)).await,
        ACCEPTED
    );
    assert_eq!(
        write_ticket(&base, &s.id(), &ticket, envelope(1, 2)).await,
        err(409, ErrorCode::TicketUsed)
    );
    assert_eq!(
        write_ticket(&base, &s.id(), &Ticket::generate(), envelope(1, 3)).await,
        err(401, ErrorCode::Unauthorized)
    );
    // Wrong key, too long a lifetime, and the live-ticket limit.
    let other = SigningKey::generate();
    assert_eq!(
        register(&base, &s.id(), &other, &Ticket::generate(), now() + 120).await,
        err(401, ErrorCode::Unauthorized)
    );
    assert_eq!(
        register(&base, &s.id(), &s.sig, &Ticket::generate(), now() + 181).await,
        err(400, ErrorCode::Malformed)
    );
    for _ in 0..4 {
        let r = register(&base, &s.id(), &s.sig, &Ticket::generate(), now() + 60).await;
        assert_eq!(r.0, StatusCode::NO_CONTENT);
    }
    assert_eq!(
        register(&base, &s.id(), &s.sig, &Ticket::generate(), now() + 60).await,
        err(429, ErrorCode::TicketsFull)
    );
}

#[tokio::test]
async fn expired_ticket() {
    let base = relay(Limits::default()).await;
    let s = Party::new();
    let ticket = Ticket::generate();
    register(&base, &s.id(), &s.sig, &ticket, now() + 1).await;
    tokio::time::sleep(Duration::from_millis(2100)).await;
    assert_eq!(
        write_ticket(&base, &s.id(), &ticket, envelope(1, 1)).await,
        err(401, ErrorCode::Expired)
    );
}

#[tokio::test]
async fn token_writes_need_the_recipients_signature_and_the_writers_request() {
    let base = relay(Limits::default()).await;
    let (s, k) = (Party::new(), Party::new());
    let mut t = token(&s, &k);
    // Half-signed (keystore only): the requester may write to K, not the other way round.
    assert_eq!(
        write(&base, &k.id(), &t, &s.sig, envelope(2, 1)).await,
        ACCEPTED
    );
    assert_eq!(
        write(&base, &s.id(), &t, &k.sig, envelope(2, 1)).await,
        err(401, ErrorCode::Unauthorized)
    );
    t.countersign(&s.sig).unwrap();
    assert_eq!(
        write(&base, &s.id(), &t, &k.sig, envelope(2, 2)).await,
        ACCEPTED
    );
    // Signed by the recipient itself, or by an outsider.
    assert_eq!(
        write(&base, &k.id(), &t, &k.sig, envelope(2, 3)).await,
        err(401, ErrorCode::Unauthorized)
    );
    let outsider = Party::new();
    assert_eq!(
        write(&base, &k.id(), &t, &outsider.sig, envelope(2, 3)).await,
        err(401, ErrorCode::Unauthorized)
    );
    // An inbox that isn't a party to the token.
    assert_eq!(
        write(&base, &outsider.id(), &t, &s.sig, envelope(2, 3)).await,
        err(401, ErrorCode::Unauthorized)
    );
    // A token whose signature doesn't verify.
    let mut forged = token(&s, &k).to_bytes();
    let n = forged.len();
    forged[n - 1] ^= 1;
    let forged = Token::from_bytes(&forged).unwrap();
    assert_eq!(
        write(&base, &k.id(), &forged, &s.sig, envelope(2, 3)).await,
        err(401, ErrorCode::Unauthorized)
    );
    // A stale request signature.
    assert_eq!(
        write_signed(&base, &k.id(), &t, &s.sig, now() - 120, envelope(2, 3)).await,
        err(401, ErrorCode::Clock)
    );
}

#[tokio::test]
async fn token_times() {
    let base = relay(Limits::default()).await;
    let (s, k) = (Party::new(), Party::new());
    let expired = token_with(&s, &k, now() - 100, now() - 1);
    assert_eq!(
        write(&base, &k.id(), &expired, &s.sig, envelope(2, 1)).await,
        err(401, ErrorCode::Expired)
    );
    let too_long = token_with(&s, &k, now(), now() + 91 * 86400);
    assert_eq!(
        write(&base, &k.id(), &too_long, &s.sig, envelope(2, 1)).await,
        err(401, ErrorCode::Unauthorized)
    );
    let future = token_with(&s, &k, now() + 600, now() + 86400);
    assert_eq!(
        write(&base, &k.id(), &future, &s.sig, envelope(2, 1)).await,
        err(401, ErrorCode::Unauthorized)
    );
}

#[tokio::test]
async fn revocation_by_either_party() {
    let base = relay(Limits::default()).await;
    let (s, k) = (Party::new(), Party::new());
    let mut t = token(&s, &k);
    // The requester may revoke a token it hasn't signed (the contested case, §5.3).
    assert_eq!(revoke(&base, &t, &s.sig).await.0, StatusCode::NO_CONTENT);
    assert_eq!(
        write(&base, &k.id(), &t, &s.sig, envelope(2, 1)).await,
        err(403, ErrorCode::Revoked)
    );
    // Countersigning doesn't change the id, so the full token is revoked too.
    t.countersign(&s.sig).unwrap();
    assert_eq!(
        write(&base, &s.id(), &t, &k.sig, envelope(2, 1)).await,
        err(403, ErrorCode::Revoked)
    );
    let t2 = token(&s, &k);
    assert_eq!(
        revoke(&base, &t2, &Party::new().sig).await,
        err(401, ErrorCode::Unauthorized)
    );
    assert_eq!(revoke(&base, &t2, &k.sig).await.0, StatusCode::NO_CONTENT);
    assert_eq!(
        write(&base, &k.id(), &t2, &s.sig, envelope(2, 1)).await,
        err(403, ErrorCode::Revoked)
    );
}

#[tokio::test]
async fn several_readers_each_get_every_message() {
    let base = relay(Limits {
        inbox_max_readers: 2,
        ..Limits::default()
    })
    .await;
    let (s, k) = (Party::new(), Party::new());
    let mut t = token(&s, &k);
    t.countersign(&s.sig).unwrap();
    let mut a = Sse::connect(&base, &s.sig).await;
    let mut b = Sse::connect(&base, &s.sig).await;
    let res = Sse::open(&base, &s.id(), &s.sig).await;
    assert_eq!(code(res).await, err(429, ErrorCode::ReadersFull));
    let res = Sse::open(&base, &s.id(), &k.sig).await;
    assert_eq!(code(res).await, err(401, ErrorCode::Unauthorized));

    write(&base, &s.id(), &t, &k.sig, envelope(2, 7)).await;
    let ma = a.next(T).await.unwrap();
    let mb = b.next(T).await.unwrap();
    assert_eq!(ma, mb);
    // Acknowledged by one reader: gone for readers that connect later.
    assert_eq!(ack(&base, &s.sig, ma["seq"].as_u64().unwrap()).await, 204);
    drop(b);
    tokio::time::sleep(Duration::from_millis(100)).await;
    let mut c = Sse::connect(&base, &s.sig).await;
    assert!(c.next(QUIET).await.is_none());
    // Acknowledging needs the inbox key.
    let path = format!("/v1/inbox/{}/0", s.id());
    let res = http()
        .delete(format!("{base}{path}"))
        .header(
            "authorization",
            reqsig::sign(&k.sig, "DELETE", &path, now(), b""),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 401);
}

#[tokio::test]
async fn reconnecting_reader_gets_unacknowledged_messages() {
    let base = relay(Limits::default()).await;
    let (s, k) = (Party::new(), Party::new());
    let t = token(&s, &k);
    for tag in 1..=2 {
        assert_eq!(
            write(&base, &k.id(), &t, &s.sig, envelope(2, tag)).await,
            ACCEPTED
        );
    }
    let mut r = Sse::connect(&base, &k.sig).await;
    let first = r.next(T).await.unwrap();
    let second = r.next(T).await.unwrap();
    assert_eq!(
        (first["seq"].as_u64(), second["seq"].as_u64()),
        (Some(0), Some(1))
    );
    assert_eq!(ack(&base, &k.sig, 0).await, 204);
    drop(r);
    let mut r = Sse::connect(&base, &k.sig).await;
    assert_eq!(r.next(T).await.unwrap()["seq"], 1);
    assert!(r.next(QUIET).await.is_none());
    // Live delivery to a connected reader.
    write(&base, &k.id(), &t, &s.sig, envelope(2, 3)).await;
    assert_eq!(r.next(T).await.unwrap()["seq"], 2);
}

#[tokio::test]
async fn per_writer_quota_isolates_connections() {
    let base = relay(Limits::default()).await;
    let k = Party::new();
    let (s1, s2) = (Party::new(), Party::new());
    let (t1, t2) = (token(&s1, &k), token(&s2, &k));
    for i in 0..4 {
        assert_eq!(
            write(&base, &k.id(), &t1, &s1.sig, envelope(2, i)).await,
            ACCEPTED
        );
    }
    assert_eq!(
        write(&base, &k.id(), &t1, &s1.sig, envelope(2, 9)).await,
        err(429, ErrorCode::WriterFull)
    );
    assert_eq!(
        write(&base, &k.id(), &t2, &s2.sig, envelope(2, 9)).await,
        ACCEPTED
    );
}

#[tokio::test]
async fn size_queue_and_rate_limits() {
    let base = relay(Limits {
        max_envelope_bytes: 200,
        inbox_max_messages: 2,
        ..Limits::default()
    })
    .await;
    let k = Party::new();
    let mut big = envelope(2, 0);
    big.resize(201, 0);
    let (s1, s2, s3) = (Party::new(), Party::new(), Party::new());
    let t1 = token(&s1, &k);
    assert_eq!(
        write(&base, &k.id(), &t1, &s1.sig, big).await,
        err(413, ErrorCode::TooLarge)
    );
    assert_eq!(
        write(&base, &k.id(), &t1, &s1.sig, envelope(2, 1)).await,
        ACCEPTED
    );
    assert_eq!(
        write(&base, &k.id(), &token(&s2, &k), &s2.sig, envelope(2, 1)).await,
        ACCEPTED
    );
    assert_eq!(
        write(&base, &k.id(), &token(&s3, &k), &s3.sig, envelope(2, 1)).await,
        err(429, ErrorCode::QueueFull)
    );

    let base = relay(Limits {
        ip_writes_per_minute: 2,
        ..Limits::default()
    })
    .await;
    let s = Party::new();
    let t = token(&s, &k);
    for _ in 0..2 {
        assert_eq!(
            write(&base, &k.id(), &t, &s.sig, envelope(2, 1)).await,
            ACCEPTED
        );
    }
    assert_eq!(
        write(&base, &k.id(), &t, &s.sig, envelope(2, 1)).await,
        err(429, ErrorCode::RateLimited)
    );
}

#[tokio::test]
async fn cors_preflight() {
    let base = relay(Limits::default()).await;
    let res = http()
        .request(reqwest::Method::OPTIONS, format!("{base}/v1/inbox/x"))
        .header("origin", "https://app.example")
        .header("access-control-request-method", "POST")
        .header(
            "access-control-request-headers",
            "authorization,content-type,blox-token,blox-ticket",
        )
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let h = res.headers();
    assert_eq!(h["access-control-allow-origin"], "*");
    let allowed = h["access-control-allow-headers"].to_str().unwrap();
    for name in ["authorization", "content-type", "blox-token", "blox-ticket"] {
        assert!(allowed.contains(name), "{allowed}");
    }
    assert_eq!(h["access-control-max-age"], "86400");
    assert!(h.get("access-control-allow-credentials").is_none());
}

#[tokio::test]
async fn memory_returns_to_baseline() {
    let state = AppState::new(
        Limits {
            message_ttl: Duration::from_secs(1),
            ip_writes_per_minute: 100_000,
            writer_writes_per_minute: 100_000,
            ..Limits::default()
        },
        false,
    );
    let base = start(state.clone()).await;
    let s = Party::new();
    for _ in 0..200 {
        let k = Party::new();
        write(&base, &k.id(), &token(&s, &k), &s.sig, envelope(2, 1)).await;
    }
    let ticket = Ticket::generate();
    register(&base, &s.id(), &s.sig, &ticket, now() + 1).await;
    revoke(
        &base,
        &token_with(&s, &Party::new(), now(), now() + 1),
        &s.sig,
    )
    .await;
    let st = state.store().stats();
    assert_eq!((st.inboxes, st.tickets, st.revocations), (200, 1, 1));
    tokio::time::sleep(Duration::from_millis(2100)).await;
    state.sweep();
    assert_eq!(state.store().stats(), blox_relay::Stats::default());
}

/// §13.3: 1,000 concurrent readers, enqueue-to-delivery p99 < 50 ms. Slow; run with --ignored.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn thousand_readers_latency() {
    let base = relay(Limits {
        ip_max_readers: 2000,
        ip_writes_per_minute: 100_000,
        writer_writes_per_minute: 100_000,
        ..Limits::default()
    })
    .await;
    let k = Party::new();
    let mut readers = Vec::new();
    let mut writers = Vec::new();
    for _ in 0..1000 {
        let s = Party::new();
        readers.push(Sse::connect(&base, &s.sig).await);
        let mut t = token(&s, &k);
        t.countersign(&s.sig).unwrap();
        writers.push((s, t));
    }
    let mut lat = Vec::new();
    for ((s, t), mut r) in writers.iter().zip(readers.drain(..)) {
        let start = Instant::now();
        write(&base, &s.id(), t, &k.sig, envelope(2, 1)).await;
        r.next(T).await.unwrap();
        lat.push(start.elapsed());
    }
    lat.sort();
    let p99 = lat[lat.len() * 99 / 100];
    assert!(p99 < Duration::from_millis(50), "p99 {p99:?}");
}
