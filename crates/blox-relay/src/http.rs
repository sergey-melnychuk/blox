//! HTTP API (BLOX.md §8.2).

use std::collections::HashMap;
use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::rejection::BytesRejection;
use axum::extract::{ConnectInfo, DefaultBodyLimit, MatchedPath, Path, Request, State};
use axum::http::{HeaderMap, HeaderName, Method, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use blox_proto::api::{self, Accepted, ErrorBody, ErrorCode, TicketRegistration};
use blox_proto::b64;
use blox_proto::envelope::{Kind, check_header};
use blox_proto::ident::{InboxId, Ticket, VerifyingKey};
use blox_proto::reqsig::{self, SigError};
use blox_proto::token::Token;
use bytes::Bytes;
use futures::Stream;
use serde_json::json;
use tokio::sync::Notify;
use tower_http::cors::{Any, CorsLayer};

use crate::Limits;
use crate::store::{Key, Queued, Store, Writer};

#[derive(Clone)]
pub struct AppState {
    store: Arc<Store>,
    limits: Limits,
    trust_proxy: bool,
    rates: Arc<Mutex<Rates>>,
    /// Test hook: seconds added to the relay's clock.
    clock_offset: i64,
}

/// Rate counters. Held in memory only, expired by the sweeper, never logged (§8.4).
#[derive(Default)]
struct Rates {
    ip_writes: HashMap<IpAddr, (Instant, u32)>,
    writer_writes: HashMap<Key, (Instant, u32)>,
    ip_readers: HashMap<IpAddr, usize>,
}

const MINUTE: Duration = Duration::from_secs(60);

fn bump<K: std::hash::Hash + Eq>(map: &mut HashMap<K, (Instant, u32)>, k: K, max: u32) -> bool {
    let now = Instant::now();
    let (start, count) = map.entry(k).or_insert((now, 0));
    if now.duration_since(*start) >= MINUTE {
        *start = now;
        *count = 0;
    }
    *count += 1;
    *count <= max
}

impl AppState {
    pub fn new(limits: Limits, trust_proxy: bool) -> Self {
        Self {
            store: Arc::new(Store::new(limits.clone())),
            limits,
            trust_proxy,
            rates: Arc::default(),
            clock_offset: 0,
        }
    }

    /// Shifts the relay's clock (tests of client clock handling).
    pub fn with_clock_offset(mut self, secs: i64) -> Self {
        self.clock_offset = secs;
        self
    }

    pub fn store(&self) -> &Store {
        &self.store
    }

    pub fn now(&self) -> u64 {
        let wall = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock after 1970")
            .as_secs();
        wall.saturating_add_signed(self.clock_offset)
    }

    pub fn sweep(&self) {
        let now = Instant::now();
        self.store.sweep(now, self.now());
        let mut r = self.rates.lock().unwrap();
        r.ip_writes
            .retain(|_, (start, _)| now.duration_since(*start) < MINUTE);
        r.writer_writes
            .retain(|_, (start, _)| now.duration_since(*start) < MINUTE);
    }

    fn allow_ip_write(&self, ip: IpAddr) -> Result<(), ApiError> {
        let mut r = self.rates.lock().unwrap();
        bump(&mut r.ip_writes, ip, self.limits.ip_writes_per_minute)
            .then_some(())
            .ok_or(ApiError(ErrorCode::RateLimited))
    }

    fn allow_writer(&self, writer: &VerifyingKey) -> Result<(), ApiError> {
        let mut r = self.rates.lock().unwrap();
        bump(
            &mut r.writer_writes,
            *writer.as_bytes(),
            self.limits.writer_writes_per_minute,
        )
        .then_some(())
        .ok_or(ApiError(ErrorCode::RateLimited))
    }

    fn acquire_ip_reader(&self, ip: IpAddr) -> bool {
        let mut r = self.rates.lock().unwrap();
        let n = r.ip_readers.entry(ip).or_default();
        if *n >= self.limits.ip_max_readers {
            return false;
        }
        *n += 1;
        true
    }

    fn release_ip_reader(&self, ip: IpAddr) {
        let mut r = self.rates.lock().unwrap();
        if let Some(n) = r.ip_readers.get_mut(&ip) {
            *n -= 1;
            if *n == 0 {
                r.ip_readers.remove(&ip);
            }
        }
    }

    fn client_ip(&self, peer: SocketAddr, headers: &HeaderMap) -> IpAddr {
        if self.trust_proxy {
            // The trusted proxy appends the client address last.
            let forwarded = headers
                .get("x-forwarded-for")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.rsplit(',').next())
                .and_then(|v| v.trim().parse().ok());
            if let Some(ip) = forwarded {
                return ip;
            }
        }
        peer.ip()
    }
}

pub fn router(state: AppState) -> Router {
    let max = state.limits.max_envelope_bytes;
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET, Method::POST, Method::DELETE])
        .allow_headers([
            header::AUTHORIZATION,
            header::CONTENT_TYPE,
            HeaderName::from_static(api::HEADER_TOKEN),
            HeaderName::from_static(api::HEADER_TICKET),
        ])
        .max_age(Duration::from_secs(86400));
    Router::new()
        .route("/v1/inbox/{id}", get(read).post(write))
        .route("/v1/inbox/{id}/{seq}", delete(ack))
        .route("/v1/inbox/{id}/tickets", post(register_ticket))
        .route("/v1/revoke", post(revoke))
        .route("/v1/info", get(info))
        .route("/health", get(|| async { Json(json!({ "ok": true })) }))
        .layer(DefaultBodyLimit::max(max))
        .layer(cors)
        .layer(middleware::from_fn(access_log))
        .with_state(state)
}

/// Logs the route template only — never the concrete path, which holds an inbox id (§8.5).
async fn access_log(req: Request, next: Next) -> Response {
    let method = req.method().clone();
    let route = req
        .extensions()
        .get::<MatchedPath>()
        .map(|p| p.as_str().to_owned())
        .unwrap_or_else(|| "<unmatched>".into());
    let start = Instant::now();
    let res = next.run(req).await;
    tracing::debug!(%method, route, status = res.status().as_u16(), ms = start.elapsed().as_millis() as u64);
    res
}

/// Error response: `{"error": code}` with the code's status (§8.2).
#[derive(Debug)]
struct ApiError(ErrorCode);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = StatusCode::from_u16(self.0.status()).expect("valid status");
        (status, Json(ErrorBody { error: self.0 })).into_response()
    }
}

impl From<SigError> for ApiError {
    fn from(e: SigError) -> Self {
        ApiError(match e {
            SigError::Clock => ErrorCode::Clock,
            SigError::Malformed | SigError::Signature => ErrorCode::Unauthorized,
        })
    }
}

type ApiResult = Result<Response, ApiError>;

fn parse_inbox(s: &str) -> Result<InboxId, ApiError> {
    InboxId::parse(s).map_err(|_| ApiError(ErrorCode::Malformed))
}

/// The envelope header the relay may look at (§4.5): version, type and minimum length.
fn check_envelope(bytes: &[u8]) -> Result<Kind, ApiError> {
    check_header(bytes).map_err(|_| ApiError(ErrorCode::Malformed))
}

fn header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

/// Checks the request signature against `key` with the relay's clock.
fn check_sig(
    state: &AppState,
    headers: &HeaderMap,
    key: &VerifyingKey,
    method: &str,
    path: &str,
    body: &[u8],
) -> Result<(), ApiError> {
    let auth =
        header(headers, header::AUTHORIZATION.as_str()).ok_or(ApiError(ErrorCode::Unauthorized))?;
    reqsig::verify(
        auth,
        key,
        method,
        path,
        body,
        state.now(),
        state.limits.clock_skew_secs,
    )?;
    Ok(())
}

async fn write(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> ApiResult {
    let inbox = parse_inbox(&id)?;
    let body = body.map_err(|_| ApiError(ErrorCode::TooLarge))?;
    let kind = check_envelope(&body)?;
    state.allow_ip_write(state.client_ip(peer, &headers))?;
    let now = state.now();
    let seq = if let Some(ticket) = header(&headers, api::HEADER_TICKET) {
        let ticket = Ticket::parse(ticket).map_err(|_| ApiError(ErrorCode::Malformed))?;
        if kind != Kind::Bind {
            return Err(ApiError(ErrorCode::Malformed));
        }
        state
            .store
            .push_with_ticket(*inbox.as_bytes(), ticket.hash(), body, now)
    } else {
        let token = header(&headers, api::HEADER_TOKEN).ok_or(ApiError(ErrorCode::Unauthorized))?;
        let token = Token::from_header(token).map_err(|_| ApiError(ErrorCode::Malformed))?;
        let party = token
            .body
            .party_of(&inbox)
            .ok_or(ApiError(ErrorCode::Unauthorized))?;
        token
            .verify(party)
            .map_err(|_| ApiError(ErrorCode::Unauthorized))?;
        let writer = token.body.keys(party.other()).sig;
        check_sig(
            &state,
            &headers,
            &writer,
            "POST",
            &format!("/v1/inbox/{id}"),
            &body,
        )?;
        check_token_times(&state, &token, now)?;
        if state.store.is_revoked(&token.id()) {
            return Err(ApiError(ErrorCode::Revoked));
        }
        state.allow_writer(&writer)?;
        state
            .store
            .push(*inbox.as_bytes(), body, Writer::Key(*writer.as_bytes()))
    }
    .map_err(ApiError)?;
    Ok((StatusCode::ACCEPTED, Json(Accepted { seq })).into_response())
}

fn check_token_times(state: &AppState, token: &Token, now: u64) -> Result<(), ApiError> {
    let b = &token.body;
    if b.expires_at <= now {
        return Err(ApiError(ErrorCode::Expired));
    }
    if b.issued_at > now + state.limits.clock_skew_secs
        || b.expires_at < b.issued_at
        || b.expires_at - b.issued_at > state.limits.max_token_lifetime_secs
    {
        return Err(ApiError(ErrorCode::Unauthorized));
    }
    Ok(())
}

async fn register_ticket(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> ApiResult {
    let inbox = parse_inbox(&id)?;
    let body = body.map_err(|_| ApiError(ErrorCode::TooLarge))?;
    check_sig(
        &state,
        &headers,
        &inbox,
        "POST",
        &format!("/v1/inbox/{id}/tickets"),
        &body,
    )?;
    let reg: TicketRegistration =
        serde_json::from_slice(&body).map_err(|_| ApiError(ErrorCode::Malformed))?;
    let now = state.now();
    if reg.expires_at <= now || reg.expires_at > now + state.limits.ticket_max_lifetime_secs {
        return Err(ApiError(ErrorCode::Malformed));
    }
    state.allow_ip_write(state.client_ip(peer, &headers))?;
    state
        .store
        .register_ticket(*inbox.as_bytes(), reg.ticket_hash, reg.expires_at, now)
        .map_err(ApiError)?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

async fn revoke(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> ApiResult {
    let body = body.map_err(|_| ApiError(ErrorCode::TooLarge))?;
    let token = header(&headers, api::HEADER_TOKEN).ok_or(ApiError(ErrorCode::Unauthorized))?;
    let token = Token::from_header(token).map_err(|_| ApiError(ErrorCode::Malformed))?;
    // Either party named in the token may revoke it; the token's own signatures aren't needed.
    let signed_by_party = [token.body.requester.sig, token.body.keystore.sig]
        .iter()
        .map(|k| check_sig(&state, &headers, k, "POST", "/v1/revoke", &body))
        .find(|r| !matches!(r, Err(ApiError(ErrorCode::Unauthorized))))
        .unwrap_or(Err(ApiError(ErrorCode::Unauthorized)));
    signed_by_party?;
    state.allow_ip_write(state.client_ip(peer, &headers))?;
    let now = state.now();
    if token.body.expires_at > now {
        let until = token
            .body
            .expires_at
            .min(now + state.limits.max_token_lifetime_secs);
        state.store.revoke(token.id(), until).map_err(ApiError)?;
    }
    Ok(StatusCode::NO_CONTENT.into_response())
}

async fn ack(
    State(state): State<AppState>,
    Path((id, seq)): Path<(String, u64)>,
    headers: HeaderMap,
) -> ApiResult {
    let inbox = parse_inbox(&id)?;
    check_sig(
        &state,
        &headers,
        &inbox,
        "DELETE",
        &format!("/v1/inbox/{id}/{seq}"),
        b"",
    )?;
    state.store.ack(inbox.as_bytes(), seq);
    Ok(StatusCode::NO_CONTENT.into_response())
}

async fn info(State(state): State<AppState>) -> Response {
    Json(json!({
        "version": env!("CARGO_PKG_VERSION"),
        "now": state.now(),
        "limits": state.limits,
    }))
    .into_response()
}

async fn read(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> ApiResult {
    let inbox = parse_inbox(&id)?;
    check_sig(
        &state,
        &headers,
        &inbox,
        "GET",
        &format!("/v1/inbox/{id}"),
        b"",
    )?;
    let ip = state.client_ip(peer, &headers);
    if !state.acquire_ip_reader(ip) {
        return Err(ApiError(ErrorCode::ReadersFull));
    }
    let notify = match state.store.attach_reader(*inbox.as_bytes()) {
        Ok(n) => n,
        Err(e) => {
            state.release_ip_reader(ip);
            return Err(ApiError(e));
        }
    };
    let reader = Reader {
        state,
        inbox: *inbox.as_bytes(),
        ip,
        notify,
        cursor: None,
        batch: Vec::new(),
    };
    let keep_alive = KeepAlive::new()
        .interval(Duration::from_secs(15))
        .text("ping");
    Ok(Sse::new(stream(reader))
        .keep_alive(keep_alive)
        .into_response())
}

/// One SSE reader. Dropping it (the client went away) releases its slots.
struct Reader {
    state: AppState,
    inbox: Key,
    ip: IpAddr,
    notify: Arc<Notify>,
    cursor: Option<u64>,
    batch: Vec<Queued>,
}

impl Drop for Reader {
    fn drop(&mut self) {
        self.state.store.detach_reader(&self.inbox);
        self.state.release_ip_reader(self.ip);
    }
}

fn stream(reader: Reader) -> impl Stream<Item = Result<Event, Infallible>> {
    futures::stream::unfold(reader, |mut r| async move {
        loop {
            if let Some(q) = r.batch.pop() {
                r.cursor = Some(q.seq);
                let data = api::Event {
                    seq: q.seq,
                    body: b64::encode(&q.body),
                    age_ms: q.enqueued.elapsed().as_millis() as u64,
                };
                let data = serde_json::to_string(&data).expect("event serializes");
                return Some((Ok(Event::default().event("msg").data(data)), r));
            }
            // Register for wake-ups before looking, so a push in between isn't missed.
            let notify = r.notify.clone();
            let notified = notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let mut pending = r.state.store.pending(&r.inbox, r.cursor);
            if pending.is_empty() {
                notified.await;
                continue;
            }
            pending.reverse(); // pop() yields ascending seq
            r.batch = pending;
        }
    })
}
