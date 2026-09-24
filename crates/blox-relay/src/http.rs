//! HTTP API (§8.2).

use std::collections::HashMap;
use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::{ConnectInfo, DefaultBodyLimit, MatchedPath, Path, Request, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get};
use axum::{Json, Router};
use blox_proto::b64;
use blox_proto::envelope::check_header;
use blox_proto::mailbox::{MailboxId, ReadSecret};
use bytes::Bytes;
use futures::Stream;
use serde_json::json;
use tokio::sync::Notify;

use crate::Limits;
use crate::store::{PushError, Store};

#[derive(Clone)]
pub struct AppState {
    store: Arc<Store>,
    limits: Limits,
    trust_proxy: bool,
    ip: Arc<Mutex<IpState>>,
}

/// Per-IP counters. Held in memory only, expired by the sweeper, never logged (§8.4).
#[derive(Default)]
struct IpState {
    writes: HashMap<IpAddr, (Instant, u32)>,
    readers: HashMap<IpAddr, usize>,
}

impl AppState {
    pub fn new(limits: Limits, trust_proxy: bool) -> Self {
        Self {
            store: Arc::new(Store::new(limits.clone())),
            limits,
            trust_proxy,
            ip: Arc::default(),
        }
    }

    pub fn store(&self) -> &Store {
        &self.store
    }

    pub fn sweep(&self) {
        let now = Instant::now();
        self.store.sweep(now);
        let mut ip = self.ip.lock().unwrap();
        ip.writes
            .retain(|_, (start, _)| now.duration_since(*start) < Duration::from_secs(60));
    }

    fn allow_write(&self, addr: IpAddr) -> bool {
        let now = Instant::now();
        let mut ip = self.ip.lock().unwrap();
        let (start, count) = ip.writes.entry(addr).or_insert((now, 0));
        if now.duration_since(*start) >= Duration::from_secs(60) {
            *start = now;
            *count = 0;
        }
        *count += 1;
        *count <= self.limits.ip_writes_per_minute
    }

    fn acquire_reader(&self, addr: IpAddr) -> bool {
        let mut ip = self.ip.lock().unwrap();
        let n = ip.readers.entry(addr).or_default();
        if *n >= self.limits.ip_max_readers {
            return false;
        }
        *n += 1;
        true
    }

    fn release_reader(&self, addr: IpAddr) {
        let mut ip = self.ip.lock().unwrap();
        if let Some(n) = ip.readers.get_mut(&addr) {
            *n -= 1;
            if *n == 0 {
                ip.readers.remove(&addr);
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
    Router::new()
        .route("/v1/m/{mailbox_id}", get(read).post(write))
        .route("/v1/m/{mailbox_id}/{seq}", delete(ack))
        .route("/v1/info", get(info))
        .route("/health", get(|| async { Json(json!({ "ok": true })) }))
        .layer(DefaultBodyLimit::max(max))
        .layer(middleware::from_fn(access_log))
        .with_state(state)
}

/// Logs the route template only — never the concrete path, which holds a mailbox id (§8.5).
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

/// Error response: `{"error": "..."}` with a status code.
struct ApiError(StatusCode, &'static str);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({ "error": self.1 }))).into_response()
    }
}

type ApiResult = Result<Response, ApiError>;

fn parse_id(s: &str) -> Result<MailboxId, ApiError> {
    MailboxId::parse(s).map_err(|_| ApiError(StatusCode::BAD_REQUEST, "malformed mailbox id"))
}

fn authorize(id: &MailboxId, headers: &HeaderMap) -> Result<(), ApiError> {
    const UNAUTHORIZED: ApiError = ApiError(StatusCode::UNAUTHORIZED, "unauthorized");
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or(UNAUTHORIZED)?;
    let secret = ReadSecret::parse(token).map_err(|_| UNAUTHORIZED)?;
    if secret.mailbox_id() != *id {
        return Err(UNAUTHORIZED);
    }
    Ok(())
}

async fn write(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult {
    let id = parse_id(&id)?;
    if check_header(&body).is_err() {
        return Err(ApiError(
            StatusCode::BAD_REQUEST,
            "malformed envelope header",
        ));
    }
    if !state.allow_write(state.client_ip(peer, &headers)) {
        return Err(ApiError(StatusCode::TOO_MANY_REQUESTS, "rate limited"));
    }
    match state.store.push(id, body) {
        Ok(seq) => Ok((StatusCode::ACCEPTED, Json(json!({ "seq": seq }))).into_response()),
        Err(PushError::MailboxFull) => Err(ApiError(StatusCode::TOO_MANY_REQUESTS, "mailbox full")),
        Err(PushError::RelayFull) => Err(ApiError(StatusCode::SERVICE_UNAVAILABLE, "relay full")),
    }
}

async fn ack(
    State(state): State<AppState>,
    Path((id, seq)): Path<(String, u64)>,
    headers: HeaderMap,
) -> ApiResult {
    let id = parse_id(&id)?;
    authorize(&id, &headers)?;
    state.store.ack(&id, seq);
    Ok(StatusCode::NO_CONTENT.into_response())
}

async fn info(State(state): State<AppState>) -> Response {
    Json(json!({ "version": env!("CARGO_PKG_VERSION"), "limits": state.limits })).into_response()
}

async fn read(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> ApiResult {
    let id = parse_id(&id)?;
    authorize(&id, &headers)?;
    let ip = state.client_ip(peer, &headers);
    if !state.acquire_reader(ip) {
        return Err(ApiError(StatusCode::TOO_MANY_REQUESTS, "too many readers"));
    }
    let (generation, notify) = state.store.attach_reader(id);
    let reader = Reader {
        state,
        id,
        generation,
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

/// One SSE reader. Dropping it (client gone, or superseded) releases its slot.
struct Reader {
    state: AppState,
    id: MailboxId,
    generation: u64,
    ip: IpAddr,
    notify: Arc<Notify>,
    cursor: Option<u64>,
    batch: Vec<crate::store::Queued>,
}

impl Drop for Reader {
    fn drop(&mut self) {
        self.state.store.detach_reader(&self.id, self.generation);
        self.state.release_reader(self.ip);
    }
}

fn stream(reader: Reader) -> impl Stream<Item = Result<Event, Infallible>> {
    futures::stream::unfold(reader, |mut r| async move {
        loop {
            if let Some(q) = r.batch.pop() {
                r.cursor = Some(q.seq);
                let data = json!({
                    "seq": q.seq,
                    "body": b64::encode(&q.body),
                    "age_ms": q.enqueued.elapsed().as_millis() as u64,
                });
                return Some((Ok(Event::default().event("msg").data(data.to_string())), r));
            }
            // Superseded by a newer reader: end this stream.
            let mut pending = r.state.store.pending(&r.id, r.generation, r.cursor)?;
            if pending.is_empty() {
                r.notify.notified().await;
                continue;
            }
            pending.reverse(); // pop() yields ascending seq
            r.batch = pending;
        }
    })
}
