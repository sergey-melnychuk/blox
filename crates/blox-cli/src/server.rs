//! The HTTP endpoint (§9.2, §9.7) around [`blox_adapter::Adapter`].

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Request, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use blox_adapter::{Adapter, Event, Hooks, HttpUpstream, RpcError};
use blox_evm::Address;
use blox_proto::message::Origin;
use serde_json::{Value, json};

pub type OnQr = Arc<dyn Fn(&str) + Send + Sync>;

pub struct Config {
    pub relay: String,
    pub upstream: String,
    pub label: String,
    /// Addresses to report from `eth_accounts`, in addition to cached ones.
    pub accounts: Vec<Address>,
    pub token: Option<String>,
    pub allow_origins: Vec<String>,
    pub timeout: Duration,
    pub join_timeout: Duration,
    pub idle_timeout: Duration,
    pub gas_multiplier: f64,
    /// Where `accounts.json` is cached; `None` disables the cache.
    pub state_dir: Option<PathBuf>,
    pub on_qr: OnQr,
}

/// Terminal output and the on-disk account cache.
struct Terminal {
    on_qr: OnQr,
    state_dir: Option<PathBuf>,
    seen: std::sync::Mutex<Vec<Address>>,
}

impl Hooks for Terminal {
    fn show_qr(&self, uri: &str) {
        (self.on_qr)(uri)
    }

    fn event(&self, event: Event) {
        match event {
            Event::Joined => eprintln!("✓ phone joined"),
            Event::Sent { summary } => eprintln!("→ sent: {summary}"),
            Event::Signed => eprintln!("✓ signed"),
            Event::Rejected { reason } => eprintln!("✗ rejected ({reason})"),
            Event::Failed { message } => eprintln!("✗ {message}"),
            Event::VerificationFailed { detail } => {
                eprintln!("⚠ signer response failed verification ({detail}); closing session")
            }
            Event::SessionClosed => eprintln!("session closed"),
            Event::AccountSeen(a) => {
                let mut seen = self.seen.lock().unwrap();
                seen.push(a);
                if let Some(dir) = &self.state_dir {
                    let _ = std::fs::create_dir_all(dir);
                    let _ = std::fs::write(
                        dir.join("accounts.json"),
                        serde_json::to_vec_pretty(&*seen).unwrap_or_default(),
                    );
                }
            }
        }
    }
}

struct App {
    adapter: Adapter,
    upstream: HttpUpstream,
    chain_id: u64,
    port: u16,
    token: Option<String>,
    allow_origins: Vec<String>,
}

/// Serves the adapter on `listener` until the process exits.
pub async fn serve(cfg: Config, listener: tokio::net::TcpListener) -> std::io::Result<()> {
    let port = listener.local_addr()?.port();
    let upstream = HttpUpstream::new(&cfg.upstream);
    let chain_id = upstream
        .chain_id()
        .await
        .map_err(|e| std::io::Error::other(format!("cannot reach upstream: {}", e.message)))?;
    let cached = load_cache(cfg.state_dir.as_ref());
    let mut accounts = cfg.accounts.clone();
    for a in &cached {
        if !accounts.contains(a) {
            accounts.push(*a);
        }
    }
    let hooks = Arc::new(Terminal {
        on_qr: cfg.on_qr.clone(),
        state_dir: cfg.state_dir.clone(),
        seen: cached.into(),
    });
    let adapter = Adapter::new(
        blox_adapter::Config {
            relay: cfg.relay,
            label: cfg.label,
            accounts,
            timeout: cfg.timeout,
            join_timeout: cfg.join_timeout,
            idle_timeout: cfg.idle_timeout,
            gas_multiplier: cfg.gas_multiplier,
        },
        Arc::new(upstream.clone()),
        hooks,
    );
    let app = Arc::new(App {
        adapter,
        upstream,
        chain_id,
        port,
        token: cfg.token,
        allow_origins: cfg.allow_origins,
    });
    let router = Router::new()
        .route("/", post(rpc))
        .layer(middleware::from_fn_with_state(app.clone(), guard))
        .with_state(app);
    axum::serve(
        listener,
        router.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
}

/// Blocks DNS rebinding, browser CSRF and (optionally) unauthenticated callers (§9.7).
async fn guard(State(app): State<Arc<App>>, req: Request, next: Next) -> Response {
    let headers = req.headers();
    let host_ok = headers
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .is_some_and(|h| {
            let p = app.port;
            h == format!("localhost:{p}")
                || h == format!("localhost:{p}")
                || h == format!("[ipv6-host]:{p}")
        });
    if !host_ok {
        return (StatusCode::FORBIDDEN, "bad Host header").into_response();
    }
    if let Some(origin) = headers.get(header::ORIGIN) {
        let allowed = origin
            .to_str()
            .is_ok_and(|o| app.allow_origins.iter().any(|a| a == o));
        if !allowed {
            return (StatusCode::FORBIDDEN, "origin not allowed").into_response();
        }
    }
    if let Some(token) = &app.token {
        let ok = headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .is_some_and(|t| t == token);
        if !ok {
            return (StatusCode::UNAUTHORIZED, "missing or wrong token").into_response();
        }
    }
    next.run(req).await
}

async fn rpc(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Json<Value> {
    let client: Option<String> = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.chars().take(64).collect());
    match body {
        // Batch members run in order; signing requests queue behind each other anyway.
        Value::Array(reqs) => {
            let mut out = Vec::with_capacity(reqs.len());
            for r in &reqs {
                out.push(handle(&app, r, client.clone()).await);
            }
            Json(Value::Array(out))
        }
        req => Json(handle(&app, &req, client).await),
    }
}

async fn handle(app: &App, req: &Value, client: Option<String>) -> Value {
    let id = req.get("id").cloned().unwrap_or(Value::Null);
    let method = req
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let params = req.get("params").cloned().unwrap_or(json!([]));
    let origin = Origin { client, note: None };
    match app
        .adapter
        .handle(app.chain_id, method, &params, origin)
        .await
    {
        Some(Ok(result)) => json!({ "jsonrpc": "2.0", "id": id, "result": result }),
        Some(Err(e)) => error_response(id, &e),
        None => app
            .upstream
            .forward(req)
            .await
            .unwrap_or_else(|e| error_response(id, &e)),
    }
}

fn error_response(id: Value, e: &RpcError) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": e.to_json() })
}

fn load_cache(dir: Option<&PathBuf>) -> Vec<Address> {
    dir.and_then(|d| std::fs::read(d.join("accounts.json")).ok())
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}
