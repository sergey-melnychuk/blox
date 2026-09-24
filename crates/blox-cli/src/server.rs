//! The JSON-RPC endpoint (§9.2, §9.4, §9.7).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::{Request, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use blox_evm::rpc::{Fill, TxRequest, TxType};
use blox_evm::verify::Verified;
use blox_evm::{Address, KIND_PERSONAL_SIGN, KIND_TX, KIND_TYPED_DATA, caip};
use blox_proto::message::{Origin, SignRequest, now};
use serde_json::{Value, json};

use crate::queue::{OnQr, Queue, QueueConfig};
use crate::upstream::{RpcError, Upstream, parse_quantity};

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

struct App {
    cfg: Config,
    port: u16,
    upstream: Upstream,
    chain_id: u64,
    queue: Queue,
    accounts: Mutex<Vec<Address>>,
    /// Next nonce per sender, from transactions signed in this process.
    next_nonce: Mutex<HashMap<Address, u64>>,
}

/// Serves the adapter on `listener` until the process exits.
pub async fn serve(cfg: Config, listener: tokio::net::TcpListener) -> std::io::Result<()> {
    let port = listener.local_addr()?.port();
    let upstream = Upstream::new(&cfg.upstream);
    let chain_id = upstream
        .call_u128("eth_chainId", json!([]))
        .await
        .map_err(|e| std::io::Error::other(format!("cannot reach upstream: {}", e.message)))?
        as u64;
    let mut accounts = cfg.accounts.clone();
    for a in load_cache(cfg.state_dir.as_ref()) {
        if !accounts.contains(&a) {
            accounts.push(a);
        }
    }
    let queue = Queue::spawn(QueueConfig {
        relay: cfg.relay.clone(),
        label: cfg.label.clone(),
        join_timeout: cfg.join_timeout,
        idle_timeout: cfg.idle_timeout,
        on_qr: cfg.on_qr.clone(),
    });
    let app = Arc::new(App {
        cfg,
        port,
        upstream,
        chain_id,
        queue,
        accounts: Mutex::new(accounts),
        next_nonce: Mutex::default(),
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
            .is_ok_and(|o| app.cfg.allow_origins.iter().any(|a| a == o));
        if !allowed {
            return (StatusCode::FORBIDDEN, "origin not allowed").into_response();
        }
    }
    if let Some(token) = &app.cfg.token {
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
    let client = headers
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
    let result = match method {
        "eth_accounts" | "eth_requestAccounts" => Ok(json!(app.accounts.lock().unwrap().clone())),
        "eth_sendTransaction" => send_transaction(app, &params, origin, true).await,
        "eth_signTransaction" => send_transaction(app, &params, origin, false).await,
        "personal_sign" => personal_sign(app, &params, origin).await,
        "eth_signTypedData_v4" => sign_typed_data(app, &params, origin).await,
        "eth_sign" | "eth_signTypedData" | "eth_signTypedData_v1" | "eth_signTypedData_v3" => {
            Err(RpcError::new(
                4200,
                format!("{method} is not supported; it can sign arbitrary hashes"),
            ))
        }
        _ => {
            return app
                .upstream
                .forward(req)
                .await
                .unwrap_or_else(|e| error_response(id, &e));
        }
    };
    match result {
        Ok(result) => json!({ "jsonrpc": "2.0", "id": id, "result": result }),
        Err(e) => error_response(id, &e),
    }
}

fn error_response(id: Value, e: &RpcError) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": e.to_json() })
}

fn signing_request(
    app: &App,
    account: Address,
    kind: &str,
    payload: Value,
    origin: Origin,
) -> SignRequest {
    SignRequest {
        chain: caip::chain(app.chain_id),
        account: caip::account(app.chain_id, account),
        kind: kind.into(),
        payload,
        origin: Some(origin),
        expires_at: now() + app.cfg.timeout.as_secs(),
    }
}

async fn send_transaction(
    app: &App,
    params: &Value,
    origin: Origin,
    broadcast: bool,
) -> Result<Value, RpcError> {
    let obj = params
        .get(0)
        .ok_or_else(|| RpcError::invalid_params("missing transaction object"))?;
    let req = TxRequest::parse(obj).map_err(|e| RpcError::invalid_params(e.to_string()))?;
    let fill = fill(app, &req, obj).await?;
    let tx = req
        .build(fill)
        .map_err(|e| RpcError::invalid_params(e.to_string()))?;
    let nonce = tx.nonce();
    let payload = json!({ "tx": format!("0x{}", hex_encode(&tx.encode_for_signing())) });
    let to = req
        .to
        .map_or("contract creation".to_owned(), |a| format!("tx to {a}"));
    let summary = format!("{to} (nonce {nonce})");
    let sreq = signing_request(app, req.from, KIND_TX, payload, origin);
    let Verified::Tx { raw, .. } = app
        .queue
        .submit((req.from, nonce), sreq, summary, app.cfg.timeout)
        .await?
    else {
        unreachable!("tx requests verify to Verified::Tx");
    };
    {
        let mut next = app.next_nonce.lock().unwrap();
        let n = next.entry(req.from).or_default();
        *n = (*n).max(nonce + 1);
    }
    remember(app, req.from);
    let raw_hex = format!("0x{}", hex_encode(&raw));
    if broadcast {
        app.upstream
            .call("eth_sendRawTransaction", json!([raw_hex]))
            .await
    } else {
        Ok(json!(raw_hex))
    }
}

/// Fetches from upstream only the values the caller left out (§9.4).
async fn fill(app: &App, req: &TxRequest, obj: &Value) -> Result<Fill, RpcError> {
    let up = &app.upstream;
    let mut fill = Fill {
        chain_id: app.chain_id,
        ..Fill::default()
    };
    if req.nonce.is_none() {
        let pending = up
            .call_u128("eth_getTransactionCount", json!([req.from, "pending"]))
            .await? as u64;
        let local = app
            .next_nonce
            .lock()
            .unwrap()
            .get(&req.from)
            .copied()
            .unwrap_or(0);
        fill.nonce = pending.max(local);
    }
    let ty = req
        .tx_type()
        .map_err(|e| RpcError::invalid_params(e.to_string()))?;
    match ty {
        TxType::Legacy | TxType::Eip2930 if req.gas_price.is_none() => {
            fill.gas_price = up.call_u128("eth_gasPrice", json!([])).await?;
        }
        TxType::Eip1559 => {
            if req.max_priority_fee_per_gas.is_none() {
                fill.max_priority_fee_per_gas =
                    up.call_u128("eth_maxPriorityFeePerGas", json!([])).await?;
            }
            if req.max_fee_per_gas.is_none() {
                let block = up
                    .call("eth_getBlockByNumber", json!(["latest", false]))
                    .await?;
                let base = block
                    .get("baseFeePerGas")
                    .and_then(parse_quantity)
                    .unwrap_or(0);
                let prio = req
                    .max_priority_fee_per_gas
                    .unwrap_or(fill.max_priority_fee_per_gas);
                fill.max_fee_per_gas = 2 * base + prio;
            }
        }
        _ => {}
    }
    if req.gas.is_none() {
        let mut est = obj.clone();
        if let Some(o) = est.as_object_mut() {
            o.remove("gas");
        }
        let gas = up.call_u128("eth_estimateGas", json!([est])).await? as f64;
        fill.gas = (gas * app.cfg.gas_multiplier).ceil() as u64;
    }
    Ok(fill)
}

async fn personal_sign(app: &App, params: &Value, origin: Origin) -> Result<Value, RpcError> {
    let msg = params
        .get(0)
        .and_then(Value::as_str)
        .ok_or_else(|| RpcError::invalid_params("missing message"))?;
    let account = parse_address(params.get(1))?;
    // Tools send hex; accept plain text too, as wallets do.
    let hex = if msg.starts_with("0x") {
        msg.to_owned()
    } else {
        format!("0x{}", hex_encode(msg.as_bytes()))
    };
    let req = signing_request(
        app,
        account,
        KIND_PERSONAL_SIGN,
        json!({ "message": hex }),
        origin,
    );
    signature(app, account, req, "personal_sign").await
}

async fn sign_typed_data(app: &App, params: &Value, origin: Origin) -> Result<Value, RpcError> {
    let account = parse_address(params.get(0))?;
    let data = match params.get(1) {
        Some(Value::String(s)) => serde_json::from_str(s)
            .map_err(|_| RpcError::invalid_params("typed data is not JSON"))?,
        Some(v @ Value::Object(_)) => v.clone(),
        _ => return Err(RpcError::invalid_params("missing typed data")),
    };
    let req = signing_request(
        app,
        account,
        KIND_TYPED_DATA,
        json!({ "data": data }),
        origin,
    );
    signature(app, account, req, "typed data").await
}

async fn signature(
    app: &App,
    account: Address,
    req: SignRequest,
    what: &str,
) -> Result<Value, RpcError> {
    match app
        .queue
        .submit((account, 0), req, what.into(), app.cfg.timeout)
        .await?
    {
        Verified::Signature(sig) => {
            remember(app, account);
            Ok(json!(sig))
        }
        Verified::Tx { .. } => unreachable!("message requests verify to Verified::Signature"),
    }
}

fn parse_address(v: Option<&Value>) -> Result<Address, RpcError> {
    v.and_then(Value::as_str)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| RpcError::invalid_params("missing or invalid address"))
}

fn hex_encode(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Adds a verified signer address to `eth_accounts` and the on-disk cache.
fn remember(app: &App, a: Address) {
    let mut accounts = app.accounts.lock().unwrap();
    if accounts.contains(&a) {
        return;
    }
    accounts.push(a);
    if let Some(dir) = &app.cfg.state_dir {
        let _ = std::fs::create_dir_all(dir);
        let _ = std::fs::write(
            dir.join("accounts.json"),
            serde_json::to_vec_pretty(&*accounts).unwrap_or_default(),
        );
    }
}

fn load_cache(dir: Option<&PathBuf>) -> Vec<Address> {
    dir.and_then(|d| std::fs::read(d.join("accounts.json")).ok())
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}
