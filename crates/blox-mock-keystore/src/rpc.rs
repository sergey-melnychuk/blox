//! A JSON-RPC `ChainRpc` over HTTP for the mock keystore's endpoints (e.g. a local anvil).

use std::sync::atomic::{AtomicU64, Ordering};

use blox_evm::rpc::{ChainRpc, RpcError};
use serde_json::{Value, json};

/// Calls an HTTP JSON-RPC endpoint. `call` blocks: use it from `spawn_blocking`.
pub struct HttpRpc {
    url: String,
    client: reqwest::Client,
    runtime: tokio::runtime::Handle,
    id: AtomicU64,
}

impl HttpRpc {
    /// Must be created inside a Tokio runtime.
    pub fn new(url: &str) -> Self {
        Self {
            url: url.to_owned(),
            client: reqwest::Client::new(),
            runtime: tokio::runtime::Handle::current(),
            id: AtomicU64::new(1),
        }
    }

    /// The host shown as "Sent via".
    pub fn host(&self) -> &str {
        blox_proto::relay_url::host(&self.url)
    }

    /// The same call, for async callers.
    pub async fn call_async(&self, method: &str, params: Value) -> Result<Value, RpcError> {
        let id = self.id.fetch_add(1, Ordering::Relaxed);
        let body = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
        let res = self
            .client
            .post(&self.url)
            .json(&body)
            .send()
            .await
            .map_err(|e| RpcError::Unreachable(kind(&e)))?;
        let v: Value = res
            .json()
            .await
            .map_err(|e| RpcError::Unreachable(kind(&e)))?;
        if let Some(err) = v.get("error") {
            return Err(RpcError::Rpc {
                code: err["code"].as_i64().unwrap_or(0),
                message: err["message"].as_str().unwrap_or("error").to_owned(),
            });
        }
        Ok(v.get("result").cloned().unwrap_or(Value::Null))
    }
}

fn kind(e: &reqwest::Error) -> String {
    if e.is_connect() {
        "connection refused".into()
    } else if e.is_timeout() {
        "timeout".into()
    } else {
        "bad answer".into()
    }
}

impl ChainRpc for HttpRpc {
    fn call(&self, method: &str, params: Value) -> Result<Value, RpcError> {
        self.runtime.block_on(self.call_async(method, params))
    }
}
