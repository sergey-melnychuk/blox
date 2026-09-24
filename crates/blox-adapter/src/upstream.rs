use futures::future::BoxFuture;
use serde_json::{Value, json};

use crate::RpcError;

/// Chain access for filling transactions and broadcasting. Implement it to route
/// by chain (e.g. one RPC URL per chain id).
pub trait Upstream: Send + Sync {
    /// Calls `method` on `chain_id` and returns its `result`.
    fn call<'a>(
        &'a self,
        chain_id: u64,
        method: &'a str,
        params: Value,
    ) -> BoxFuture<'a, Result<Value, RpcError>>;
}

/// One JSON-RPC endpoint; ignores `chain_id` (the caller checked it at startup).
#[derive(Clone)]
pub struct HttpUpstream {
    url: String,
    http: reqwest::Client,
}

impl HttpUpstream {
    pub fn new(url: &str) -> Self {
        Self {
            url: url.to_owned(),
            http: reqwest::Client::new(),
        }
    }

    /// Forwards one request object unchanged and returns the upstream response object.
    pub async fn forward(&self, req: &Value) -> Result<Value, RpcError> {
        let res = self
            .http
            .post(&self.url)
            .json(req)
            .send()
            .await
            .map_err(|e| RpcError::internal(format!("upstream: {e}")))?;
        res.json()
            .await
            .map_err(|e| RpcError::internal(format!("upstream: {e}")))
    }

    pub async fn chain_id(&self) -> Result<u64, RpcError> {
        let v = self.call(0, "eth_chainId", json!([])).await?;
        parse_quantity(&v)
            .map(|n| n as u64)
            .ok_or_else(|| RpcError::internal("upstream: bad eth_chainId"))
    }
}

impl Upstream for HttpUpstream {
    fn call<'a>(
        &'a self,
        _chain_id: u64,
        method: &'a str,
        params: Value,
    ) -> BoxFuture<'a, Result<Value, RpcError>> {
        Box::pin(async move {
            let res = self
                .forward(&json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params }))
                .await?;
            if let Some(e) = res.get("error") {
                let code = e.get("code").and_then(Value::as_i64).unwrap_or(-32603);
                let msg = e
                    .get("message")
                    .and_then(Value::as_str)
                    .unwrap_or("upstream error");
                return Err(RpcError::new(code, msg));
            }
            res.get("result")
                .cloned()
                .ok_or_else(|| RpcError::internal("upstream: no result"))
        })
    }
}

pub(crate) async fn call_u128(
    up: &dyn Upstream,
    chain_id: u64,
    method: &str,
    params: Value,
) -> Result<u128, RpcError> {
    let v = up.call(chain_id, method, params).await?;
    parse_quantity(&v)
        .ok_or_else(|| RpcError::internal(format!("upstream: bad quantity from {method}")))
}

pub fn parse_quantity(v: &Value) -> Option<u128> {
    u128::from_str_radix(v.as_str()?.strip_prefix("0x")?, 16).ok()
}
