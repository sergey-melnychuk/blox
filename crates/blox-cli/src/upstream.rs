use serde_json::{Value, json};

/// A JSON-RPC error object.
#[derive(Clone, Debug, PartialEq)]
pub struct RpcError {
    pub code: i64,
    pub message: String,
}

impl RpcError {
    pub fn new(code: i64, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(-32603, message)
    }

    pub fn invalid_params(message: impl Into<String>) -> Self {
        Self::new(-32602, message)
    }

    pub fn to_json(&self) -> Value {
        json!({ "code": self.code, "message": self.message })
    }
}

#[derive(Clone)]
pub struct Upstream {
    url: String,
    http: reqwest::Client,
}

impl Upstream {
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

    /// Calls `method` and returns its `result`.
    pub async fn call(&self, method: &str, params: Value) -> Result<Value, RpcError> {
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
    }

    pub async fn call_u128(&self, method: &str, params: Value) -> Result<u128, RpcError> {
        let v = self.call(method, params).await?;
        parse_quantity(&v)
            .ok_or_else(|| RpcError::internal(format!("upstream: bad quantity from {method}")))
    }
}

pub fn parse_quantity(v: &Value) -> Option<u128> {
    u128::from_str_radix(v.as_str()?.strip_prefix("0x")?, 16).ok()
}
