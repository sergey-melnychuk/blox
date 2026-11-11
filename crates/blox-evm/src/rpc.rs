//! The keystore's view of a chain: its configured endpoint (BLOX.md §10.3, §10.4).
//!
//! `ChainRpc` is synchronous and speaks JSON, so the Android app can implement it as a
//! UniFFI foreign trait over OkHttp, and the fill logic stays in Rust (§10.1).

use alloy_primitives::{Address, B256, U256};
use serde_json::{Value, json};

/// Why an endpoint call failed.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum RpcError {
    /// The endpoint couldn't be reached, or didn't answer with JSON-RPC.
    #[error("endpoint unreachable: {0}")]
    Unreachable(String),
    /// The endpoint answered with a JSON-RPC error.
    #[error("{message}")]
    Rpc { code: i64, message: String },
}

pub trait ChainRpc: Send + Sync {
    /// Calls `method` with `params` (a JSON array) and returns the JSON `result`.
    fn call(&self, method: &str, params: Value) -> Result<Value, RpcError>;
}

fn bad(what: &str) -> RpcError {
    RpcError::Unreachable(format!("unexpected answer to {what}"))
}

pub(crate) fn quantity(v: &Value, what: &str) -> Result<U256, RpcError> {
    let s = v.as_str().ok_or_else(|| bad(what))?;
    let h = s.strip_prefix("0x").ok_or_else(|| bad(what))?;
    U256::from_str_radix(if h.is_empty() { "0" } else { h }, 16).map_err(|_| bad(what))
}

pub(crate) fn q_u64(v: &Value, what: &str) -> Result<u64, RpcError> {
    u64::try_from(quantity(v, what)?).map_err(|_| bad(what))
}

pub(crate) fn q_u128(v: &Value, what: &str) -> Result<u128, RpcError> {
    u128::try_from(quantity(v, what)?).map_err(|_| bad(what))
}

pub(crate) fn hex_q(v: impl std::fmt::LowerHex) -> String {
    format!("{v:#x}")
}

/// Typed helpers over a `ChainRpc`.
pub struct Rpc<'a>(pub &'a dyn ChainRpc);

impl Rpc<'_> {
    pub fn chain_id(&self) -> Result<u64, RpcError> {
        q_u64(&self.0.call("eth_chainId", json!([]))?, "eth_chainId")
    }

    pub fn pending_nonce(&self, from: Address) -> Result<u64, RpcError> {
        let v = self
            .0
            .call("eth_getTransactionCount", json!([from, "pending"]))?;
        q_u64(&v, "eth_getTransactionCount")
    }

    pub fn pending_balance(&self, from: Address) -> Result<U256, RpcError> {
        quantity(
            &self.0.call("eth_getBalance", json!([from, "pending"]))?,
            "eth_getBalance",
        )
    }

    /// The latest block's base fee, or `None` on a chain without EIP-1559.
    pub fn base_fee(&self) -> Result<Option<u128>, RpcError> {
        let block = self
            .0
            .call("eth_getBlockByNumber", json!(["latest", false]))?;
        match block.get("baseFeePerGas") {
            None | Some(Value::Null) => Ok(None),
            Some(v) => q_u128(v, "baseFeePerGas").map(Some),
        }
    }

    pub fn gas_price(&self) -> Result<u128, RpcError> {
        q_u128(&self.0.call("eth_gasPrice", json!([]))?, "eth_gasPrice")
    }

    pub fn max_priority_fee(&self) -> Result<u128, RpcError> {
        q_u128(
            &self.0.call("eth_maxPriorityFeePerGas", json!([]))?,
            "eth_maxPriorityFeePerGas",
        )
    }

    pub fn estimate_gas(&self, call: Value) -> Result<u64, RpcError> {
        q_u64(
            &self.0.call("eth_estimateGas", json!([call]))?,
            "eth_estimateGas",
        )
    }

    /// Broadcasts a signed transaction; returns the hash the endpoint reports.
    pub fn send_raw(&self, raw: &[u8]) -> Result<B256, RpcError> {
        let v = self
            .0
            .call("eth_sendRawTransaction", json!([crate::to_hex(raw)]))?;
        v.as_str()
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| bad("eth_sendRawTransaction"))
    }
}
