//! The adapter core (BLOX.md §9): turns Ethereum JSON-RPC signing calls into
//! Blox signing requests, and verifies what comes back before anything is used.
//!
//! Embed it in any JSON-RPC proxy: call [`Adapter::handle`] for every request
//! and forward it yourself when it returns `None`. `blox rpc` is a thin HTTP
//! server around this crate.

mod queue;
mod upstream;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use blox_evm::rpc::{Fill, TxRequest, TxType};
use blox_evm::tx::UnsignedTx;
use blox_evm::verify::Verified;
use blox_evm::{Address, KIND_PERSONAL_SIGN, KIND_TX, KIND_TYPED_DATA, caip, to_hex};
use blox_proto::message::{Origin, SignRequest, now};
use futures::future::BoxFuture;
use serde_json::{Value, json};

pub use blox_proto::message::Origin as RequestOrigin;
pub use upstream::{HttpUpstream, Upstream, parse_quantity};

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

    /// EIP-1193 "user rejected"; use it from [`Hooks::before_sign`] to veto a request.
    pub fn user_rejected(message: impl Into<String>) -> Self {
        Self::new(4001, message)
    }

    pub fn to_json(&self) -> Value {
        json!({ "code": self.code, "message": self.message })
    }
}

/// What is about to be sent to the phone.
#[derive(Debug)]
pub enum Review<'a> {
    /// The exact transaction that will be signed: every field filled in.
    Tx {
        chain_id: u64,
        from: Address,
        tx: &'a UnsignedTx,
    },
    /// A message signature (`evm.personal_sign` or `evm.typed_data`).
    Message {
        chain_id: u64,
        account: Address,
        kind: &'a str,
        payload: &'a Value,
    },
}

/// Progress reports, for a terminal or a UI.
#[derive(Clone, Debug, PartialEq)]
pub enum Event {
    Joined,
    /// A request went to the phone; `summary` holds no secrets (kind, recipient, nonce).
    Sent {
        summary: String,
    },
    Signed,
    Rejected {
        reason: String,
    },
    Failed {
        message: String,
    },
    /// The phone returned something that doesn't match the request. The session is closed.
    VerificationFailed {
        detail: String,
    },
    SessionClosed,
    /// An address proven by a verified signature.
    AccountSeen(Address),
}

/// Integration points. Only `show_qr` is required.
pub trait Hooks: Send + Sync {
    /// Display a session QR code (`BLOX:…`) for the phone to scan.
    fn show_qr(&self, uri: &str);

    /// Called before a request is sent to the phone. Return an error to veto it;
    /// the caller receives that error. This is where a simulator reviews `tx`.
    fn before_sign<'a>(&'a self, _review: Review<'a>) -> BoxFuture<'a, Result<(), RpcError>> {
        Box::pin(async { Ok(()) })
    }

    fn event(&self, _event: Event) {}
}

pub struct Config {
    pub relay: String,
    /// Name shown on the phone.
    pub label: String,
    /// Addresses reported by `eth_accounts` before any signature is seen.
    pub accounts: Vec<Address>,
    /// How long a signing call may wait for approval.
    pub timeout: Duration,
    pub join_timeout: Duration,
    pub idle_timeout: Duration,
    pub gas_multiplier: f64,
}

pub struct Adapter {
    cfg: Config,
    upstream: Arc<dyn Upstream>,
    hooks: Arc<dyn Hooks>,
    queue: queue::Queue,
    accounts: Mutex<Vec<Address>>,
    /// Next nonce per (chain, sender), from transactions signed by this adapter.
    next_nonce: Mutex<HashMap<(u64, Address), u64>>,
}

impl Adapter {
    /// Starts the adapter. Needs a Tokio runtime.
    pub fn new(cfg: Config, upstream: Arc<dyn Upstream>, hooks: Arc<dyn Hooks>) -> Self {
        let queue = queue::Queue::spawn(queue::QueueConfig {
            relay: cfg.relay.clone(),
            label: cfg.label.clone(),
            join_timeout: cfg.join_timeout,
            idle_timeout: cfg.idle_timeout,
            hooks: hooks.clone(),
        });
        let accounts = Mutex::new(cfg.accounts.clone());
        Self {
            cfg,
            upstream,
            hooks,
            queue,
            accounts,
            next_nonce: Mutex::default(),
        }
    }

    /// `eth_accounts`: configured addresses plus every verified signer.
    pub fn accounts(&self) -> Vec<Address> {
        self.accounts.lock().unwrap().clone()
    }

    /// Handles a signing method on `chain_id`. Returns `None` for any other method:
    /// forward those upstream unchanged.
    pub async fn handle(
        &self,
        chain_id: u64,
        method: &str,
        params: &Value,
        origin: Origin,
    ) -> Option<Result<Value, RpcError>> {
        Some(match method {
            "eth_accounts" | "eth_requestAccounts" => Ok(json!(self.accounts())),
            "eth_sendTransaction" => self.transaction(chain_id, params, origin, true).await,
            "eth_signTransaction" => self.transaction(chain_id, params, origin, false).await,
            "personal_sign" => self.personal_sign(chain_id, params, origin).await,
            "eth_signTypedData_v4" => self.sign_typed_data(chain_id, params, origin).await,
            "eth_sign" | "eth_signTypedData" | "eth_signTypedData_v1" | "eth_signTypedData_v3" => {
                Err(RpcError::new(
                    4200,
                    format!("{method} is not supported; it can sign arbitrary hashes"),
                ))
            }
            _ => return None,
        })
    }

    fn request(
        &self,
        chain_id: u64,
        account: Address,
        kind: &str,
        payload: Value,
        origin: Origin,
    ) -> SignRequest {
        SignRequest {
            chain: caip::chain(chain_id),
            account: caip::account(chain_id, account),
            kind: kind.into(),
            payload,
            origin: Some(origin),
            expires_at: now() + self.cfg.timeout.as_secs(),
        }
    }

    async fn transaction(
        &self,
        chain_id: u64,
        params: &Value,
        origin: Origin,
        broadcast: bool,
    ) -> Result<Value, RpcError> {
        let obj = params
            .get(0)
            .ok_or_else(|| RpcError::invalid_params("missing transaction object"))?;
        let req = TxRequest::parse(obj).map_err(|e| RpcError::invalid_params(e.to_string()))?;
        let fill = self.fill(chain_id, &req, obj).await?;
        let tx = req
            .build(fill)
            .map_err(|e| RpcError::invalid_params(e.to_string()))?;
        self.hooks
            .before_sign(Review::Tx {
                chain_id,
                from: req.from,
                tx: &tx,
            })
            .await?;

        let nonce = tx.nonce();
        let to = req
            .to
            .map_or("contract creation".to_owned(), |a| format!("tx to {a}"));
        let summary = format!("{to} (nonce {nonce})");
        let sreq = self.request(
            chain_id,
            req.from,
            KIND_TX,
            json!({ "tx": to_hex(tx.encode_for_signing()) }),
            origin,
        );
        let Verified::Tx { raw, .. } = self
            .queue
            .submit((chain_id, req.from, nonce), sreq, summary, self.cfg.timeout)
            .await?
        else {
            unreachable!("tx requests verify to Verified::Tx");
        };
        {
            let mut next = self.next_nonce.lock().unwrap();
            let n = next.entry((chain_id, req.from)).or_default();
            *n = (*n).max(nonce + 1);
        }
        self.remember(req.from);
        let raw = to_hex(raw);
        if broadcast {
            self.upstream
                .call(chain_id, "eth_sendRawTransaction", json!([raw]))
                .await
        } else {
            Ok(json!(raw))
        }
    }

    /// Fetches only the values the caller left out (§9.4).
    async fn fill(&self, chain_id: u64, req: &TxRequest, obj: &Value) -> Result<Fill, RpcError> {
        let up = self.upstream.as_ref();
        let mut fill = Fill {
            chain_id,
            ..Fill::default()
        };
        if req.nonce.is_none() {
            let pending = upstream::call_u128(
                up,
                chain_id,
                "eth_getTransactionCount",
                json!([req.from, "pending"]),
            )
            .await? as u64;
            let local = self
                .next_nonce
                .lock()
                .unwrap()
                .get(&(chain_id, req.from))
                .copied()
                .unwrap_or(0);
            fill.nonce = pending.max(local);
        }
        match req
            .tx_type()
            .map_err(|e| RpcError::invalid_params(e.to_string()))?
        {
            TxType::Legacy | TxType::Eip2930 if req.gas_price.is_none() => {
                fill.gas_price =
                    upstream::call_u128(up, chain_id, "eth_gasPrice", json!([])).await?;
            }
            TxType::Eip1559 => {
                if req.max_priority_fee_per_gas.is_none() {
                    fill.max_priority_fee_per_gas =
                        upstream::call_u128(up, chain_id, "eth_maxPriorityFeePerGas", json!([]))
                            .await?;
                }
                if req.max_fee_per_gas.is_none() {
                    let block = up
                        .call(chain_id, "eth_getBlockByNumber", json!(["latest", false]))
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
            let gas =
                upstream::call_u128(up, chain_id, "eth_estimateGas", json!([est])).await? as f64;
            fill.gas = (gas * self.cfg.gas_multiplier).ceil() as u64;
        }
        Ok(fill)
    }

    async fn personal_sign(
        &self,
        chain_id: u64,
        params: &Value,
        origin: Origin,
    ) -> Result<Value, RpcError> {
        let msg = params
            .get(0)
            .and_then(Value::as_str)
            .ok_or_else(|| RpcError::invalid_params("missing message"))?;
        let account = parse_address(params.get(1))?;
        // Tools send hex; accept plain text too, as wallets do.
        let hex = if msg.starts_with("0x") {
            msg.to_owned()
        } else {
            to_hex(msg.as_bytes())
        };
        self.message(
            chain_id,
            account,
            KIND_PERSONAL_SIGN,
            json!({ "message": hex }),
            origin,
            "personal_sign",
        )
        .await
    }

    async fn sign_typed_data(
        &self,
        chain_id: u64,
        params: &Value,
        origin: Origin,
    ) -> Result<Value, RpcError> {
        let account = parse_address(params.get(0))?;
        let data = match params.get(1) {
            Some(Value::String(s)) => serde_json::from_str(s)
                .map_err(|_| RpcError::invalid_params("typed data is not JSON"))?,
            Some(v @ Value::Object(_)) => v.clone(),
            _ => return Err(RpcError::invalid_params("missing typed data")),
        };
        self.message(
            chain_id,
            account,
            KIND_TYPED_DATA,
            json!({ "data": data }),
            origin,
            "typed data",
        )
        .await
    }

    async fn message(
        &self,
        chain_id: u64,
        account: Address,
        kind: &str,
        payload: Value,
        origin: Origin,
        summary: &str,
    ) -> Result<Value, RpcError> {
        self.hooks
            .before_sign(Review::Message {
                chain_id,
                account,
                kind,
                payload: &payload,
            })
            .await?;
        let req = self.request(chain_id, account, kind, payload, origin);
        match self
            .queue
            .submit(
                (chain_id, account, 0),
                req,
                summary.into(),
                self.cfg.timeout,
            )
            .await?
        {
            Verified::Signature(sig) => {
                self.remember(account);
                Ok(json!(sig))
            }
            Verified::Tx { .. } => unreachable!("message requests verify to Verified::Signature"),
        }
    }

    fn remember(&self, a: Address) {
        let mut accounts = self.accounts.lock().unwrap();
        if !accounts.contains(&a) {
            accounts.push(a);
            drop(accounts);
            self.hooks.event(Event::AccountSeen(a));
        }
    }
}

fn parse_address(v: Option<&Value>) -> Result<Address, RpcError> {
    v.and_then(Value::as_str)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| RpcError::invalid_params("missing or invalid address"))
}
