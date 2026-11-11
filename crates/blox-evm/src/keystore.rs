//! The keystore's request flow (BLOX.md §10.4–§10.8): review → approve → (broadcast).
//!
//! The app (or the mock keystore) owns state such as the last nonce sent and the stored
//! answers; these functions are pure apart from the endpoint calls.

use alloy_primitives::{Address, B256};
use alloy_signer_local::PrivateKeySigner;
use blox_proto::message::{RejectReason, SignRequest, SignResponse};

use crate::display::{Display, DisplayCtx, describe};
use crate::fill::{FillError, fill};
use crate::intent::{Intent, decode};
use crate::rpc::{ChainRpc, Rpc};
use crate::sign::{Prepared, Signed, sign};
use crate::{caip, to_hex};

/// The chain endpoint the user configured for the request's chain.
pub struct Endpoint<'a> {
    pub rpc: &'a dyn ChainRpc,
    /// Shown as "Sent via" / "Filled from".
    pub host: &'a str,
}

/// A request ready for the review screen.
#[derive(Clone, Debug)]
pub struct Review {
    pub chain_id: u64,
    pub prepared: Prepared,
    pub display: Display,
    pub expires_at: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReviewError {
    /// Answer `rejected` with this reason without asking the user.
    Reject(RejectReason),
    /// Show "This transaction would fail" with the endpoint's message; only Reject, which
    /// answers `would_fail`.
    WouldFail(String),
    /// Show the endpoint's error with Retry and Reject.
    Unreachable(String),
}

/// Checks, decodes and (for transactions) fills a request (§10.4).
///
/// `endpoint` is `None` when the user has no endpoint for the chain. `last_sent_nonce` is
/// the last nonce the app sent for this chain and account since it started.
pub fn review<'a>(
    req: &SignRequest,
    ts: u64,
    now: u64,
    signer: (Address, &str),
    endpoint_for: impl FnOnce(u64) -> Option<Endpoint<'a>>,
    last_sent_nonce: impl FnOnce(u64) -> Option<u64>,
) -> Result<Review, ReviewError> {
    let decoded = decode(req, ts, now).map_err(ReviewError::Reject)?;
    let (from, label) = signer;
    let chain_id = decoded.chain_id;
    let (prepared, host, warnings) = match decoded.intent {
        Intent::Send(intent) | Intent::SignTx(intent) => {
            let broadcast = req.kind == crate::intent::KIND_SEND;
            let ep = endpoint_for(chain_id).ok_or(ReviewError::Reject(RejectReason::NoEndpoint))?;
            let filled =
                fill(ep.rpc, chain_id, from, &intent, last_sent_nonce(chain_id)).map_err(|e| {
                    match e {
                        FillError::WouldFail(m) => ReviewError::WouldFail(m),
                        FillError::Unreachable(m) => ReviewError::Unreachable(m),
                    }
                })?;
            (
                Prepared::Tx {
                    tx: filled.tx,
                    broadcast,
                },
                Some(ep.host),
                filled.warnings,
            )
        }
        Intent::PersonalSign(m) => (Prepared::PersonalSign(m), None, vec![]),
        Intent::TypedData(td) => (Prepared::TypedData(td), None, vec![]),
    };
    let display = describe(
        &prepared,
        &DisplayCtx {
            from,
            signer_label: label,
            endpoint_host: host,
            warnings,
        },
    );
    Ok(Review {
        chain_id,
        prepared,
        display,
        expires_at: decoded.expires_at,
    })
}

/// What to do after the user approved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Approved {
    /// Send this answer.
    Answer(SignResponse),
    /// `evm.send`: record `raw` and `tx_hash` with the request id (§10.8), then call
    /// [`broadcast`] and send its answer.
    Broadcast {
        raw: Vec<u8>,
        tx_hash: B256,
        nonce: u64,
    },
}

/// Signs an approved review with the signer's key.
pub fn approve(signer: &PrivateKeySigner, review: &Review) -> Approved {
    let account = caip::account(review.chain_id, signer.address());
    match sign(signer, &review.prepared) {
        Signed::Tx {
            raw,
            hash,
            nonce,
            broadcast: true,
        } => Approved::Broadcast {
            raw,
            tx_hash: hash,
            nonce,
        },
        Signed::Tx { raw, hash, .. } => Approved::Answer(SignResponse::SignedTx {
            account,
            tx_hash: to_hex(hash),
            raw: to_hex(raw),
        }),
        Signed::Message(signature) => Approved::Answer(SignResponse::Signed { account, signature }),
    }
}

/// Calls `eth_sendRawTransaction` once (no retry) and builds `sent` or `failed` (§6.4).
pub fn broadcast(
    rpc: &dyn ChainRpc,
    chain_id: u64,
    from: Address,
    raw: &[u8],
    tx_hash: B256,
) -> SignResponse {
    let account = caip::account(chain_id, from);
    match Rpc(rpc).send_raw(raw) {
        Ok(_) => SignResponse::Sent {
            account,
            tx_hash: to_hex(tx_hash),
        },
        Err(e) => failed(chain_id, from, tx_hash, &e.to_string()),
    }
}

/// `failed` with `tx_hash`, e.g. when the app died between signing and broadcasting (§10.8).
pub fn failed(chain_id: u64, from: Address, tx_hash: B256, error: &str) -> SignResponse {
    SignResponse::Failed {
        account: caip::account(chain_id, from),
        tx_hash: to_hex(tx_hash),
        error: error.to_owned(),
    }
}

pub fn rejected(reason: RejectReason) -> SignResponse {
    SignResponse::Rejected { reason }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fill::tests::london;
    use crate::sign::signer_from_mnemonic;
    use serde_json::json;
    use std::sync::LazyLock;

    static RPC: LazyLock<crate::fill::tests::Fake> = LazyLock::new(london);

    fn endpoint(_: u64) -> Option<Endpoint<'static>> {
        Some(Endpoint {
            rpc: &*RPC,
            host: "base.example",
        })
    }

    fn req(kind: &str, payload: serde_json::Value) -> SignRequest {
        SignRequest {
            chain: "eip155:8453".into(),
            kind: kind.into(),
            payload,
            origin: None,
            expires_at: 1300,
        }
    }

    #[test]
    fn send_flow() {
        let s = signer_from_mnemonic(
            "test test test test test test test test test test test junk",
            0,
        )
        .unwrap();
        let r = req(
            "evm.send",
            json!({"to": "0x70997970C51812dc3A010C7d01b50e0d17dc79C8", "value": "0x1"}),
        );
        let rv = review(&r, 1000, 1000, (s.address(), "Main"), endpoint, |_| None).unwrap();
        assert!(
            rv.display
                .fields
                .iter()
                .any(|f| f.label == "Sent via" && f.value == "base.example")
        );
        let Approved::Broadcast { tx_hash, .. } = approve(&s, &rv) else {
            panic!()
        };
        let mut rpc = london();
        rpc.answers
            .insert("eth_sendRawTransaction", Ok(json!(to_hex(tx_hash))));
        assert!(matches!(
            broadcast(&rpc, 8453, s.address(), &[1], tx_hash),
            SignResponse::Sent { .. }
        ));
        let refused = broadcast(&london(), 8453, s.address(), &[1], tx_hash);
        assert!(matches!(refused, SignResponse::Failed { .. }));
    }

    #[test]
    fn sign_tx_messages_and_rejections() {
        let s = signer_from_mnemonic(
            "test test test test test test test test test test test junk",
            0,
        )
        .unwrap();
        let r = req("evm.sign_tx", json!({"to": null, "data": "0x6080"}));
        let rv = review(&r, 1000, 1000, (s.address(), "Main"), endpoint, |_| None).unwrap();
        assert!(matches!(
            approve(&s, &rv),
            Approved::Answer(SignResponse::SignedTx { .. })
        ));
        let r = req("evm.personal_sign", json!({"message": "0x68"}));
        let rv = review(&r, 1000, 1000, (s.address(), "Main"), |_| None, |_| None).unwrap();
        assert!(matches!(
            approve(&s, &rv),
            Approved::Answer(SignResponse::Signed { .. })
        ));
        let r = req("evm.send", json!({"to": null}));
        assert_eq!(
            review(&r, 1000, 1000, (s.address(), "Main"), |_| None, |_| None).unwrap_err(),
            ReviewError::Reject(RejectReason::NoEndpoint)
        );
    }
}
