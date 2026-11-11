//! Plaintext messages (BLOX.md §4.6) and their bodies (§5, §6).

use serde::{Deserialize, Serialize};

use crate::{Result, b64};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MsgId(#[serde(with = "b64::array")] pub [u8; 16]);

impl MsgId {
    pub fn generate() -> Self {
        let mut b = [0u8; 16];
        getrandom::fill(&mut b).expect("OS RNG");
        Self(b)
    }
}

impl std::fmt::Display for MsgId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&b64::encode(self.0))
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Message {
    pub id: MsgId,
    pub ts: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub re: Option<MsgId>,
    #[serde(flatten)]
    pub body: Body,
}

impl Message {
    /// A new message stamped with `ts` (relay time, §4.8).
    pub fn at(body: Body, ts: u64) -> Self {
        Self {
            id: MsgId::generate(),
            ts,
            re: None,
            body,
        }
    }

    /// A new message answering `to`, stamped with `ts`.
    pub fn reply_at(to: MsgId, body: Body, ts: u64) -> Self {
        Self {
            re: Some(to),
            ..Self::at(body, ts)
        }
    }

    pub fn to_json(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("message serializes")
    }

    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        Ok(serde_json::from_slice(bytes)?)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", content = "body", rename_all = "snake_case")]
pub enum Body {
    Bind(Bind),
    Bound(Bound),
    SignRequest(SignRequest),
    SignResponse(SignResponse),
    /// Withdraws the request named by `re` (§6.5).
    Cancel(Empty),
    /// Ends the connection (§5.5).
    Unbind(Empty),
}

/// An empty body, serialized as `{}`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Empty {}

/// Keystore → requester, sealed with the PSK (§5.2).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bind {
    /// The token signed by the keystore (`Blox-Token` encoding).
    pub token: String,
    /// Checksummed EVM address.
    pub account: String,
    pub statement: String,
    /// EIP-191 signature by the account over the statement, `0x` + 65 bytes.
    pub signature: String,
}

/// Requester → keystore: the countersigned token (§5.3).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bound {
    pub token: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SignRequest {
    /// CAIP-2, e.g. `eip155:8453`.
    pub chain: String,
    /// Namespaced payload kind, e.g. `evm.send`.
    pub kind: String,
    /// Kind-specific payload; decoded strictly by the chain crate (§6.3).
    pub payload: serde_json::Value,
    /// Informational and untrusted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<Origin>,
    pub expires_at: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Origin {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum SignResponse {
    /// The endpoint accepted the transaction.
    Sent {
        account: String,
        tx_hash: String,
    },
    /// `evm.sign_tx`: filled and signed, not broadcast.
    SignedTx {
        account: String,
        tx_hash: String,
        raw: String,
    },
    /// A message signature.
    Signed {
        account: String,
        signature: String,
    },
    /// Signed, but the endpoint refused it or did not answer.
    Failed {
        account: String,
        tx_hash: String,
        error: String,
    },
    Rejected {
        reason: RejectReason,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RejectReason {
    User,
    Expired,
    Unsupported,
    DecodeFailed,
    NoEndpoint,
    WouldFail,
}

/// The local wall clock. Prefer relay time where the protocol needs agreement (§4.8).
pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock after 1970")
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn wire_shape_matches_spec() {
        let m = Message {
            id: MsgId([0; 16]),
            ts: 1760000000,
            re: Some(MsgId([1; 16])),
            body: Body::Cancel(Empty {}),
        };
        let v: serde_json::Value = serde_json::from_slice(&m.to_json()).unwrap();
        assert_eq!(
            v,
            json!({"id":"AAAAAAAAAAAAAAAAAAAAAA","ts":1760000000,"re":"AQEBAQEBAQEBAQEBAQEBAQ","type":"cancel","body":{}})
        );
        for (resp, want) in [
            (
                SignResponse::Rejected {
                    reason: RejectReason::WouldFail,
                },
                json!({"status":"rejected","reason":"would_fail"}),
            ),
            (
                SignResponse::SignedTx {
                    account: "a".into(),
                    tx_hash: "h".into(),
                    raw: "r".into(),
                },
                json!({"status":"signed_tx","account":"a","tx_hash":"h","raw":"r"}),
            ),
        ] {
            let v = serde_json::to_value(Body::SignResponse(resp)).unwrap();
            assert_eq!(v, json!({"type": "sign_response", "body": want}));
        }
    }

    #[test]
    fn roundtrip_request() {
        let req = Message::at(
            Body::SignRequest(SignRequest {
                chain: "eip155:1".into(),
                kind: "evm.send".into(),
                payload: json!({"to": null, "value": "0x0", "data": "0x"}),
                origin: Some(Origin {
                    name: Some("Example".into()),
                    url: None,
                }),
                expires_at: 1,
            }),
            5,
        );
        assert_eq!(Message::from_json(&req.to_json()).unwrap(), req);
        let reply = Message::reply_at(req.id, Body::Unbind(Empty {}), 6);
        assert_eq!((reply.re, reply.ts), (Some(req.id), 6));
    }
}
