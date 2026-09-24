//! Plaintext messages (§4.4) and signing bodies (§6).

use serde::{Deserialize, Serialize};

use crate::mailbox::MailboxId;
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
    pub fn new(body: Body) -> Self {
        Self {
            id: MsgId::generate(),
            ts: now(),
            re: None,
            body,
        }
    }

    pub fn reply(to: &Message, body: Body) -> Self {
        Self {
            re: Some(to.id),
            ..Self::new(body)
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
    Hello(Hello),
    SignRequest(SignRequest),
    SignResponse(SignResponse),
    Close(Close),
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Hello {
    pub mk: MailboxId,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SignRequest {
    /// CAIP-2, e.g. `eip155:8453`.
    pub chain: String,
    /// CAIP-10, e.g. `eip155:8453:0xAbC…`.
    pub account: String,
    /// Namespaced payload kind, e.g. `evm.tx`.
    pub kind: String,
    /// Kind-specific payload; decoded by the chain crate, never trusted as-is.
    pub payload: serde_json::Value,
    /// Informational and untrusted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<Origin>,
    pub expires_at: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Origin {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum SignResponse {
    Approved {
        signature: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        signed_tx: Option<String>,
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
    AccountUnknown,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Close {
    pub reason: CloseReason,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CloseReason {
    Done,
    Contested,
    Timeout,
    Shutdown,
}

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
            re: None,
            body: Body::Close(Close {
                reason: CloseReason::Contested,
            }),
        };
        let v: serde_json::Value = serde_json::from_slice(&m.to_json()).unwrap();
        assert_eq!(
            v,
            json!({"id":"AAAAAAAAAAAAAAAAAAAAAA","ts":1760000000,"type":"close","body":{"reason":"contested"}})
        );

        let r = Body::SignResponse(SignResponse::Rejected {
            reason: RejectReason::DecodeFailed,
        });
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(
            v,
            json!({"type":"sign_response","body":{"status":"rejected","reason":"decode_failed"}})
        );
    }

    #[test]
    fn roundtrip_sign_request() {
        let req = Message::new(Body::SignRequest(SignRequest {
            chain: "eip155:1".into(),
            account: "eip155:1:0x0000000000000000000000000000000000000001".into(),
            kind: "evm.tx".into(),
            payload: json!({"tx": "0x02"}),
            origin: Some(Origin {
                client: Some("cast".into()),
                note: None,
            }),
            expires_at: 1,
        }));
        let back = Message::from_json(&req.to_json()).unwrap();
        assert_eq!(back, req);
        let reply = Message::reply(
            &req,
            Body::SignResponse(SignResponse::Rejected {
                reason: RejectReason::User,
            }),
        );
        assert_eq!(reply.re, Some(req.id));
    }
}
