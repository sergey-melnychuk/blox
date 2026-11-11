//! Strict decoding of request payloads (BLOX.md §6.2, §6.3, §10.4 step 1).

use alloy_dyn_abi::TypedData;
use alloy_primitives::{Address, Bytes, U256};
use blox_proto::message::{RejectReason, SignRequest};
use serde_json::{Map, Value};

use crate::caip;

pub const KIND_SEND: &str = "evm.send";
pub const KIND_SIGN_TX: &str = "evm.sign_tx";
pub const KIND_PERSONAL_SIGN: &str = "evm.personal_sign";
pub const KIND_TYPED_DATA: &str = "evm.typed_data";
/// A request may live at most this long after its `ts` (§6.2).
pub const MAX_REQUEST_SECS: u64 = 300;

/// What a transaction request asks for. Everything else is filled on the phone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxIntent {
    /// `None` deploys a contract.
    pub to: Option<Address>,
    pub value: U256,
    pub data: Bytes,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Intent {
    /// Fill, sign and broadcast.
    Send(TxIntent),
    /// Fill and sign; return the signed transaction.
    SignTx(TxIntent),
    PersonalSign(Vec<u8>),
    TypedData(Box<TypedData>),
}

#[derive(Clone, Debug, PartialEq)]
pub struct Decoded {
    pub chain_id: u64,
    pub intent: Intent,
    /// The request's expiry, capped at `ts + 300` (§6.2).
    pub expires_at: u64,
}

/// Decodes and checks a request that arrived with message time `ts`, at time `now`.
pub fn decode(req: &SignRequest, ts: u64, now: u64) -> Result<Decoded, RejectReason> {
    let expires_at = req.expires_at.min(ts + MAX_REQUEST_SECS);
    if expires_at < now {
        return Err(RejectReason::Expired);
    }
    let (chain_id, intent) = decode_intent(req)?;
    Ok(Decoded {
        chain_id,
        intent,
        expires_at,
    })
}

/// Decodes the chain and payload, without the expiry check.
pub fn decode_intent(req: &SignRequest) -> Result<(u64, Intent), RejectReason> {
    let chain_id = caip::parse_chain(&req.chain).map_err(|_| RejectReason::Unsupported)?;
    let payload = req.payload.as_object().ok_or(RejectReason::DecodeFailed)?;
    let intent = match req.kind.as_str() {
        KIND_SEND => Intent::Send(tx_intent(payload)?),
        KIND_SIGN_TX => Intent::SignTx(tx_intent(payload)?),
        KIND_PERSONAL_SIGN => {
            only(payload, &["message"])?;
            let msg = payload.get("message").and_then(Value::as_str);
            Intent::PersonalSign(hex_bytes(msg.ok_or(RejectReason::DecodeFailed)?)?)
        }
        KIND_TYPED_DATA => {
            only(payload, &["data"])?;
            let data = payload.get("data").ok_or(RejectReason::DecodeFailed)?;
            let td: TypedData =
                serde_json::from_value(data.clone()).map_err(|_| RejectReason::DecodeFailed)?;
            if td
                .domain
                .chain_id
                .is_some_and(|c| c != U256::from(chain_id))
            {
                return Err(RejectReason::DecodeFailed);
            }
            td.eip712_signing_hash()
                .map_err(|_| RejectReason::DecodeFailed)?;
            Intent::TypedData(Box::new(td))
        }
        // evm.eip7702_auth, evm.eth_sign and everything else (§6.3).
        _ => return Err(RejectReason::Unsupported),
    };
    Ok((chain_id, intent))
}

/// Refuses any field outside `allowed`, so no requester can believe it set one (§6.3).
fn only(payload: &Map<String, Value>, allowed: &[&str]) -> Result<(), RejectReason> {
    if payload.keys().all(|k| allowed.contains(&k.as_str())) {
        Ok(())
    } else {
        Err(RejectReason::DecodeFailed)
    }
}

fn tx_intent(payload: &Map<String, Value>) -> Result<TxIntent, RejectReason> {
    only(payload, &["to", "value", "data"])?;
    let bad = RejectReason::DecodeFailed;
    let to = match payload.get("to") {
        // `to` must be present: null is an explicit contract creation.
        None => return Err(bad),
        Some(Value::Null) => None,
        Some(Value::String(s)) => Some(s.parse().map_err(|_| bad)?),
        Some(_) => return Err(bad),
    };
    let value = match payload.get("value") {
        None => U256::ZERO,
        Some(Value::String(s)) => quantity(s)?,
        Some(_) => return Err(bad),
    };
    let data = match payload.get("data") {
        None => Bytes::new(),
        Some(Value::String(s)) => hex_bytes(s)?.into(),
        Some(_) => return Err(bad),
    };
    Ok(TxIntent { to, value, data })
}

fn quantity(s: &str) -> Result<U256, RejectReason> {
    let h = s.strip_prefix("0x").ok_or(RejectReason::DecodeFailed)?;
    if h.is_empty() || h.len() > 64 {
        return Err(RejectReason::DecodeFailed);
    }
    U256::from_str_radix(h, 16).map_err(|_| RejectReason::DecodeFailed)
}

fn hex_bytes(s: &str) -> Result<Vec<u8>, RejectReason> {
    crate::hex_bytes(s).map_err(|_| RejectReason::DecodeFailed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn req(kind: &str, payload: Value) -> SignRequest {
        SignRequest {
            chain: "eip155:8453".into(),
            kind: kind.into(),
            payload,
            origin: None,
            expires_at: 1300,
        }
    }

    #[test]
    fn send_and_sign_tx() {
        let p = json!({"to": "0x70997970C51812dc3A010C7d01b50e0d17dc79C8", "value": "0x10", "data": "0xabcd"});
        let d = decode(&req(KIND_SEND, p.clone()), 1000, 1000).unwrap();
        assert_eq!(d.chain_id, 8453);
        let Intent::Send(t) = d.intent else { panic!() };
        assert_eq!(
            (t.value, t.data.to_vec()),
            (U256::from(16), vec![0xab, 0xcd])
        );
        assert!(matches!(
            decode(&req(KIND_SIGN_TX, p), 1000, 1000).unwrap().intent,
            Intent::SignTx(_)
        ));
        let deploy = decode(
            &req(KIND_SEND, json!({"to": null, "data": "0x6080"})),
            1000,
            1000,
        )
        .unwrap();
        let Intent::Send(t) = deploy.intent else {
            panic!()
        };
        assert_eq!((t.to, t.value), (None, U256::ZERO));
    }

    #[test]
    fn refusals() {
        let to = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";
        for (kind, payload, want) in [
            (
                KIND_SEND,
                json!({"to": to, "nonce": "0x1"}),
                RejectReason::DecodeFailed,
            ),
            (
                KIND_SEND,
                json!({"to": to, "gas": "0x5208"}),
                RejectReason::DecodeFailed,
            ),
            (
                KIND_SEND,
                json!({"value": "0x1"}),
                RejectReason::DecodeFailed,
            ),
            (
                KIND_SEND,
                json!({"to": to, "value": "16"}),
                RejectReason::DecodeFailed,
            ),
            (
                KIND_SEND,
                json!({"to": to, "data": "0xabc"}),
                RejectReason::DecodeFailed,
            ),
            (KIND_SEND, json!([]), RejectReason::DecodeFailed),
            (
                KIND_PERSONAL_SIGN,
                json!({"message": "hi"}),
                RejectReason::DecodeFailed,
            ),
            ("evm.eth_sign", json!({}), RejectReason::Unsupported),
            ("evm.eip7702_auth", json!({}), RejectReason::Unsupported),
            ("solana.tx", json!({}), RejectReason::Unsupported),
        ] {
            assert_eq!(
                decode(&req(kind, payload), 1000, 1000).unwrap_err(),
                want,
                "{kind}"
            );
        }
        let mut other_chain = req(KIND_PERSONAL_SIGN, json!({"message": "0x01"}));
        other_chain.chain = "solana:abc".into();
        assert_eq!(
            decode(&other_chain, 1000, 1000).unwrap_err(),
            RejectReason::Unsupported
        );
    }

    #[test]
    fn expiry_is_capped_at_300_seconds() {
        let mut r = req(KIND_PERSONAL_SIGN, json!({"message": "0x01"}));
        r.expires_at = 99_999;
        assert_eq!(decode(&r, 1000, 1000).unwrap().expires_at, 1300);
        assert_eq!(decode(&r, 1000, 1301).unwrap_err(), RejectReason::Expired);
    }

    #[test]
    fn typed_data_chain_must_match() {
        let td = |chain: u64| {
            json!({"data": {
                "types": {"EIP712Domain":[{"name":"chainId","type":"uint256"}],"M":[{"name":"x","type":"uint256"}]},
                "primaryType": "M", "domain": {"chainId": chain}, "message": {"x": "1"}
            }})
        };
        decode(&req(KIND_TYPED_DATA, td(8453)), 1000, 1000).unwrap();
        assert_eq!(
            decode(&req(KIND_TYPED_DATA, td(1)), 1000, 1000).unwrap_err(),
            RejectReason::DecodeFailed
        );
    }
}
