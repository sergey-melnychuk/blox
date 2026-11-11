//! Requester side (BLOX.md §9.5): never trust a keystore response without checking it.

use alloy_consensus::transaction::SignerRecoverable;
use alloy_consensus::{Transaction as _, TxEnvelope};
use alloy_eips::eip2718::Decodable2718;
use alloy_primitives::{Address, B256, Signature, eip191_hash_message, keccak256};
use blox_proto::message::{SignRequest, SignResponse};

use crate::intent::{self, Intent};
use crate::{Error, Result, caip, hex_bytes};

/// Checks `resp` against the request that produced it and the connection's account.
pub fn check(req: &SignRequest, resp: &SignResponse, account: Address) -> Result<()> {
    let (chain_id, intent) = intent::decode_intent(req)
        .map_err(|_| Error::Verification("request is not well formed"))?;
    let expected = caip::account(chain_id, account);
    let same_account = |a: &str| {
        if a == expected {
            Ok(())
        } else {
            Err(Error::Verification("response names another account"))
        }
    };
    match (resp, &intent) {
        (SignResponse::Rejected { .. }, _) => Ok(()),
        (
            SignResponse::Sent {
                account: a,
                tx_hash,
            },
            Intent::Send(_),
        )
        | (
            SignResponse::Failed {
                account: a,
                tx_hash,
                ..
            },
            Intent::Send(_),
        ) => {
            same_account(a)?;
            parse_hash(tx_hash).map(|_| ())
        }
        (
            SignResponse::SignedTx {
                account: a,
                tx_hash,
                raw,
            },
            Intent::SignTx(want),
        ) => {
            same_account(a)?;
            let raw = hex_bytes(raw)?;
            let env = TxEnvelope::decode_2718(&mut raw.as_slice())
                .map_err(|_| Error::Verification("undecodable transaction"))?;
            if !matches!(env, TxEnvelope::Legacy(_) | TxEnvelope::Eip1559(_)) {
                return Err(Error::Verification("transaction type"));
            }
            if env.chain_id() != Some(chain_id) {
                return Err(Error::Verification("chain id differs"));
            }
            if env.to() != want.to || env.value() != want.value || *env.input() != want.data {
                return Err(Error::Verification("transaction differs from the request"));
            }
            if env
                .recover_signer()
                .map_err(|_| Error::Verification("bad signature"))?
                != account
            {
                return Err(Error::Verification("signed by a different account"));
            }
            if keccak256(&raw) != parse_hash(tx_hash)? {
                return Err(Error::Verification("tx_hash differs"));
            }
            Ok(())
        }
        (
            SignResponse::Signed {
                account: a,
                signature,
            },
            Intent::PersonalSign(_) | Intent::TypedData(_),
        ) => {
            same_account(a)?;
            let hash = match &intent {
                Intent::PersonalSign(m) => eip191_hash_message(m),
                Intent::TypedData(td) => td.eip712_signing_hash().map_err(Error::malformed)?,
                _ => unreachable!(),
            };
            let sig = Signature::try_from(hex_bytes(signature)?.as_slice())
                .map_err(|_| Error::Verification("bad signature"))?;
            let signer = sig
                .recover_address_from_prehash(&hash)
                .map_err(|_| Error::Verification("bad signature"))?;
            if signer != account {
                return Err(Error::Verification("signed by a different account"));
            }
            Ok(())
        }
        _ => Err(Error::Verification(
            "response does not fit the request kind",
        )),
    }
}

fn parse_hash(s: &str) -> Result<B256> {
    let b = hex_bytes(s)?;
    if b.len() != 32 {
        return Err(Error::Verification("tx_hash"));
    }
    Ok(B256::from_slice(&b))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fill::tests::london;
    use crate::keystore::{Approved, Endpoint, approve, review};
    use crate::sign::signer_from_mnemonic;
    use blox_proto::message::RejectReason;
    use serde_json::json;
    use std::sync::LazyLock;

    static RPC: LazyLock<crate::fill::tests::Fake> = LazyLock::new(london);
    const PHRASE: &str = "test test test test test test test test test test test junk";

    fn req(kind: &str, payload: serde_json::Value) -> SignRequest {
        SignRequest {
            chain: "eip155:8453".into(),
            kind: kind.into(),
            payload,
            origin: None,
            expires_at: 1300,
        }
    }

    fn answer(s: &alloy_signer_local::PrivateKeySigner, r: &SignRequest) -> SignResponse {
        let ep = |_| {
            Some(Endpoint {
                rpc: &*RPC,
                host: "h",
            })
        };
        let rv = review(r, 1000, 1000, (s.address(), "Main"), ep, |_| None).unwrap();
        match approve(s, &rv) {
            Approved::Answer(a) => a,
            Approved::Broadcast { .. } => panic!(),
        }
    }

    #[test]
    fn genuine_answers_pass() {
        let s = signer_from_mnemonic(PHRASE, 0).unwrap();
        let td = json!({"data": {
            "types": {"EIP712Domain":[{"name":"name","type":"string"}],"Mail":[{"name":"contents","type":"string"}]},
            "primaryType": "Mail", "domain": {"name": "Blox"}, "message": {"contents": "hello"}}});
        for r in [
            req(
                "evm.sign_tx",
                json!({"to": "0x70997970C51812dc3A010C7d01b50e0d17dc79C8", "value": "0x5"}),
            ),
            req("evm.personal_sign", json!({"message": "0x68656c6c6f"})),
            req("evm.typed_data", td),
        ] {
            check(&r, &answer(&s, &r), s.address()).unwrap_or_else(|e| panic!("{}: {e}", r.kind));
        }
        let rej = SignResponse::Rejected {
            reason: RejectReason::User,
        };
        check(&req("evm.send", json!({"to": null})), &rej, s.address()).unwrap();
    }

    #[test]
    fn substitutions_are_caught() {
        let s = signer_from_mnemonic(PHRASE, 0).unwrap();
        let other = signer_from_mnemonic(PHRASE, 1).unwrap();
        let r = req(
            "evm.sign_tx",
            json!({"to": "0x70997970C51812dc3A010C7d01b50e0d17dc79C8", "value": "0x5"}),
        );
        // Signed by another key.
        assert!(check(&r, &answer(&other, &r), s.address()).is_err());
        // A different transaction, correctly signed.
        let r2 = req(
            "evm.sign_tx",
            json!({"to": "0x70997970C51812dc3A010C7d01b50e0d17dc79C8", "value": "0x6"}),
        );
        assert!(check(&r, &answer(&s, &r2), s.address()).is_err());
        // A message signature for a different message.
        let m1 = req("evm.personal_sign", json!({"message": "0x01"}));
        let m2 = req("evm.personal_sign", json!({"message": "0x02"}));
        assert!(check(&m1, &answer(&s, &m2), s.address()).is_err());
        // A response that doesn't fit the kind.
        assert!(check(&m1, &answer(&s, &r), s.address()).is_err());
        let sent = SignResponse::Sent {
            account: caip::account(8453, s.address()),
            tx_hash: "0x12".into(),
        };
        assert!(check(&req("evm.send", json!({"to": null})), &sent, s.address()).is_err());
    }
}
