//! Adapter side (§9.5): never trust a keystore response without checking it.

use alloy_consensus::TxEnvelope;
use alloy_consensus::transaction::SignerRecoverable;
use alloy_dyn_abi::TypedData;
use alloy_eips::eip2718::Decodable2718;
use alloy_primitives::{B256, Signature, eip191_hash_message};
use blox_proto::message::{SignRequest, SignResponse};

use crate::tx::UnsignedTx;
use crate::{Error, KIND_PERSONAL_SIGN, KIND_TX, KIND_TYPED_DATA, Result, caip, hex_bytes};

#[derive(Clone, Debug, PartialEq)]
pub enum Verified {
    /// A signed transaction, ready for `eth_sendRawTransaction`.
    Tx { raw: Vec<u8>, hash: B256 },
    /// A 65-byte `r‖s‖v` signature (hex) over the requested message.
    Signature(String),
}

/// Checks an approved response against the request that produced it.
pub fn verify(req: &SignRequest, resp: &SignResponse) -> Result<Verified> {
    let SignResponse::Approved {
        signature,
        signed_tx,
    } = resp
    else {
        return Err(Error::Verification("response is not an approval"));
    };
    let (chain, account) = caip::parse_account(&req.account)?;
    let field = |name: &str| {
        req.payload
            .get(name)
            .ok_or_else(|| Error::Malformed(format!("request payload lacks {name}")))
    };
    match req.kind.as_str() {
        KIND_TX => {
            let requested = hex_bytes(field("tx")?.as_str().unwrap_or_default())?;
            let raw = hex_bytes(
                signed_tx
                    .as_deref()
                    .ok_or(Error::Verification("no signed_tx"))?,
            )?;
            let env = TxEnvelope::decode_2718(&mut raw.as_slice())
                .map_err(|_| Error::Verification("undecodable"))?;
            let unsigned = UnsignedTx::from_envelope(&env)?;
            if unsigned.encode_for_signing() != requested {
                return Err(Error::Verification(
                    "signed transaction differs from the request",
                ));
            }
            if unsigned.chain_id() != chain {
                return Err(Error::Verification("chain id differs"));
            }
            if env
                .recover_signer()
                .map_err(|_| Error::Verification("bad signature"))?
                != account
            {
                return Err(Error::Verification("signed by a different account"));
            }
            Ok(Verified::Tx {
                hash: *env.tx_hash(),
                raw,
            })
        }
        KIND_TYPED_DATA | KIND_PERSONAL_SIGN => {
            let hash = if req.kind == KIND_TYPED_DATA {
                let td: TypedData =
                    serde_json::from_value(field("data")?.clone()).map_err(Error::malformed)?;
                td.eip712_signing_hash().map_err(Error::malformed)?
            } else {
                eip191_hash_message(hex_bytes(field("message")?.as_str().unwrap_or_default())?)
            };
            let sig = Signature::try_from(hex_bytes(signature)?.as_slice())
                .map_err(|_| Error::Verification("bad signature"))?;
            let signer = sig
                .recover_address_from_prehash(&hash)
                .map_err(|_| Error::Verification("bad signature"))?;
            if signer != account {
                return Err(Error::Verification("signed by a different account"));
            }
            Ok(Verified::Signature(signature.clone()))
        }
        _ => Err(Error::Unsupported(req.kind.clone())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sign::{prepare, sign, signer_from_mnemonic};
    use crate::to_hex;
    use alloy_primitives::{TxKind, U256, address};
    use blox_proto::message::{RejectReason, now};
    use serde_json::json;

    const MNEMONIC: &str = "test test test test test test test test test test test junk";

    fn request(
        kind: &str,
        payload: serde_json::Value,
        chain: u64,
        account: alloy_primitives::Address,
    ) -> SignRequest {
        SignRequest {
            chain: caip::chain(chain),
            account: caip::account(chain, account),
            kind: kind.into(),
            payload,
            origin: None,
            expires_at: now() + 300,
        }
    }

    fn tx() -> UnsignedTx {
        UnsignedTx::Eip1559(alloy_consensus::TxEip1559 {
            chain_id: 31337,
            nonce: 0,
            gas_limit: 21000,
            max_fee_per_gas: 2_000_000_001,
            max_priority_fee_per_gas: 1,
            to: TxKind::Call(address!("0x70997970C51812dc3A010C7d01b50e0d17dc79C8")),
            value: U256::from(1),
            ..Default::default()
        })
    }

    #[test]
    fn anvil_account_zero() {
        let s = signer_from_mnemonic(MNEMONIC, 0).unwrap();
        assert_eq!(
            s.address(),
            address!("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266")
        );
    }

    #[test]
    fn sign_then_verify_every_kind() {
        let s = signer_from_mnemonic(MNEMONIC, 0).unwrap();
        let typed = json!({
            "types": {"EIP712Domain":[{"name":"name","type":"string"},{"name":"chainId","type":"uint256"}],
                      "Mail":[{"name":"contents","type":"string"}]},
            "primaryType": "Mail",
            "domain": {"name":"Blox","chainId":31337},
            "message": {"contents":"hello"}
        });
        let reqs = [
            request(
                KIND_TX,
                json!({"tx": to_hex(tx().encode_for_signing())}),
                31337,
                s.address(),
            ),
            request(KIND_TYPED_DATA, json!({"data": typed}), 31337, s.address()),
            request(
                KIND_PERSONAL_SIGN,
                json!({"message": "0x68656c6c6f"}),
                31337,
                s.address(),
            ),
        ];
        for req in reqs {
            let (_, prepared) = prepare(&req, &[s.address()], now()).unwrap();
            let resp = sign(&s, prepared);
            verify(&req, &resp).unwrap_or_else(|e| panic!("{}: {e}", req.kind));
        }
    }

    #[test]
    fn verify_catches_substitution() {
        let s = signer_from_mnemonic(MNEMONIC, 0).unwrap();
        let other = signer_from_mnemonic(MNEMONIC, 1).unwrap();
        let req = request(
            KIND_TX,
            json!({"tx": to_hex(tx().encode_for_signing())}),
            31337,
            s.address(),
        );

        // A different transaction, correctly signed by the right key.
        let UnsignedTx::Eip1559(mut modified) = tx() else {
            unreachable!()
        };
        modified.value = U256::from(2);
        let swapped = sign(&s, crate::sign::Prepared::Tx(UnsignedTx::Eip1559(modified)));
        assert!(verify(&req, &swapped).is_err());

        // The right transaction, signed by a different key.
        let wrong_key = sign(&other, crate::sign::Prepared::Tx(tx()));
        assert!(verify(&req, &wrong_key).is_err());

        let rejected = SignResponse::Rejected {
            reason: RejectReason::User,
        };
        assert!(verify(&req, &rejected).is_err());
    }

    #[test]
    fn prepare_rejections() {
        let s = signer_from_mnemonic(MNEMONIC, 0).unwrap();
        let good = request(
            KIND_TX,
            json!({"tx": to_hex(tx().encode_for_signing())}),
            31337,
            s.address(),
        );
        let accounts = [s.address()];

        let expired = SignRequest {
            expires_at: 1,
            ..good.clone()
        };
        assert_eq!(
            prepare(&expired, &accounts, now()).unwrap_err(),
            RejectReason::Expired
        );
        assert_eq!(
            prepare(&good, &[], now()).unwrap_err(),
            RejectReason::AccountUnknown
        );
        let wrong_chain = request(KIND_TX, good.payload.clone(), 1, s.address());
        assert_eq!(
            prepare(&wrong_chain, &accounts, now()).unwrap_err(),
            RejectReason::DecodeFailed
        );
        let blob = request(KIND_TX, json!({"tx": "0x03c0"}), 31337, s.address());
        assert_eq!(
            prepare(&blob, &accounts, now()).unwrap_err(),
            RejectReason::Unsupported
        );
        let eth_sign = request("evm.eth_sign", json!({}), 31337, s.address());
        assert_eq!(
            prepare(&eth_sign, &accounts, now()).unwrap_err(),
            RejectReason::Unsupported
        );
    }
}
