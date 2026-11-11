//! Keystore side (§10.4, §10.7): check a request, then sign it after approval.

use alloy_dyn_abi::TypedData;
use alloy_primitives::{B256, U256, eip191_hash_message};
use alloy_signer::SignerSync;
use alloy_signer_local::{MnemonicBuilder, PrivateKeySigner, coins_bip39::English};
use blox_proto::message::{RejectReason, SignRequest, SignResponse};

use crate::tx::UnsignedTx;
use crate::{KIND_PERSONAL_SIGN, KIND_TX, KIND_TYPED_DATA, caip, hex_bytes, to_hex};

/// A request that passed every check and may be shown for approval.
#[derive(Clone, Debug)]
pub enum Prepared {
    Tx(UnsignedTx),
    TypedData(Box<TypedData>),
    PersonalSign(Vec<u8>),
}

impl Prepared {
    fn hash(&self) -> B256 {
        match self {
            Prepared::Tx(tx) => tx.signature_hash(),
            Prepared::TypedData(td) => td.eip712_signing_hash().expect("checked in prepare"),
            Prepared::PersonalSign(m) => eip191_hash_message(m),
        }
    }
}

/// Checks a request for the connection's account (§10.4). On failure, the returned
/// reason goes back to the requester as `rejected`.
pub fn prepare(req: &SignRequest, now: u64) -> Result<Prepared, RejectReason> {
    if req.expires_at < now {
        return Err(RejectReason::Expired);
    }
    let chain = caip::parse_chain(&req.chain).map_err(|_| RejectReason::Unsupported)?;
    let field = |name: &str| req.payload.get(name).ok_or(RejectReason::DecodeFailed);
    let prepared = match req.kind.as_str() {
        KIND_TX => {
            let hex = field("tx")?.as_str().ok_or(RejectReason::DecodeFailed)?;
            let bytes = hex_bytes(hex).map_err(|_| RejectReason::DecodeFailed)?;
            let tx = UnsignedTx::decode(&bytes).map_err(|e| match e {
                crate::Error::Unsupported(_) => RejectReason::Unsupported,
                _ => RejectReason::DecodeFailed,
            })?;
            if tx.chain_id() != chain {
                return Err(RejectReason::DecodeFailed);
            }
            Prepared::Tx(tx)
        }
        KIND_TYPED_DATA => {
            let td: TypedData = serde_json::from_value(field("data")?.clone())
                .map_err(|_| RejectReason::DecodeFailed)?;
            if td.domain.chain_id.is_some_and(|c| c != U256::from(chain)) {
                return Err(RejectReason::DecodeFailed);
            }
            td.eip712_signing_hash()
                .map_err(|_| RejectReason::DecodeFailed)?;
            Prepared::TypedData(Box::new(td))
        }
        KIND_PERSONAL_SIGN => {
            let hex = field("message")?
                .as_str()
                .ok_or(RejectReason::DecodeFailed)?;
            Prepared::PersonalSign(hex_bytes(hex).map_err(|_| RejectReason::DecodeFailed)?)
        }
        _ => return Err(RejectReason::Unsupported),
    };
    Ok(prepared)
}

/// Signs an approved request with `signer` (interim shape until PLAN.md step 4.1).
pub fn sign(signer: &PrivateKeySigner, prepared: Prepared, chain: u64) -> SignResponse {
    let sig = signer
        .sign_hash_sync(&prepared.hash())
        .expect("local signing does not fail");
    let account = caip::account(chain, signer.address());
    match prepared {
        Prepared::Tx(tx) => {
            let raw = tx.encode_signed(sig);
            SignResponse::SignedTx {
                account,
                tx_hash: to_hex(alloy_primitives::keccak256(&raw)),
                raw: to_hex(raw),
            }
        }
        _ => SignResponse::Signed {
            account,
            signature: to_hex(sig.as_bytes()),
        },
    }
}

/// Derives the EVM key at `m/44'/60'/0'/0/{index}` from a BIP-39 mnemonic.
pub fn signer_from_mnemonic(phrase: &str, index: u32) -> crate::Result<PrivateKeySigner> {
    MnemonicBuilder::<English>::default()
        .phrase(phrase)
        .index(index)
        .map_err(crate::Error::malformed)?
        .build()
        .map_err(crate::Error::malformed)
}
