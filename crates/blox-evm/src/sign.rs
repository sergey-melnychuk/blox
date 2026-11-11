//! Signing what the user approved (BLOX.md §10.8).

use alloy_dyn_abi::TypedData;
use alloy_primitives::{B256, eip191_hash_message, keccak256};
use alloy_signer::SignerSync;
use alloy_signer_local::{MnemonicBuilder, PrivateKeySigner, coins_bip39::English};

use crate::to_hex;
use crate::tx::UnsignedTx;

/// A request that passed every check and was filled; exactly what is shown and signed.
#[derive(Clone, Debug, PartialEq)]
pub enum Prepared {
    /// `broadcast` is true for `evm.send`, false for `evm.sign_tx`.
    Tx {
        tx: UnsignedTx,
        broadcast: bool,
    },
    TypedData(Box<TypedData>),
    PersonalSign(Vec<u8>),
}

impl Prepared {
    pub fn hash(&self) -> B256 {
        match self {
            Prepared::Tx { tx, .. } => tx.signature_hash(),
            Prepared::TypedData(td) => td.eip712_signing_hash().expect("checked when decoded"),
            Prepared::PersonalSign(m) => eip191_hash_message(m),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Signed {
    /// A signed transaction (EIP-2718 encoding) and its hash.
    Tx {
        raw: Vec<u8>,
        hash: B256,
        nonce: u64,
        broadcast: bool,
    },
    /// `0x` + r‖s‖v, v = 27 or 28.
    Message(String),
}

/// Signs with RFC 6979 deterministic, low-s ECDSA.
pub fn sign(signer: &PrivateKeySigner, prepared: &Prepared) -> Signed {
    let sig = signer
        .sign_hash_sync(&prepared.hash())
        .expect("local signing does not fail");
    match prepared {
        Prepared::Tx { tx, broadcast } => {
            let raw = tx.clone().encode_signed(sig);
            Signed::Tx {
                hash: keccak256(&raw),
                raw,
                nonce: tx.nonce(),
                broadcast: *broadcast,
            }
        }
        _ => Signed::Message(to_hex(sig.as_bytes())),
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

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::address;

    #[test]
    fn anvil_account_zero() {
        let s = signer_from_mnemonic(
            "test test test test test test test test test test test junk",
            0,
        )
        .unwrap();
        assert_eq!(
            s.address(),
            address!("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266")
        );
    }
}
