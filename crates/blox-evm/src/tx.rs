//! Unsigned transactions as carried in `evm.tx` payloads: the exact bytes that
//! are hashed for signing (legacy EIP-155 preimage, or `type ‖ rlp(fields)`).

use alloy_consensus::{
    SignableTransaction, Signed, TxEip1559, TxEip2930, TxEnvelope, TxLegacy,
    transaction::RlpEcdsaDecodableTx,
};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{B256, Signature};
use alloy_rlp::Decodable;

use crate::{Error, Result};

#[derive(Clone, Debug, PartialEq)]
pub enum UnsignedTx {
    Legacy(TxLegacy),
    Eip2930(TxEip2930),
    Eip1559(TxEip1559),
}

impl UnsignedTx {
    /// Decodes signing-preimage bytes. Only canonical encodings are accepted:
    /// re-encoding must reproduce the input exactly, so what is displayed is
    /// exactly what gets signed.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let first = *bytes
            .first()
            .ok_or_else(|| Error::Malformed("empty tx".into()))?;
        let tx = match first {
            0x01 => UnsignedTx::Eip2930(
                TxEip2930::rlp_decode(&mut &bytes[1..]).map_err(Error::malformed)?,
            ),
            0x02 => UnsignedTx::Eip1559(
                TxEip1559::rlp_decode(&mut &bytes[1..]).map_err(Error::malformed)?,
            ),
            0x03 => return Err(Error::Unsupported("blob transactions (type 3)".into())),
            0x04 => return Err(Error::Unsupported("EIP-7702 transactions (type 4)".into())),
            0xc0.. => {
                let tx = TxLegacy::decode(&mut &bytes[..]).map_err(Error::malformed)?;
                if tx.chain_id.is_none() {
                    return Err(Error::Unsupported(
                        "legacy transaction without EIP-155 chain id".into(),
                    ));
                }
                UnsignedTx::Legacy(tx)
            }
            t => return Err(Error::Unsupported(format!("transaction type {t:#x}"))),
        };
        if tx.encode_for_signing() != bytes {
            return Err(Error::Malformed(
                "non-canonical transaction encoding".into(),
            ));
        }
        Ok(tx)
    }

    pub fn encode_for_signing(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            UnsignedTx::Legacy(t) => t.encode_for_signing(&mut out),
            UnsignedTx::Eip2930(t) => t.encode_for_signing(&mut out),
            UnsignedTx::Eip1559(t) => t.encode_for_signing(&mut out),
        }
        out
    }

    pub fn signature_hash(&self) -> B256 {
        match self {
            UnsignedTx::Legacy(t) => t.signature_hash(),
            UnsignedTx::Eip2930(t) => t.signature_hash(),
            UnsignedTx::Eip1559(t) => t.signature_hash(),
        }
    }

    pub fn chain_id(&self) -> u64 {
        match self {
            UnsignedTx::Legacy(t) => t.chain_id.expect("checked at decode"),
            UnsignedTx::Eip2930(t) => t.chain_id,
            UnsignedTx::Eip1559(t) => t.chain_id,
        }
    }

    pub fn nonce(&self) -> u64 {
        match self {
            UnsignedTx::Legacy(t) => t.nonce,
            UnsignedTx::Eip2930(t) => t.nonce,
            UnsignedTx::Eip1559(t) => t.nonce,
        }
    }

    pub fn into_envelope(self, sig: Signature) -> TxEnvelope {
        match self {
            UnsignedTx::Legacy(t) => Signed::new_unhashed(t, sig).into(),
            UnsignedTx::Eip2930(t) => Signed::new_unhashed(t, sig).into(),
            UnsignedTx::Eip1559(t) => Signed::new_unhashed(t, sig).into(),
        }
    }

    /// Signed network encoding (what `eth_sendRawTransaction` takes).
    pub fn encode_signed(self, sig: Signature) -> Vec<u8> {
        self.into_envelope(sig).encoded_2718()
    }

    /// The unsigned part of a signed envelope, for re-encoding comparisons.
    pub fn from_envelope(env: &TxEnvelope) -> Result<Self> {
        match env {
            TxEnvelope::Legacy(s) => Ok(UnsignedTx::Legacy(s.tx().clone())),
            TxEnvelope::Eip2930(s) => Ok(UnsignedTx::Eip2930(s.tx().clone())),
            TxEnvelope::Eip1559(s) => Ok(UnsignedTx::Eip1559(s.tx().clone())),
            _ => Err(Error::Unsupported("signed transaction type".into())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{TxKind, U256, address};

    pub(crate) fn sample_1559() -> UnsignedTx {
        UnsignedTx::Eip1559(TxEip1559 {
            chain_id: 31337,
            nonce: 7,
            gas_limit: 21000,
            max_fee_per_gas: 2_000_000_001,
            max_priority_fee_per_gas: 1,
            to: TxKind::Call(address!("0x70997970C51812dc3A010C7d01b50e0d17dc79C8")),
            value: U256::from(1),
            ..Default::default()
        })
    }

    #[test]
    fn roundtrip_all_types() {
        let legacy = UnsignedTx::Legacy(TxLegacy {
            chain_id: Some(1),
            nonce: 1,
            gas_price: 10,
            gas_limit: 21000,
            ..Default::default()
        });
        let t2930 = UnsignedTx::Eip2930(TxEip2930 {
            chain_id: 1,
            nonce: 2,
            gas_price: 10,
            gas_limit: 21000,
            ..Default::default()
        });
        for tx in [legacy, t2930, sample_1559()] {
            let bytes = tx.encode_for_signing();
            assert_eq!(UnsignedTx::decode(&bytes).unwrap(), tx);
        }
    }

    #[test]
    fn refuses_other_types_and_junk() {
        assert!(matches!(
            UnsignedTx::decode(&[0x03, 0xc0]),
            Err(Error::Unsupported(_))
        ));
        assert!(matches!(
            UnsignedTx::decode(&[0x04, 0xc0]),
            Err(Error::Unsupported(_))
        ));
        let legacy_no_chain = UnsignedTx::Legacy(TxLegacy {
            gas_limit: 1,
            ..Default::default()
        })
        .encode_for_signing();
        assert!(matches!(
            UnsignedTx::decode(&legacy_no_chain),
            Err(Error::Unsupported(_))
        ));
        let mut trailing = sample_1559().encode_for_signing();
        trailing.push(0);
        assert!(UnsignedTx::decode(&trailing).is_err());
    }
}
