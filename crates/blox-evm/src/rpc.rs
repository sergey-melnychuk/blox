//! `eth_sendTransaction`-style request objects (§9.4).

use alloy_consensus::{TxEip1559, TxEip2930, TxLegacy};
use alloy_eips::eip2930::AccessList;
use alloy_primitives::{Address, Bytes, TxKind, U256};
use serde_json::Value;

use crate::tx::UnsignedTx;
use crate::{Error, Result, hex_bytes};

/// A transaction request as sent by tools. Every field the caller supplies is
/// used unchanged; the adapter fills only what is missing.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct TxRequest {
    pub from: Address,
    pub to: Option<Address>,
    pub gas: Option<u64>,
    pub gas_price: Option<u128>,
    pub max_fee_per_gas: Option<u128>,
    pub max_priority_fee_per_gas: Option<u128>,
    pub value: U256,
    pub input: Bytes,
    pub nonce: Option<u64>,
    pub chain_id: Option<u64>,
    pub tx_type: Option<u8>,
    pub access_list: Option<AccessList>,
}

/// Which envelope a request resolves to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxType {
    Legacy,
    Eip2930,
    Eip1559,
}

/// Values the adapter fetched from upstream for fields the caller left out.
#[derive(Clone, Copy, Debug, Default)]
pub struct Fill {
    pub chain_id: u64,
    pub nonce: u64,
    pub gas: u64,
    pub gas_price: u128,
    pub max_fee_per_gas: u128,
    pub max_priority_fee_per_gas: u128,
}

fn quantity<T: TryFrom<U256>>(v: &Value, field: &str) -> Result<Option<T>> {
    match v.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => {
            let n: U256 = s
                .parse()
                .map_err(|_| Error::Malformed(format!("{field}: bad quantity")))?;
            T::try_from(n)
                .map(Some)
                .map_err(|_| Error::Malformed(format!("{field}: out of range")))
        }
        Some(_) => Err(Error::Malformed(format!("{field}: expected hex string"))),
    }
}

impl TxRequest {
    pub fn parse(v: &Value) -> Result<Self> {
        let str_field = |f: &str| v.get(f).and_then(Value::as_str);
        let from = str_field("from")
            .ok_or_else(|| Error::Malformed("from is required".into()))?
            .parse()
            .map_err(Error::malformed)?;
        let to = match v.get("to") {
            None | Some(Value::Null) => None,
            Some(Value::String(s)) => Some(s.parse().map_err(Error::malformed)?),
            Some(_) => return Err(Error::Malformed("to".into())),
        };
        let input = match (str_field("input"), str_field("data")) {
            (Some(a), Some(b)) if hex_bytes(a)? != hex_bytes(b)? => {
                return Err(Error::Malformed("input and data differ".into()));
            }
            (Some(x), _) | (None, Some(x)) => hex_bytes(x)?.into(),
            (None, None) => Bytes::new(),
        };
        let access_list = match v.get("accessList") {
            None | Some(Value::Null) => None,
            Some(a) => Some(serde_json::from_value(a.clone()).map_err(Error::malformed)?),
        };
        Ok(Self {
            from,
            to,
            gas: quantity(v, "gas")?,
            gas_price: quantity(v, "gasPrice")?,
            max_fee_per_gas: quantity(v, "maxFeePerGas")?,
            max_priority_fee_per_gas: quantity(v, "maxPriorityFeePerGas")?,
            value: quantity(v, "value")?.unwrap_or_default(),
            input,
            nonce: quantity(v, "nonce")?,
            chain_id: quantity(v, "chainId")?,
            tx_type: quantity(v, "type")?,
            access_list,
        })
    }

    pub fn tx_type(&self) -> Result<TxType> {
        match self.tx_type {
            Some(0) => Ok(TxType::Legacy),
            Some(1) => Ok(TxType::Eip2930),
            Some(2) => Ok(TxType::Eip1559),
            Some(t) => Err(Error::Unsupported(format!("transaction type {t}"))),
            None if self.max_fee_per_gas.is_some() || self.max_priority_fee_per_gas.is_some() => {
                Ok(TxType::Eip1559)
            }
            None if self.gas_price.is_some() && self.access_list.is_some() => Ok(TxType::Eip2930),
            None if self.gas_price.is_some() => Ok(TxType::Legacy),
            None => Ok(TxType::Eip1559),
        }
    }

    /// Builds the unsigned transaction. `chain_id` is the upstream chain; a
    /// caller-supplied `chainId` must match it.
    pub fn build(&self, fill: Fill) -> Result<UnsignedTx> {
        if self.chain_id.is_some_and(|c| c != fill.chain_id) {
            return Err(Error::ChainMismatch);
        }
        let chain_id = fill.chain_id;
        let nonce = self.nonce.unwrap_or(fill.nonce);
        let gas_limit = self.gas.unwrap_or(fill.gas);
        let to = self.to.map_or(TxKind::Create, TxKind::Call);
        let input = self.input.clone();
        let access_list = self.access_list.clone().unwrap_or_default();
        Ok(match self.tx_type()? {
            TxType::Legacy => UnsignedTx::Legacy(TxLegacy {
                chain_id: Some(chain_id),
                nonce,
                gas_price: self.gas_price.unwrap_or(fill.gas_price),
                gas_limit,
                to,
                value: self.value,
                input,
            }),
            TxType::Eip2930 => UnsignedTx::Eip2930(TxEip2930 {
                chain_id,
                nonce,
                gas_price: self.gas_price.unwrap_or(fill.gas_price),
                gas_limit,
                to,
                value: self.value,
                access_list,
                input,
            }),
            TxType::Eip1559 => UnsignedTx::Eip1559(TxEip1559 {
                chain_id,
                nonce,
                gas_limit,
                max_fee_per_gas: self.max_fee_per_gas.unwrap_or(fill.max_fee_per_gas),
                max_priority_fee_per_gas: self
                    .max_priority_fee_per_gas
                    .unwrap_or(fill.max_priority_fee_per_gas),
                to,
                value: self.value,
                access_list,
                input,
            }),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Shape observed from `cast send --unlocked` (Foundry 1.8.3).
    fn cast_request() -> Value {
        json!({"from":"0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266","to":"0x70997970c51812dc3a010c7d01b50e0d17dc79c8",
               "maxFeePerGas":"0x77359401","maxPriorityFeePerGas":"0x1","gas":"0x5208","value":"0xde0b6b3a7640000",
               "input":"0x","data":"0x","nonce":"0x0","chainId":"0x7a69","type":"0x2"})
    }

    #[test]
    fn caller_fields_win_over_fill() {
        let req = TxRequest::parse(&cast_request()).unwrap();
        let UnsignedTx::Eip1559(tx) = req
            .build(Fill {
                chain_id: 31337,
                nonce: 99,
                gas: 1,
                ..Default::default()
            })
            .unwrap()
        else {
            panic!()
        };
        assert_eq!(
            (
                tx.nonce,
                tx.gas_limit,
                tx.max_fee_per_gas,
                tx.max_priority_fee_per_gas
            ),
            (0, 21000, 2_000_000_001, 1)
        );
        assert_eq!(tx.value, U256::from(10u64.pow(18)));
    }

    #[test]
    fn rejects_mismatches() {
        let mut v = cast_request();
        v["data"] = json!("0x01");
        assert!(TxRequest::parse(&v).is_err());
        let req = TxRequest::parse(&cast_request()).unwrap();
        assert!(matches!(
            req.build(Fill {
                chain_id: 1,
                ..Default::default()
            }),
            Err(Error::ChainMismatch)
        ));
    }

    #[test]
    fn type_inference_and_fill() {
        let legacy = TxRequest::parse(
            &json!({"from":"0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266","gasPrice":"0x1"}),
        )
        .unwrap();
        assert_eq!(legacy.tx_type().unwrap(), TxType::Legacy);
        let bare = TxRequest::parse(&json!({"from":"0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"}))
            .unwrap();
        let UnsignedTx::Eip1559(tx) = bare
            .build(Fill {
                chain_id: 5,
                nonce: 3,
                gas: 53000,
                max_fee_per_gas: 10,
                max_priority_fee_per_gas: 2,
                ..Default::default()
            })
            .unwrap()
        else {
            panic!()
        };
        assert_eq!(
            (tx.chain_id, tx.nonce, tx.gas_limit, tx.to),
            (5, 3, 53000, TxKind::Create)
        );
    }
}
