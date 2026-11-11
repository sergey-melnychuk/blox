//! Filling a transaction from intent plus the keystore's own endpoint (BLOX.md §10.4).

use alloy_consensus::{TxEip1559, TxLegacy};
use alloy_primitives::{Address, TxKind, U256};
use serde_json::json;

use crate::display::format_units;
use crate::intent::TxIntent;
use crate::rpc::{ChainRpc, Rpc, RpcError, hex_q};
use crate::tx::UnsignedTx;

#[derive(Clone, Debug, PartialEq)]
pub struct Filled {
    pub tx: UnsignedTx,
    /// Shown on the review screen; approval is still possible.
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum FillError {
    /// `eth_estimateGas` failed: the transaction would fail on chain. Only Reject is offered.
    #[error("this transaction would fail: {0}")]
    WouldFail(String),
    /// The endpoint couldn't be reached or answered nonsense: Retry or Reject.
    #[error("{0}")]
    Unreachable(String),
}

impl From<RpcError> for FillError {
    fn from(e: RpcError) -> Self {
        FillError::Unreachable(e.to_string())
    }
}

/// Fills nonce, fees and gas for `intent` from `rpc`, the endpoint for `chain_id`.
///
/// `last_sent_nonce` is the last nonce this app *sent* for this chain and account since it
/// started; transactions returned by `evm.sign_tx` don't count (§6.4).
pub fn fill(
    rpc: &dyn ChainRpc,
    chain_id: u64,
    from: Address,
    intent: &TxIntent,
    last_sent_nonce: Option<u64>,
) -> Result<Filled, FillError> {
    let rpc = Rpc(rpc);
    let actual = rpc.chain_id()?;
    if actual != chain_id {
        return Err(FillError::Unreachable(format!(
            "the endpoint is on chain {actual}, not {chain_id}"
        )));
    }
    let pending = rpc.pending_nonce(from)?;
    let nonce = last_sent_nonce.map_or(pending, |n| pending.max(n + 1));

    let mut call = json!({
        "from": from,
        "value": hex_q(intent.value),
        "data": crate::to_hex(&intent.data),
    });
    if let Some(to) = intent.to {
        call["to"] = json!(to);
    }
    let estimate = match rpc.estimate_gas(call) {
        Ok(g) => g,
        Err(RpcError::Rpc { message, .. }) => return Err(FillError::WouldFail(message)),
        Err(e) => return Err(e.into()),
    };
    // × 1.2, rounded up.
    let gas_limit = estimate.saturating_mul(6).div_ceil(5);

    let to = intent.to.map_or(TxKind::Create, TxKind::Call);
    let (tx, max_price) = match rpc.base_fee()? {
        Some(base) => {
            let prio = match rpc.max_priority_fee() {
                Ok(p) => p,
                Err(RpcError::Rpc { .. }) => rpc.gas_price()?.saturating_sub(base),
                Err(e) => return Err(e.into()),
            };
            let max_fee = base.saturating_mul(2).saturating_add(prio);
            let tx = UnsignedTx::Eip1559(TxEip1559 {
                chain_id,
                nonce,
                gas_limit,
                max_fee_per_gas: max_fee,
                max_priority_fee_per_gas: prio,
                to,
                value: intent.value,
                access_list: Default::default(),
                input: intent.data.clone(),
            });
            (tx, max_fee)
        }
        None => {
            let gas_price = rpc.gas_price()?;
            let tx = UnsignedTx::Legacy(TxLegacy {
                chain_id: Some(chain_id),
                nonce,
                gas_price,
                gas_limit,
                to,
                value: intent.value,
                input: intent.data.clone(),
            });
            (tx, gas_price)
        }
    };

    let mut warnings = Vec::new();
    let max_cost = U256::from(gas_limit) * U256::from(max_price) + intent.value;
    let balance = rpc.pending_balance(from)?;
    if balance < max_cost {
        warnings.push(format!(
            "The balance ({} ETH) is below the maximum cost ({} ETH).",
            format_units(balance, 18),
            format_units(max_cost, 18)
        ));
    }
    Ok(Filled { tx, warnings })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use serde_json::Value;
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// A scripted endpoint: method → result (or error), recording calls.
    #[derive(Default)]
    pub(crate) struct Fake {
        pub answers: HashMap<&'static str, Result<Value, RpcError>>,
        pub calls: Mutex<Vec<(String, Value)>>,
    }

    impl ChainRpc for Fake {
        fn call(&self, method: &str, params: Value) -> Result<Value, RpcError> {
            self.calls.lock().unwrap().push((method.into(), params));
            self.answers.get(method).cloned().unwrap_or_else(|| {
                Err(RpcError::Rpc {
                    code: -32601,
                    message: "method not found".into(),
                })
            })
        }
    }

    pub(crate) fn london() -> Fake {
        let mut f = Fake::default();
        f.answers.insert("eth_chainId", Ok(json!("0x2105")));
        f.answers
            .insert("eth_getTransactionCount", Ok(json!("0x7")));
        f.answers.insert("eth_estimateGas", Ok(json!("0x5208")));
        f.answers.insert(
            "eth_getBlockByNumber",
            Ok(json!({"baseFeePerGas": "0x3b9aca00"})),
        );
        f.answers
            .insert("eth_maxPriorityFeePerGas", Ok(json!("0x5f5e100")));
        f.answers.insert("eth_gasPrice", Ok(json!("0x4a817c800")));
        f.answers
            .insert("eth_getBalance", Ok(json!("0xde0b6b3a7640000")));
        f
    }

    const FROM: Address = alloy_primitives::address!("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266");

    fn intent() -> TxIntent {
        TxIntent {
            to: Some(alloy_primitives::address!(
                "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
            )),
            value: U256::from(1000),
            data: Default::default(),
        }
    }

    #[test]
    fn type2_with_estimate_margin_and_nonce_rule() {
        let rpc = london();
        let f = fill(&rpc, 8453, FROM, &intent(), None).unwrap();
        let UnsignedTx::Eip1559(t) = &f.tx else {
            panic!()
        };
        assert_eq!(t.nonce, 7);
        assert_eq!(t.gas_limit, 25200); // 21000 × 1.2
        assert_eq!(t.max_priority_fee_per_gas, 100_000_000);
        assert_eq!(t.max_fee_per_gas, 2 * 1_000_000_000 + 100_000_000);
        assert!(f.warnings.is_empty());
        // The app sent nonce 9 already: next is 10 even if the endpoint lags.
        let f = fill(&rpc, 8453, FROM, &intent(), Some(9)).unwrap();
        assert_eq!(f.tx.nonce(), 10);
        let f = fill(&rpc, 8453, FROM, &intent(), Some(3)).unwrap();
        assert_eq!(f.tx.nonce(), 7);
    }

    #[test]
    fn priority_fee_fallback_and_legacy() {
        let mut rpc = london();
        rpc.answers.remove("eth_maxPriorityFeePerGas");
        let f = fill(&rpc, 8453, FROM, &intent(), None).unwrap();
        let UnsignedTx::Eip1559(t) = &f.tx else {
            panic!()
        };
        assert_eq!(t.max_priority_fee_per_gas, 20_000_000_000 - 1_000_000_000);

        rpc.answers
            .insert("eth_getBlockByNumber", Ok(json!({"number": "0x1"})));
        let f = fill(&rpc, 8453, FROM, &intent(), None).unwrap();
        let UnsignedTx::Legacy(t) = &f.tx else {
            panic!()
        };
        assert_eq!((t.chain_id, t.gas_price), (Some(8453), 20_000_000_000));
    }

    #[test]
    fn would_fail_unreachable_wrong_chain_and_balance() {
        let mut rpc = london();
        rpc.answers.insert(
            "eth_estimateGas",
            Err(RpcError::Rpc {
                code: 3,
                message: "execution reverted".into(),
            }),
        );
        assert_eq!(
            fill(&rpc, 8453, FROM, &intent(), None).unwrap_err(),
            FillError::WouldFail("execution reverted".into())
        );
        rpc.answers.insert(
            "eth_estimateGas",
            Err(RpcError::Unreachable("timeout".into())),
        );
        assert!(matches!(
            fill(&rpc, 8453, FROM, &intent(), None),
            Err(FillError::Unreachable(_))
        ));
        assert!(matches!(
            fill(&london(), 1, FROM, &intent(), None),
            Err(FillError::Unreachable(_))
        ));
        let mut poor = london();
        poor.answers.insert("eth_getBalance", Ok(json!("0x0")));
        assert_eq!(
            fill(&poor, 8453, FROM, &intent(), None)
                .unwrap()
                .warnings
                .len(),
            1
        );
    }
}
