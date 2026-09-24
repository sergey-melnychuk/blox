//! What the keystore shows before approval (§10.5). The app renders this
//! model as-is and never parses payloads itself.

use alloy_dyn_abi::{DynSolType, DynSolValue, TypedData};
use alloy_primitives::{Address, U256, keccak256};

use crate::sign::Prepared;
use crate::tx::UnsignedTx;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Display {
    pub title: String,
    pub fields: Vec<Field>,
    /// A decoded contract call or message, when recognised.
    pub decoded: Option<String>,
    pub dangers: Vec<Danger>,
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Field {
    pub label: String,
    pub value: String,
    /// Full value when `value` is shortened (shown on tap).
    pub full: Option<String>,
}

/// A request that needs a red banner and an extra, typed confirmation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Danger {
    pub message: String,
    /// What the user must type to continue (last 4 hex chars of the spender or
    /// operator), or `None` when a plain extra confirmation is enough.
    pub confirm: Option<String>,
}

const UNLIMITED: U256 = U256::from_limbs([0, 0, 0, 1 << 63]); // 2^255
const PERMIT2: Address = alloy_primitives::address!("0x000000000022D473030F116dDEE9F6B43aC78BA3");

pub fn chain_name(id: u64) -> Option<&'static str> {
    Some(match id {
        1 => "Ethereum",
        10 => "OP Mainnet",
        56 => "BNB Smart Chain",
        100 => "Gnosis",
        137 => "Polygon",
        324 => "zkSync Era",
        8453 => "Base",
        42161 => "Arbitrum One",
        43114 => "Avalanche C-Chain",
        59144 => "Linea",
        534352 => "Scroll",
        11155111 => "Sepolia",
        17000 => "Holesky",
        84532 => "Base Sepolia",
        31337 => "Local (Anvil / Hardhat)",
        _ => return None,
    })
}

pub fn describe(prepared: &Prepared, from: Address) -> Display {
    match prepared {
        Prepared::Tx(tx) => describe_tx(tx, from),
        Prepared::TypedData(td) => describe_typed(td, from),
        Prepared::PersonalSign(m) => describe_message(m, from),
    }
}

fn field(label: &str, value: impl Into<String>) -> Field {
    Field {
        label: label.into(),
        value: value.into(),
        full: None,
    }
}

fn checksum(a: Address) -> String {
    a.to_checksum(None)
}

fn last4(a: Address) -> String {
    checksum(a)[38..].to_owned()
}

/// Formats `wei` with 18 decimals, trimming trailing zeros.
pub fn format_units(v: U256, decimals: usize) -> String {
    let s = v.to_string();
    let (int, frac) = if s.len() > decimals {
        (
            s[..s.len() - decimals].to_owned(),
            s[s.len() - decimals..].to_owned(),
        )
    } else {
        ("0".to_owned(), format!("{s:0>decimals$}"))
    };
    let frac = frac.trim_end_matches('0');
    if frac.is_empty() {
        int
    } else {
        format!("{int}.{frac}")
    }
}

fn gwei(v: u128) -> String {
    format!("{} gwei", format_units(U256::from(v), 9))
}

fn network(chain_id: u64, warnings: &mut Vec<String>) -> Field {
    match chain_name(chain_id) {
        Some(name) => field("Network", format!("{name} (eip155:{chain_id})")),
        None => {
            warnings.push(format!(
                "Unknown network eip155:{chain_id}. Check that this is the chain you expect."
            ));
            field("Network", format!("Unknown (eip155:{chain_id})"))
        }
    }
}

fn describe_tx(tx: &UnsignedTx, from: Address) -> Display {
    let mut warnings = Vec::new();
    let mut dangers = Vec::new();
    let (to, value, input, gas, fees) = match tx {
        UnsignedTx::Legacy(t) => (
            t.to.to().copied(),
            t.value,
            &t.input,
            t.gas_limit,
            Fees::Legacy(t.gas_price),
        ),
        UnsignedTx::Eip2930(t) => (
            t.to.to().copied(),
            t.value,
            &t.input,
            t.gas_limit,
            Fees::Legacy(t.gas_price),
        ),
        UnsignedTx::Eip1559(t) => (
            t.to.to().copied(),
            t.value,
            &t.input,
            t.gas_limit,
            Fees::Eip1559(t.max_fee_per_gas, t.max_priority_fee_per_gas),
        ),
    };
    let mut fields = vec![
        network(tx.chain_id(), &mut warnings),
        field("From", checksum(from)),
    ];
    match to {
        Some(to) => fields.push(field("To", checksum(to))),
        None => {
            fields.push(field("To", "Contract creation"));
            dangers.push(Danger {
                message: "This transaction deploys a new contract.".into(),
                confirm: None,
            });
        }
    }
    fields.push(field("Value", format!("{} ETH", format_units(value, 18))));
    let max_price = match fees {
        Fees::Legacy(p) => {
            fields.push(field("Gas price", gwei(p)));
            p
        }
        Fees::Eip1559(max, prio) => {
            fields.push(field("Max fee", gwei(max)));
            fields.push(field("Max priority", gwei(prio)));
            max
        }
    };
    let max_cost = U256::from(gas) * U256::from(max_price) + value;
    fields.push(field("Gas limit", gas.to_string()));
    fields.push(field(
        "Max cost",
        format!("{} ETH", format_units(max_cost, 18)),
    ));
    fields.push(field("Nonce", tx.nonce().to_string()));
    if !input.is_empty() {
        let full = format!("0x{}", hex::encode(input));
        let short = if input.len() > 10 {
            format!("0x{}…", hex::encode(&input[..10]))
        } else {
            full.clone()
        };
        fields.push(Field {
            label: "Data".into(),
            value: short,
            full: Some(full),
        });
    }
    let decoded = decode_call(input, &mut dangers);
    if to.is_some() && !input.is_empty() && decoded.is_none() {
        warnings
            .push("Unrecognised contract call. Check the data with the contract's source.".into());
    }
    Display {
        title: "Transaction".into(),
        fields,
        decoded,
        dangers,
        warnings,
    }
}

enum Fees {
    Legacy(u128),
    Eip1559(u128, u128),
}

/// Well-known calls: `(signature, parameter names)`.
const CALLS: &[(&str, &[&str])] = &[
    ("transfer(address,uint256)", &["to", "amount"]),
    ("approve(address,uint256)", &["spender", "amount"]),
    (
        "transferFrom(address,address,uint256)",
        &["from", "to", "amount"],
    ),
    ("increaseAllowance(address,uint256)", &["spender", "added"]),
    (
        "safeTransferFrom(address,address,uint256)",
        &["from", "to", "tokenId"],
    ),
    (
        "safeTransferFrom(address,address,uint256,bytes)",
        &["from", "to", "tokenId", "data"],
    ),
    (
        "safeTransferFrom(address,address,uint256,uint256,bytes)",
        &["from", "to", "id", "amount", "data"],
    ),
    ("setApprovalForAll(address,bool)", &["operator", "approved"]),
    ("deposit()", &[]),
    ("withdraw(uint256)", &["amount"]),
    ("multicall(bytes[])", &["calls"]),
    ("multicall(uint256,bytes[])", &["deadline", "calls"]),
];

fn decode_call(input: &[u8], dangers: &mut Vec<Danger>) -> Option<String> {
    if input.len() < 4 {
        return None;
    }
    let (selector, args) = input.split_at(4);
    let (sig, names) = CALLS
        .iter()
        .find(|(sig, _)| keccak256(sig.as_bytes())[..4] == *selector)?;
    let name = &sig[..sig.find('(').unwrap()];
    let params = DynSolType::parse(&sig[name.len()..]).ok()?;
    let DynSolValue::Tuple(values) = params.abi_decode_params(args).ok()? else {
        return None;
    };

    if name.starts_with("multicall") {
        let n = values
            .iter()
            .find_map(|v| v.as_array().map(<[_]>::len))
            .unwrap_or(0);
        return Some(format!("{name}: {n} batched calls (not decoded)"));
    }
    match (name, values.as_slice()) {
        (
            "approve" | "increaseAllowance",
            [DynSolValue::Address(spender), DynSolValue::Uint(amount, _)],
        ) if *amount >= UNLIMITED => {
            dangers.push(Danger {
                message: format!("Unlimited token approval for {}.", checksum(*spender)),
                confirm: Some(last4(*spender)),
            });
        }
        ("setApprovalForAll", [DynSolValue::Address(operator), DynSolValue::Bool(true)]) => {
            dangers.push(Danger {
                message: format!(
                    "Gives {} control of all your tokens in this collection.",
                    checksum(*operator)
                ),
                confirm: Some(last4(*operator)),
            });
        }
        _ => {}
    }
    let args: Vec<String> = names
        .iter()
        .zip(&values)
        .map(|(n, v)| format!("{n}={}", show(v)))
        .collect();
    Some(format!("{name}({})", args.join(", ")))
}

fn show(v: &DynSolValue) -> String {
    match v {
        DynSolValue::Address(a) => checksum(*a),
        DynSolValue::Uint(u, _) if *u >= UNLIMITED => "unlimited".into(),
        DynSolValue::Uint(u, _) => u.to_string(),
        DynSolValue::Bool(b) => b.to_string(),
        DynSolValue::Bytes(b) => format!("0x{}", hex::encode(b)),
        other => format!("{other:?}"),
    }
}

fn describe_typed(td: &TypedData, from: Address) -> Display {
    let mut warnings = Vec::new();
    let mut dangers = Vec::new();
    let d = &td.domain;
    let mut fields = Vec::new();
    if let Some(id) = d.chain_id {
        fields.push(network(id.saturating_to(), &mut warnings));
    }
    fields.push(field("Signer", checksum(from)));
    if let Some(name) = &d.name {
        fields.push(field("App / contract name", name.to_string()));
    }
    if let Some(version) = &d.version {
        fields.push(field("Version", version.to_string()));
    }
    if let Some(vc) = d.verifying_contract {
        fields.push(field("Verifying contract", checksum(vc)));
    }
    fields.push(field("Type", td.primary_type.clone()));
    let message = serde_json::to_string_pretty(&td.message).unwrap_or_default();

    let spender = td
        .message
        .get("spender")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<Address>().ok());
    let pt = td.primary_type.as_str();
    if d.verifying_contract == Some(PERMIT2)
        && matches!(
            pt,
            "PermitSingle" | "PermitBatch" | "PermitTransferFrom" | "PermitBatchTransferFrom"
        )
    {
        dangers.push(Danger {
            message:
                "Permit2 signature: lets the spender move your tokens without another transaction."
                    .into(),
            confirm: spender.map(last4),
        });
    } else if pt == "Permit" {
        dangers.push(Danger {
            message: "Token permit: lets the spender move your tokens without another transaction."
                .into(),
            confirm: spender.map(last4),
        });
    } else if pt == "OrderComponents" {
        dangers.push(Danger {
            message: "Marketplace order (Seaport): can transfer your assets when filled.".into(),
            confirm: None,
        });
    }
    Display {
        title: "Typed data signature".into(),
        fields,
        decoded: Some(message),
        dangers,
        warnings,
    }
}

fn describe_message(m: &[u8], from: Address) -> Display {
    let mut warnings = Vec::new();
    let mut fields = vec![field("Signer", checksum(from))];
    let text = std::str::from_utf8(m)
        .ok()
        .filter(|s| s.chars().all(|c| !c.is_control() || c == '\n' || c == '\t'));
    let mut title = "Message signature".to_owned();
    let decoded =
        match text {
            Some(t) => {
                if let Some(first) = t.lines().next().and_then(|l| {
                    l.strip_suffix(" wants you to sign in with your Ethereum account:")
                }) {
                    title = "Sign-In with Ethereum".into();
                    fields.push(field("Site", first));
                    for (label, key) in [("URI", "URI: "), ("Chain", "Chain ID: ")] {
                        if let Some(v) = t.lines().find_map(|l| l.strip_prefix(key)) {
                            fields.push(field(label, v));
                        }
                    }
                }
                t.to_owned()
            }
            None => format!("0x{}", hex::encode(m)),
        };
    if m.len() == 32 {
        warnings.push("This message is exactly 32 bytes and may be a hash. Only sign it if you know what it is.".into());
    }
    if UnsignedTx::decode(m).is_ok() {
        warnings.push(
            "This message is an encoded transaction. Signing it may authorise that transaction."
                .into(),
        );
    }
    Display {
        title,
        fields,
        decoded: Some(decoded),
        dangers: vec![],
        warnings,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::TxEip1559;
    use alloy_primitives::{Bytes, TxKind, address};

    const ME: Address = address!("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266");
    const SPENDER: Address = address!("0x70997970C51812dc3A010C7d01b50e0d17dc79C8");

    fn tx(to: Option<Address>, input: Vec<u8>) -> Prepared {
        Prepared::Tx(UnsignedTx::Eip1559(TxEip1559 {
            chain_id: 8453,
            nonce: 42,
            gas_limit: 21000,
            max_fee_per_gas: 30_000_000_000,
            max_priority_fee_per_gas: 1_500_000_000,
            to: to.map_or(TxKind::Create, TxKind::Call),
            value: U256::from(1_234_500_000_000_000_000u64),
            input: Bytes::from(input),
            ..Default::default()
        }))
    }

    fn call(sig: &str, args: &[DynSolValue]) -> Vec<u8> {
        let mut v = keccak256(sig.as_bytes())[..4].to_vec();
        v.extend(DynSolValue::Tuple(args.to_vec()).abi_encode_params());
        v
    }

    fn value<'a>(d: &'a Display, label: &str) -> &'a str {
        &d.fields.iter().find(|f| f.label == label).unwrap().value
    }

    #[test]
    fn plain_transfer_fields() {
        let d = describe(&tx(Some(SPENDER), vec![]), ME);
        assert_eq!(value(&d, "Network"), "Base (eip155:8453)");
        assert_eq!(
            value(&d, "To"),
            "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
        );
        assert_eq!(value(&d, "Value"), "1.2345 ETH");
        assert_eq!(value(&d, "Max fee"), "30 gwei");
        assert_eq!(value(&d, "Max priority"), "1.5 gwei");
        assert_eq!(value(&d, "Max cost"), "1.23513 ETH");
        assert!(d.dangers.is_empty() && d.warnings.is_empty());
    }

    #[test]
    fn unlimited_approval_needs_typed_confirmation() {
        let input = call(
            "approve(address,uint256)",
            &[
                DynSolValue::Address(SPENDER),
                DynSolValue::Uint(U256::MAX, 256),
            ],
        );
        let d = describe(&tx(Some(ME), input), ME);
        assert_eq!(
            d.decoded.as_deref(),
            Some("approve(spender=0x70997970C51812dc3A010C7d01b50e0d17dc79C8, amount=unlimited)")
        );
        assert_eq!(d.dangers[0].confirm.as_deref(), Some("79C8"));
        assert_eq!(value(&d, "Data"), "0x095ea7b3000000000000…");
    }

    #[test]
    fn approval_for_all_and_creation_are_dangerous() {
        let input = call(
            "setApprovalForAll(address,bool)",
            &[DynSolValue::Address(SPENDER), DynSolValue::Bool(true)],
        );
        assert_eq!(describe(&tx(Some(ME), input), ME).dangers.len(), 1);
        let d = describe(&tx(None, vec![0x60, 0x80]), ME);
        assert_eq!(value(&d, "To"), "Contract creation");
        assert_eq!(d.dangers.len(), 1);
    }

    #[test]
    fn unknown_call_and_chain_warn() {
        let mut p = tx(Some(SPENDER), vec![1, 2, 3, 4, 5]);
        if let Prepared::Tx(UnsignedTx::Eip1559(t)) = &mut p {
            t.chain_id = 999_999;
        }
        let d = describe(&p, ME);
        assert_eq!(d.warnings.len(), 2, "{:?}", d.warnings);
    }

    #[test]
    fn permit2_is_dangerous() {
        let td: TypedData = serde_json::from_value(serde_json::json!({
            "types": {"EIP712Domain":[{"name":"name","type":"string"},{"name":"chainId","type":"uint256"},{"name":"verifyingContract","type":"address"}],
                      "PermitSingle":[{"name":"spender","type":"address"},{"name":"sigDeadline","type":"uint256"}]},
            "primaryType":"PermitSingle",
            "domain":{"name":"Permit2","chainId":1,"verifyingContract":"0x000000000022D473030F116dDEE9F6B43aC78BA3"},
            "message":{"spender":"0x70997970C51812dc3A010C7d01b50e0d17dc79C8","sigDeadline":"1"}
        }))
        .unwrap();
        let d = describe(&Prepared::TypedData(Box::new(td)), ME);
        assert_eq!(d.dangers[0].confirm.as_deref(), Some("79C8"));
    }

    #[test]
    fn messages() {
        let siwe = b"example.com wants you to sign in with your Ethereum account:\n0xf39F\n\nURI: https://example.com\nChain ID: 1";
        let d = describe(&Prepared::PersonalSign(siwe.to_vec()), ME);
        assert_eq!(d.title, "Sign-In with Ethereum");
        assert_eq!(value(&d, "Site"), "example.com");
        let d = describe(&Prepared::PersonalSign(vec![0xab; 32]), ME);
        assert_eq!(d.warnings.len(), 1);
        assert!(d.decoded.unwrap().starts_with("0xabab"));
    }
}
