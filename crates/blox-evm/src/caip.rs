//! CAIP-2 chain ids and CAIP-10 account ids for the `eip155` namespace.

use alloy_primitives::Address;

use crate::{Error, Result};

pub fn chain(chain_id: u64) -> String {
    format!("eip155:{chain_id}")
}

pub fn account(chain_id: u64, address: Address) -> String {
    format!("eip155:{chain_id}:{}", address.to_checksum(None))
}

pub fn parse_chain(s: &str) -> Result<u64> {
    s.strip_prefix("eip155:")
        .and_then(|id| id.parse().ok())
        .ok_or_else(|| Error::Unsupported(format!("chain {s}")))
}

pub fn parse_account(s: &str) -> Result<(u64, Address)> {
    let (chain, addr) = s
        .rsplit_once(':')
        .ok_or_else(|| Error::Malformed("account".into()))?;
    Ok((parse_chain(chain)?, addr.parse().map_err(Error::malformed)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let a: Address = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
            .parse()
            .unwrap();
        let s = account(8453, a);
        assert_eq!(s, "eip155:8453:0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266");
        assert_eq!(parse_account(&s).unwrap(), (8453, a));
        assert!(parse_chain("solana:abc").is_err());
    }
}
