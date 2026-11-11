//! The account's signature on the connection statement (BLOX.md §5.2, §5.3): EIP-191.

use alloy_primitives::{Address, Signature, eip191_hash_message};
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;

use crate::{Error, Result, hex_bytes, to_hex};

/// Signs the statement text; returns `0x` + r‖s‖v (65 bytes, v = 27 or 28).
pub fn sign_statement(signer: &PrivateKeySigner, statement: &str) -> String {
    let sig = signer
        .sign_message_sync(statement.as_bytes())
        .expect("local signing does not fail");
    to_hex(sig.as_bytes())
}

/// Checks that `signature` over `statement` recovers to `account`, which must be written
/// with its EIP-55 checksum.
pub fn verify_statement(statement: &str, signature: &str, account: &str) -> Result<()> {
    let addr: Address = account.parse().map_err(Error::malformed)?;
    if addr.to_checksum(None) != account {
        return Err(Error::Verification("account is not checksummed"));
    }
    let sig = Signature::try_from(hex_bytes(signature)?.as_slice())
        .map_err(|_| Error::Verification("bad signature"))?;
    let signer = sig
        .recover_address_from_prehash(&eip191_hash_message(statement.as_bytes()))
        .map_err(|_| Error::Verification("bad signature"))?;
    if signer != addr {
        return Err(Error::Verification("signed by a different account"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sign::signer_from_mnemonic;

    #[test]
    fn sign_and_verify() {
        let s = signer_from_mnemonic(
            "test test test test test test test test test test test junk",
            0,
        )
        .unwrap();
        let account = s.address().to_checksum(None);
        let sig = sign_statement(&s, "Blox connection\nx");
        assert_eq!(sig.len(), 2 + 130);
        verify_statement("Blox connection\nx", &sig, &account).unwrap();
        assert!(verify_statement("Blox connection\ny", &sig, &account).is_err());
        assert!(verify_statement("Blox connection\nx", &sig, &account.to_lowercase()).is_err());
        let other = signer_from_mnemonic(
            "test test test test test test test test test test test junk",
            1,
        )
        .unwrap();
        assert!(
            verify_statement(
                "Blox connection\nx",
                &sig,
                &other.address().to_checksum(None)
            )
            .is_err()
        );
    }
}
