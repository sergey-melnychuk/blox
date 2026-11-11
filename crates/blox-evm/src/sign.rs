//! Signing what the user approved (BLOX.md §10.8).

use alloy_dyn_abi::TypedData;
use alloy_primitives::{B256, eip191_hash_message, keccak256};
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use hmac::{Hmac, KeyInit, Mac};
use k256::elliptic_curve::PrimeField;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{FieldBytes, NonZeroScalar, ProjectivePoint, Scalar};
use sha2::Sha512;
use zeroize::{Zeroize, Zeroizing};

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

/// Derives the EVM key at `m/44'/60'/0'/0/{index}` from a BIP-39 mnemonic (English, no
/// passphrase).
///
/// Written out (BIP-39 seed by PBKDF2, BIP-32 private derivation) so that every intermediate
/// secret is wiped: the words joined, the 64-byte seed, each key and chain code, and the HMAC
/// states (`hmac`/`sha2` with `zeroize`). Library mnemonic code (coins-bip39, used by alloy)
/// leaves the seed and chain codes in memory.
pub fn signer_from_mnemonic(phrase: &str, index: u32) -> crate::Result<PrivateKeySigner> {
    let m = bip39::Mnemonic::parse_in_normalized(bip39::Language::English, phrase)
        .map_err(crate::Error::malformed)?;
    let mut words = Zeroizing::new(Vec::with_capacity(phrase.len()));
    for (i, w) in m.words().enumerate() {
        if i > 0 {
            words.push(b' ');
        }
        words.extend_from_slice(w.as_bytes());
    }
    drop(m); // zeroized on drop (bip39 `zeroize`)
    let seed = seed(&words);

    // m: I = HMAC-SHA512("Bitcoin seed", seed)
    let i = hmac512(b"Bitcoin seed", &[&seed[..]]);
    let (mut key, mut chain) = split(&i)
        .filter(|(k, _)| !bool::from(k.is_zero()))
        .ok_or_else(|| crate::Error::malformed("invalid master key"))?;
    const H: u32 = 1 << 31;
    for child in [44 | H, 60 | H, H, 0, index] {
        (key, chain) = derive(&key, &chain, child)
            .ok_or_else(|| crate::Error::malformed("invalid child key"))?;
    }
    let nz = Option::<NonZeroScalar>::from(NonZeroScalar::new(*key))
        .ok_or_else(|| crate::Error::malformed("zero key"))?;
    Ok(PrivateKeySigner::from_signing_key(nz.into()))
}

/// BIP-39 seed: PBKDF2-HMAC-SHA512(words, "mnemonic", 2048 rounds), 64 bytes (one block).
fn seed(words: &[u8]) -> Zeroizing<[u8; 64]> {
    let mac = <Hmac<Sha512> as KeyInit>::new_from_slice(words).expect("HMAC takes any key length");
    let mut u = Zeroizing::new([0u8; 64]);
    let mut t = Zeroizing::new([0u8; 64]);
    let mut m = mac.clone();
    m.update(b"mnemonic");
    m.update(&1u32.to_be_bytes());
    finalize_into(m, &mut u);
    t.copy_from_slice(&*u);
    for _ in 1..2048 {
        let mut m = mac.clone();
        m.update(&*u);
        finalize_into(m, &mut u);
        t.iter_mut().zip(u.iter()).for_each(|(a, b)| *a ^= b);
    }
    t
}

fn hmac512(key: &[u8], parts: &[&[u8]]) -> Zeroizing<[u8; 64]> {
    let mut m = <Hmac<Sha512> as KeyInit>::new_from_slice(key).expect("HMAC takes any key length");
    parts.iter().for_each(|p| m.update(p));
    let mut out = Zeroizing::new([0u8; 64]);
    finalize_into(m, &mut out);
    out
}

/// Writes the MAC into `out` and wipes the temporary it came in.
fn finalize_into(m: Hmac<Sha512>, out: &mut [u8; 64]) {
    let mut tag = m.finalize().into_bytes();
    out.copy_from_slice(&tag);
    tag.as_mut_slice().zeroize();
}

/// IL as a scalar (None if it is not below the curve order) and IR as the chain code.
fn split(i: &[u8; 64]) -> Option<(Zeroizing<Scalar>, Zeroizing<[u8; 32]>)> {
    let mut il = FieldBytes::default();
    il.copy_from_slice(&i[..32]);
    let k = Option::<Scalar>::from(Scalar::from_repr(il));
    il[..].zeroize();
    let mut c = Zeroizing::new([0u8; 32]);
    c.copy_from_slice(&i[32..]);
    Some((Zeroizing::new(k?), c))
}

/// CKDpriv: one BIP-32 step. None for the (astronomically unlikely) invalid child.
fn derive(
    key: &Scalar,
    chain: &[u8; 32],
    child: u32,
) -> Option<(Zeroizing<Scalar>, Zeroizing<[u8; 32]>)> {
    let i = if child & (1 << 31) != 0 {
        let mut k = key.to_bytes();
        let i = hmac512(chain, &[&[0u8], &k[..], &child.to_be_bytes()]);
        k[..].zeroize();
        i
    } else {
        let point = (ProjectivePoint::GENERATOR * key)
            .to_affine()
            .to_encoded_point(true);
        hmac512(chain, &[point.as_bytes(), &child.to_be_bytes()])
    };
    let (tweak, c) = split(&i)?;
    let k = Zeroizing::new(*tweak + key);
    (!bool::from(k.is_zero())).then_some((k, c))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::address;

    /// The written-out derivation gives the same keys as alloy's (coins-bip39/bip32).
    #[test]
    fn matches_alloy_mnemonic_builder() {
        use alloy_signer_local::{MnemonicBuilder, coins_bip39::English};
        for phrase in [
            "test test test test test test test test test test test junk",
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title",
        ] {
            for index in [0, 1, 2, 7, 1000, (1 << 31) - 1] {
                let ours = signer_from_mnemonic(phrase, index).unwrap();
                let theirs = MnemonicBuilder::<English>::default()
                    .phrase(phrase)
                    .index(index)
                    .unwrap()
                    .build()
                    .unwrap();
                assert_eq!(ours.address(), theirs.address(), "{phrase} #{index}");
                assert_eq!(ours.credential().to_bytes(), theirs.credential().to_bytes());
            }
        }
    }

    #[test]
    fn rejects_bad_phrases() {
        assert!(
            signer_from_mnemonic(
                "test test test test test test test test test test test test",
                0
            )
            .is_err()
        );
        assert!(signer_from_mnemonic("not words", 0).is_err());
    }

    #[test]
    fn anvil_accounts() {
        let phrase = "test test test test test test test test test test test junk";
        assert_eq!(
            signer_from_mnemonic(phrase, 1).unwrap().address(),
            address!("0x70997970C51812dc3A010C7d01b50e0d17dc79C8")
        );
        assert_eq!(
            signer_from_mnemonic(phrase, 2).unwrap().address(),
            address!("0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC")
        );
    }

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
