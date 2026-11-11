//! Ed25519 keys for relay access and connection tokens (BLOX.md §2.1, §2.2, §4.3, §4.4).
//!
//! A verifying key doubles as an inbox id. `Debug` never prints key material or ids,
//! because inbox ids must not reach logs (§8.5).

use std::fmt;

use ed25519_dalek::Signer as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::Zeroizing;

use crate::{Error, Result, b64};

/// An Ed25519 secret key (`S` on the requester side, `K` on the keystore side).
#[derive(Clone)]
pub struct SigningKey(ed25519_dalek::SigningKey);

impl SigningKey {
    pub fn generate() -> Self {
        let mut b = Zeroizing::new([0u8; 32]);
        getrandom::fill(b.as_mut()).expect("OS RNG");
        Self(ed25519_dalek::SigningKey::from_bytes(&b))
    }

    pub fn from_bytes(secret: &[u8; 32]) -> Self {
        Self(ed25519_dalek::SigningKey::from_bytes(secret))
    }

    /// The 32-byte secret, for storage by the caller.
    pub fn to_bytes(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.0.to_bytes())
    }

    pub fn public(&self) -> VerifyingKey {
        VerifyingKey(self.0.verifying_key())
    }

    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        self.0.sign(msg).to_bytes()
    }
}

impl fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SigningKey(..)")
    }
}

/// An Ed25519 public key. As an inbox id it is written as unpadded base64url (43 chars).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct VerifyingKey(ed25519_dalek::VerifyingKey);

/// Inboxes are named by their owner's verifying key (§2.2).
pub type InboxId = VerifyingKey;

impl VerifyingKey {
    pub fn from_bytes(b: &[u8; 32]) -> Result<Self> {
        let k = ed25519_dalek::VerifyingKey::from_bytes(b)
            .map_err(|_| Error::Malformed("ed25519 public key"))?;
        if k.is_weak() {
            return Err(Error::Malformed("weak ed25519 public key"));
        }
        Ok(Self(k))
    }

    pub fn parse(s: &str) -> Result<Self> {
        Self::from_bytes(&b64::decode_array(s)?)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }

    /// Strict verification (rejects malleable signatures and small-order keys).
    pub fn verify(&self, msg: &[u8], sig: &[u8; 64]) -> Result<()> {
        let sig = ed25519_dalek::Signature::from_bytes(sig);
        self.0
            .verify_strict(msg, &sig)
            .map_err(|_| Error::Signature)
    }
}

impl fmt::Display for VerifyingKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&b64::encode(self.as_bytes()))
    }
}

/// Deliberately does not print the key: it is an inbox id (§8.5).
impl fmt::Debug for VerifyingKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("VerifyingKey(..)")
    }
}

impl Serialize for VerifyingKey {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for VerifyingKey {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Self::parse(&s).map_err(serde::de::Error::custom)
    }
}

/// The 16-byte one-time ticket from the QR code (§5.1). Doubles as the server's login nonce.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Ticket(pub [u8; 16]);

impl Ticket {
    pub fn generate() -> Self {
        let mut b = [0u8; 16];
        getrandom::fill(&mut b).expect("OS RNG");
        Self(b)
    }

    pub fn parse(s: &str) -> Result<Self> {
        Ok(Self(b64::decode_array(s)?))
    }

    /// What the requester registers at the relay: `SHA-256(ticket)`.
    pub fn hash(&self) -> [u8; 32] {
        use sha2::Digest as _;
        sha2::Sha256::digest(self.0).into()
    }
}

impl fmt::Display for Ticket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&b64::encode(self.0))
    }
}

impl fmt::Debug for Ticket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Ticket(..)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_and_ids() {
        let k = SigningKey::generate();
        let pk = k.public();
        let sig = k.sign(b"hello");
        pk.verify(b"hello", &sig).unwrap();
        assert!(pk.verify(b"hellO", &sig).is_err());
        let text = pk.to_string();
        assert_eq!(text.len(), 43);
        assert_eq!(VerifyingKey::parse(&text).unwrap(), pk);
        let again = SigningKey::from_bytes(&k.to_bytes());
        assert_eq!(again.public(), pk);
        assert_eq!(format!("{k:?} {pk:?}"), "SigningKey(..) VerifyingKey(..)");
    }

    #[test]
    fn rejects_weak_and_malformed_keys() {
        assert!(VerifyingKey::from_bytes(&[0u8; 32]).is_err());
        assert!(VerifyingKey::parse("abc").is_err());
    }
}
