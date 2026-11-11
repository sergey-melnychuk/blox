//! X25519 transport keys (HPKE) and the bind PSK (BLOX.md §4.2).

use std::fmt;

use hpke::{Deserializable, Kem as _, Serializable, kem::X25519HkdfSha256};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{Error, Result, b64};

pub(crate) type Kem = X25519HkdfSha256;

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicKey(#[serde(with = "b64::array")] pub [u8; 32]);

impl PublicKey {
    pub(crate) fn to_hpke(self) -> Result<<Kem as hpke::Kem>::PublicKey> {
        <Kem as hpke::Kem>::PublicKey::from_bytes(&self.0)
            .map_err(|_| Error::Malformed("public key"))
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey({})", b64::encode(self.0))
    }
}

/// An X25519 keypair: `s` (one per connection) or `k` (one per signer).
#[derive(Clone)]
pub struct KeyPair {
    pub(crate) sk: <Kem as hpke::Kem>::PrivateKey,
    pub(crate) pk: <Kem as hpke::Kem>::PublicKey,
}

impl KeyPair {
    pub fn generate() -> Self {
        let (sk, pk) = Kem::gen_keypair();
        Self { sk, pk }
    }

    /// Deterministic keypair from input keying material (test vectors only).
    pub fn derive(ikm: &[u8]) -> Self {
        let (sk, pk) = Kem::derive_keypair(ikm);
        Self { sk, pk }
    }

    pub fn public(&self) -> PublicKey {
        PublicKey(self.pk.to_bytes().into())
    }

    /// The 32-byte secret, for storage by the caller.
    pub fn to_secret_bytes(&self) -> zeroize::Zeroizing<[u8; 32]> {
        zeroize::Zeroizing::new(self.sk.to_bytes().into())
    }

    pub fn from_secret_bytes(secret: &[u8; 32]) -> Result<Self> {
        let sk = <Kem as hpke::Kem>::PrivateKey::from_bytes(secret)
            .map_err(|_| Error::Malformed("x25519 secret key"))?;
        let pk = Kem::sk_to_pk(&sk);
        Ok(Self { sk, pk })
    }
}

impl fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KeyPair({:?})", self.public())
    }
}

/// The 32-byte PSK for `bind` (§4.5). It travels only inside the QR code.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct Psk(pub(crate) [u8; 32]);

impl Psk {
    pub fn generate() -> Self {
        let mut b = [0u8; 32];
        getrandom::fill(&mut b).expect("OS RNG");
        Self(b)
    }

    pub fn from_bytes(b: [u8; 32]) -> Self {
        Self(b)
    }
}

impl fmt::Debug for Psk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Psk(..)")
    }
}

impl Serialize for Psk {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        b64::array::serialize(&self.0, s)
    }
}

impl<'de> Deserialize<'de> for Psk {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        b64::array::deserialize(d).map(Psk)
    }
}
