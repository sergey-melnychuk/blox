//! Connection tokens (BLOX.md §4.3).
//!
//! ```text
//! body     = version(1) ‖ S(32) ‖ s(32) ‖ K(32) ‖ k(32)
//!          ‖ issued_at(8, BE) ‖ expires_at(8, BE) ‖ relay_len(1) ‖ relay
//! token    = body ‖ sig_K(64) ‖ [sig_S(64)]
//! signed   = "blox/v1/token" ‖ body
//! token_id = SHA-256("blox/v1/token" ‖ body)
//! ```

use sha2::{Digest, Sha256};

use crate::ident::{SigningKey, VerifyingKey};
use crate::keys::PublicKey;
use crate::{Error, Result, VERSION, b64};

const DOMAIN: &[u8] = b"blox/v1/token";
/// Longest allowed `expires_at − issued_at` (§4.3).
pub const MAX_LIFETIME_SECS: u64 = 90 * 24 * 3600;

/// One side's keys as named in a token.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PartyKeys {
    /// Ed25519: inbox id, relay request signatures, token signature.
    pub sig: VerifyingKey,
    /// X25519: HPKE.
    pub kem: PublicKey,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Party {
    Requester,
    Keystore,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenBody {
    pub requester: PartyKeys,
    pub keystore: PartyKeys,
    pub issued_at: u64,
    pub expires_at: u64,
    /// Normalized relay URL (§4.3).
    pub relay: String,
}

impl TokenBody {
    pub fn encode(&self) -> Vec<u8> {
        let relay = self.relay.as_bytes();
        let mut b = Vec::with_capacity(147 + relay.len());
        b.push(VERSION);
        b.extend_from_slice(self.requester.sig.as_bytes());
        b.extend_from_slice(&self.requester.kem.0);
        b.extend_from_slice(self.keystore.sig.as_bytes());
        b.extend_from_slice(&self.keystore.kem.0);
        b.extend_from_slice(&self.issued_at.to_be_bytes());
        b.extend_from_slice(&self.expires_at.to_be_bytes());
        b.push(u8::try_from(relay.len()).expect("normalized relay url is at most 255 bytes"));
        b.extend_from_slice(relay);
        b
    }

    /// Decodes a body from the start of `bytes`; returns it and its length.
    fn decode(bytes: &[u8]) -> Result<(Self, usize)> {
        let short = || Error::Malformed("short token");
        if bytes.len() < 146 {
            return Err(short());
        }
        if bytes[0] != VERSION {
            return Err(Error::Version(bytes[0]));
        }
        let arr = |at: usize| -> [u8; 32] { bytes[at..at + 32].try_into().unwrap() };
        let u64_at = |at: usize| u64::from_be_bytes(bytes[at..at + 8].try_into().unwrap());
        let relay_len = bytes[145] as usize;
        let end = 146 + relay_len;
        if bytes.len() < end {
            return Err(short());
        }
        let relay = std::str::from_utf8(&bytes[146..end])
            .map_err(|_| Error::Malformed("token relay"))?
            .to_owned();
        Ok((
            Self {
                requester: PartyKeys {
                    sig: VerifyingKey::from_bytes(&arr(1))?,
                    kem: PublicKey(arr(33)),
                },
                keystore: PartyKeys {
                    sig: VerifyingKey::from_bytes(&arr(65))?,
                    kem: PublicKey(arr(97)),
                },
                issued_at: u64_at(129),
                expires_at: u64_at(137),
                relay,
            },
            end,
        ))
    }

    pub fn keys(&self, party: Party) -> &PartyKeys {
        match party {
            Party::Requester => &self.requester,
            Party::Keystore => &self.keystore,
        }
    }

    /// Which party `key` is, if either.
    pub fn party_of(&self, key: &VerifyingKey) -> Option<Party> {
        if *key == self.requester.sig {
            Some(Party::Requester)
        } else if *key == self.keystore.sig {
            Some(Party::Keystore)
        } else {
            None
        }
    }

    /// `issued_at ≤ now + skew`, not expired, and a lifetime of at most 90 days.
    pub fn check_times(&self, now: u64, skew: u64) -> Result<()> {
        if self.issued_at > now + skew {
            return Err(Error::Malformed("token issued in the future"));
        }
        if self.expires_at <= now {
            return Err(Error::Expired);
        }
        if self.expires_at < self.issued_at || self.expires_at - self.issued_at > MAX_LIFETIME_SECS
        {
            return Err(Error::Malformed("token lifetime"));
        }
        Ok(())
    }
}

impl Party {
    pub fn other(self) -> Party {
        match self {
            Party::Requester => Party::Keystore,
            Party::Keystore => Party::Requester,
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct Token {
    pub body: TokenBody,
    encoded: Vec<u8>,
    keystore_sig: [u8; 64],
    requester_sig: Option<[u8; 64]>,
}

impl std::fmt::Debug for Token {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Token(..)")
    }
}

impl Token {
    /// Creates the token and signs it with the keystore's key `K` (§5.2).
    pub fn issue(body: TokenBody, keystore: &SigningKey) -> Result<Self> {
        if keystore.public() != body.keystore.sig {
            return Err(Error::Malformed(
                "signing key is not the token's keystore key",
            ));
        }
        let encoded = body.encode();
        let keystore_sig = keystore.sign(&signed_bytes(&encoded));
        Ok(Self {
            body,
            encoded,
            keystore_sig,
            requester_sig: None,
        })
    }

    /// Adds the requester's signature with `S` (§5.3).
    pub fn countersign(&mut self, requester: &SigningKey) -> Result<()> {
        if requester.public() != self.body.requester.sig {
            return Err(Error::Malformed(
                "signing key is not the token's requester key",
            ));
        }
        self.requester_sig = Some(requester.sign(&signed_bytes(&self.encoded)));
        Ok(())
    }

    pub fn id(&self) -> [u8; 32] {
        Sha256::digest(signed_bytes(&self.encoded)).into()
    }

    pub fn is_countersigned(&self) -> bool {
        self.requester_sig.is_some()
    }

    /// Verifies `party`'s signature. A missing requester signature is an error.
    pub fn verify(&self, party: Party) -> Result<()> {
        let msg = signed_bytes(&self.encoded);
        match party {
            Party::Keystore => self.body.keystore.sig.verify(&msg, &self.keystore_sig),
            Party::Requester => {
                let sig = self.requester_sig.as_ref().ok_or(Error::Signature)?;
                self.body.requester.sig.verify(&msg, sig)
            }
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut b = self.encoded.clone();
        b.extend_from_slice(&self.keystore_sig);
        if let Some(s) = &self.requester_sig {
            b.extend_from_slice(s);
        }
        b
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let (body, n) = TokenBody::decode(bytes)?;
        let sigs = &bytes[n..];
        let (keystore_sig, requester_sig) = match sigs.len() {
            64 => (sigs.try_into().unwrap(), None),
            128 => (
                sigs[..64].try_into().unwrap(),
                Some(sigs[64..].try_into().unwrap()),
            ),
            _ => return Err(Error::Malformed("token signatures")),
        };
        Ok(Self {
            body,
            encoded: bytes[..n].to_vec(),
            keystore_sig,
            requester_sig,
        })
    }

    /// Value of the `Blox-Token` header (unpadded base64url).
    pub fn to_header(&self) -> String {
        b64::encode(self.to_bytes())
    }

    pub fn from_header(s: &str) -> Result<Self> {
        Self::from_bytes(&b64::decode(s)?)
    }
}

fn signed_bytes(encoded: &[u8]) -> Vec<u8> {
    [DOMAIN, encoded].concat()
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::keys::KeyPair;

    pub(crate) fn body(s: &SigningKey, k: &SigningKey) -> TokenBody {
        TokenBody {
            requester: PartyKeys {
                sig: s.public(),
                kem: KeyPair::generate().public(),
            },
            keystore: PartyKeys {
                sig: k.public(),
                kem: KeyPair::generate().public(),
            },
            issued_at: 1_760_000_000,
            expires_at: 1_760_000_000 + 30 * 86400,
            relay: "https://relay.example.com".into(),
        }
    }

    #[test]
    fn issue_countersign_roundtrip() {
        let (s, k) = (SigningKey::generate(), SigningKey::generate());
        let mut t = Token::issue(body(&s, &k), &k).unwrap();
        t.verify(Party::Keystore).unwrap();
        assert!(t.verify(Party::Requester).is_err());
        let half = Token::from_header(&t.to_header()).unwrap();
        assert_eq!(half, t);
        let id = t.id();
        t.countersign(&s).unwrap();
        t.verify(Party::Requester).unwrap();
        assert_eq!(t.id(), id, "the id covers the body only");
        let full = Token::from_bytes(&t.to_bytes()).unwrap();
        assert_eq!(full, t);
        assert_eq!(full.to_bytes().len(), 146 + 21 + 128);
    }

    #[test]
    fn wrong_keys_and_tampering() {
        let (s, k) = (SigningKey::generate(), SigningKey::generate());
        assert!(Token::issue(body(&s, &k), &s).is_err());
        let mut t = Token::issue(body(&s, &k), &k).unwrap();
        assert!(t.countersign(&k).is_err());
        t.countersign(&s).unwrap();
        let bytes = t.to_bytes();
        for i in [0, 5, 130, 150, bytes.len() - 1, bytes.len() - 65] {
            let mut b = bytes.clone();
            b[i] ^= 1;
            let ok = Token::from_bytes(&b)
                .and_then(|t| t.verify(Party::Keystore).and(t.verify(Party::Requester)))
                .is_ok();
            assert!(!ok, "flip at {i} accepted");
        }
        assert!(Token::from_bytes(&bytes[..bytes.len() - 1]).is_err());
    }

    #[test]
    fn times() {
        let (s, k) = (SigningKey::generate(), SigningKey::generate());
        let b = body(&s, &k);
        b.check_times(b.issued_at, 60).unwrap();
        assert!(b.check_times(b.issued_at - 61, 60).is_err());
        assert!(matches!(
            b.check_times(b.expires_at, 60),
            Err(Error::Expired)
        ));
        let long = TokenBody {
            expires_at: b.issued_at + MAX_LIFETIME_SECS + 1,
            ..b.clone()
        };
        assert!(long.check_times(b.issued_at, 60).is_err());
        assert_eq!(b.party_of(&s.public()), Some(Party::Requester));
        assert_eq!(b.party_of(&SigningKey::generate().public()), None);
    }
}
