//! Mailbox addressing (§2.1): `mailbox_id = SHA-256("blox/v1/mailbox" ‖ read_secret)`.

use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{Result, b64};

const DOMAIN: &[u8] = b"blox/v1/mailbox";

#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MailboxId(#[serde(with = "b64::array")] pub [u8; 32]);

impl MailboxId {
    pub fn parse(s: &str) -> Result<Self> {
        Ok(Self(b64::decode_array(s)?))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for MailboxId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&b64::encode(self.0))
    }
}

/// Deliberately does not print the id: mailbox ids must never reach logs (§8.5).
impl fmt::Debug for MailboxId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MailboxId(..)")
    }
}

/// The capability to read a mailbox. Only its holder can read or acknowledge.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ReadSecret([u8; 32]);

impl ReadSecret {
    pub fn generate() -> Self {
        let mut b = [0u8; 32];
        getrandom::fill(&mut b).expect("OS RNG");
        Self(b)
    }

    pub fn from_bytes(b: [u8; 32]) -> Self {
        Self(b)
    }

    pub fn parse(s: &str) -> Result<Self> {
        Ok(Self(b64::decode_array(s)?))
    }

    pub fn mailbox_id(&self) -> MailboxId {
        derive(&self.0)
    }

    /// Value for `Authorization: Bearer …`.
    pub fn to_bearer(&self) -> String {
        b64::encode(self.0)
    }
}

impl fmt::Debug for ReadSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ReadSecret(..)")
    }
}

pub fn derive(read_secret: &[u8]) -> MailboxId {
    let mut h = Sha256::new();
    h.update(DOMAIN);
    h.update(read_secret);
    MailboxId(h.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_is_43_chars_and_roundtrips() {
        let s = ReadSecret::generate();
        let id = s.mailbox_id();
        let text = id.to_string();
        assert_eq!(text.len(), 43);
        assert_eq!(MailboxId::parse(&text).unwrap(), id);
    }

    #[test]
    fn debug_hides_values() {
        let s = ReadSecret::generate();
        assert_eq!(
            format!("{:?} {:?}", s, s.mailbox_id()),
            "ReadSecret(..) MailboxId(..)"
        );
    }
}
