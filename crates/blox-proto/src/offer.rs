//! The connect offer carried by the QR code (BLOX.md §5.1).
//!
//! ```text
//! uri     = "BLOX:" base45(payload)
//! payload = version(1) ‖ S(32) ‖ s(32) ‖ ticket(16) ‖ psk(32)
//!         ‖ relay_len(1) ‖ relay ‖ label_len(1) ‖ label
//! ```

use crate::ident::{Ticket, VerifyingKey};
use crate::keys::{Psk, PublicKey};
use crate::token::PartyKeys;
use crate::{Error, Result, VERSION, base45, relay_url};

pub const URI_PREFIX: &str = "BLOX:";
/// Labels are truncated to this many bytes (on a UTF-8 boundary).
pub const MAX_LABEL: usize = 32;

#[derive(Clone, Debug, PartialEq)]
pub struct Offer {
    /// Normalized relay URL.
    pub relay: String,
    /// The requester's `S` and `s`.
    pub requester: PartyKeys,
    pub ticket: Ticket,
    pub psk: Psk,
    /// The requester's name. A claim (§3.3).
    pub label: String,
}

impl Offer {
    pub fn new(
        relay: &str,
        requester: PartyKeys,
        ticket: Ticket,
        psk: Psk,
        label: &str,
    ) -> Result<Self> {
        Ok(Self {
            relay: relay_url::normalize(relay)?,
            requester,
            ticket,
            psk,
            label: truncate(label, MAX_LABEL),
        })
    }

    pub fn to_uri(&self) -> String {
        let relay = relay_url::to_qr_field(&self.relay);
        let mut b =
            zeroize::Zeroizing::new(Vec::with_capacity(115 + relay.len() + self.label.len()));
        b.push(VERSION);
        b.extend_from_slice(self.requester.sig.as_bytes());
        b.extend_from_slice(&self.requester.kem.0);
        b.extend_from_slice(&self.ticket.0);
        b.extend_from_slice(&self.psk.0);
        b.push(u8::try_from(relay.len()).expect("relay url under 256 bytes"));
        b.extend_from_slice(relay.as_bytes());
        b.push(self.label.len() as u8);
        b.extend_from_slice(self.label.as_bytes());
        format!("{URI_PREFIX}{}", base45::encode(&b))
    }

    pub fn from_uri(uri: &str) -> Result<Self> {
        let body = uri
            .strip_prefix(URI_PREFIX)
            .ok_or(Error::Malformed("not a blox uri"))?;
        let bytes = zeroize::Zeroizing::new(base45::decode(body)?);
        let mut r = Reader(&bytes);
        let v = r.take(1)?[0];
        if v != VERSION {
            return Err(Error::Version(v));
        }
        let sig = VerifyingKey::from_bytes(&r.array()?)?;
        let kem = PublicKey(r.array()?);
        let ticket = Ticket(r.array()?);
        let psk = Psk::from_bytes(r.array()?);
        let relay = relay_url::from_qr_field(&r.string()?)?;
        let label = r.string()?;
        if label.len() > MAX_LABEL {
            return Err(Error::Malformed("label too long"));
        }
        if !r.0.is_empty() {
            return Err(Error::Malformed("trailing bytes in offer"));
        }
        Ok(Self {
            relay,
            requester: PartyKeys { sig, kem },
            ticket,
            psk,
            label,
        })
    }
}

struct Reader<'a>(&'a [u8]);

impl Reader<'_> {
    fn take(&mut self, n: usize) -> Result<&[u8]> {
        if self.0.len() < n {
            return Err(Error::Malformed("short offer"));
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(head)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        Ok(self.take(N)?.try_into().unwrap())
    }

    fn string(&mut self) -> Result<String> {
        let n = self.take(1)?[0] as usize;
        String::from_utf8(self.take(n)?.to_vec()).map_err(|_| Error::Malformed("utf-8"))
    }
}

fn truncate(s: &str, max: usize) -> String {
    let mut cut = s.len().min(max);
    while !s.is_char_boundary(cut) {
        cut -= 1;
    }
    s[..cut].to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ident::SigningKey;
    use crate::keys::KeyPair;

    fn offer(relay: &str, label: &str) -> Offer {
        Offer::new(
            relay,
            PartyKeys {
                sig: SigningKey::generate().public(),
                kem: KeyPair::generate().public(),
            },
            Ticket::generate(),
            Psk::generate(),
            label,
        )
        .unwrap()
    }

    #[test]
    fn roundtrip_relay_forms() {
        for relay in [
            "https://relay.example.com",
            "https://relay.example.org:8443",
            "http://my-computer.lan:8080",
        ] {
            let o = offer(relay, "Example");
            assert_eq!(Offer::from_uri(&o.to_uri()).unwrap(), o);
        }
    }

    #[test]
    fn offer_is_compact_and_alphanumeric() {
        let uri = offer("https://relay.example.com", "Example").to_uri();
        // 113 + 2 + 17 (relay.example.com) + 7 bytes → 209 Base45 characters + the prefix.
        assert_eq!(uri.len(), 5 + 209, "{} chars", uri.len());
        assert!(
            uri.bytes()
                .all(|c| b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:".contains(&c))
        );
    }

    #[test]
    fn label_truncated_on_char_boundary() {
        let o = offer("https://relay.example.com", &"é".repeat(40));
        assert_eq!(o.label.len(), 32);
        assert_eq!(Offer::from_uri(&o.to_uri()).unwrap().label, o.label);
    }

    #[test]
    fn rejects_malformed() {
        let uri = offer("https://relay.example.com", "x").to_uri();
        assert!(Offer::from_uri("blox:abc").is_err());
        assert!(Offer::from_uri(&uri[..uri.len() - 3]).is_err());
        assert!(Offer::from_uri(&format!("{uri}00")).is_err());
    }
}
