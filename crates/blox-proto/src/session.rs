//! The session payload carried by the QR code (§5.1).
//!
//! ```text
//! uri     = "BLOX:" base45(payload)
//! payload = version(1) ‖ apk(32) ‖ ma(32) ‖ psk(32)
//!         ‖ relay_len(1) ‖ relay ‖ label_len(1) ‖ label
//! relay   = ""                 → the default relay (DEFAULT_RELAY)
//!           "host[:port][/p]"  → https://…
//!           "http://…"         → as written (debug / LAN only; release apps refuse it)
//! ```
//!
//! Base45 keeps the QR code in alphanumeric mode, and the default relay costs no
//! bytes: about 170 characters instead of ~280 for base64 JSON.

use crate::keys::{Psk, PublicKey};
use crate::mailbox::MailboxId;
use crate::{Error, Result, VERSION, base45};

pub const URI_PREFIX: &str = "BLOX:";
pub const DEFAULT_RELAY: &str = "https://relay.example.com";
/// Labels are truncated to this many bytes (on a UTF-8 boundary).
pub const MAX_LABEL: usize = 32;

#[derive(Clone, Debug, PartialEq)]
pub struct SessionPayload {
    pub v: u8,
    /// Full relay URL, e.g. `https://relay.example.com`.
    pub relay: String,
    pub apk: PublicKey,
    pub ma: MailboxId,
    pub psk: Psk,
    pub label: String,
}

impl SessionPayload {
    pub fn new(
        relay: impl Into<String>,
        apk: PublicKey,
        ma: MailboxId,
        psk: Psk,
        label: impl Into<String>,
    ) -> Self {
        let relay = relay.into().trim_end_matches('/').to_owned();
        Self {
            v: VERSION,
            relay,
            apk,
            ma,
            psk,
            label: truncate(label.into(), MAX_LABEL),
        }
    }

    pub fn to_uri(&self) -> String {
        let relay = if self.relay == DEFAULT_RELAY {
            ""
        } else {
            self.relay.strip_prefix("https://").unwrap_or(&self.relay)
        };
        let label = truncate(self.label.clone(), MAX_LABEL);
        let mut b = Vec::with_capacity(99 + relay.len() + label.len());
        b.push(self.v);
        b.extend_from_slice(&self.apk.0);
        b.extend_from_slice(self.ma.as_bytes());
        b.extend_from_slice(&self.psk.0);
        b.push(u8::try_from(relay.len()).expect("relay url under 256 bytes"));
        b.extend_from_slice(relay.as_bytes());
        b.push(label.len() as u8);
        b.extend_from_slice(label.as_bytes());
        let uri = format!("{URI_PREFIX}{}", base45::encode(&b));
        zeroize::Zeroize::zeroize(&mut b); // held the PSK
        uri
    }

    pub fn from_uri(uri: &str) -> Result<Self> {
        let body = uri
            .strip_prefix(URI_PREFIX)
            .ok_or(Error::Malformed("not a blox session uri"))?;
        let bytes = zeroize::Zeroizing::new(base45::decode(body)?);
        let mut r = Reader(&bytes);
        let v = r.take(1)?[0];
        if v != VERSION {
            return Err(Error::Version(v));
        }
        let apk = PublicKey(r.array()?);
        let ma = MailboxId(r.array()?);
        let psk = Psk::from_bytes(r.array()?);
        let relay = r.string()?;
        let label = r.string()?;
        if !r.0.is_empty() {
            return Err(Error::Malformed("trailing bytes in session payload"));
        }
        let relay = match relay.as_str() {
            "" => DEFAULT_RELAY.to_owned(),
            r if r.starts_with("http://") => r.to_owned(),
            r if r.contains("://") => return Err(Error::Malformed("relay url")),
            r => format!("https://{r}"),
        };
        Ok(Self {
            v,
            relay,
            apk,
            ma,
            psk,
            label,
        })
    }
}

struct Reader<'a>(&'a [u8]);

impl Reader<'_> {
    fn take(&mut self, n: usize) -> Result<&[u8]> {
        if self.0.len() < n {
            return Err(Error::Malformed("short session payload"));
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

fn truncate(mut s: String, max: usize) -> String {
    if s.len() > max {
        let mut cut = max;
        while !s.is_char_boundary(cut) {
            cut -= 1;
        }
        s.truncate(cut);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::KeyPair;
    use crate::mailbox::ReadSecret;

    fn payload(relay: &str, label: &str) -> SessionPayload {
        SessionPayload::new(
            relay,
            KeyPair::generate().public(),
            ReadSecret::generate().mailbox_id(),
            Psk::generate(),
            label,
        )
    }

    #[test]
    fn roundtrip_relay_forms() {
        for relay in [
            DEFAULT_RELAY,
            "https://relay.example.org:8443",
            "http://my-computer.lan:8080",
        ] {
            let p = payload(relay, "laptop");
            let back = SessionPayload::from_uri(&p.to_uri()).unwrap();
            assert_eq!(back, p);
        }
    }

    #[test]
    fn default_relay_is_compact_and_alphanumeric() {
        let uri = payload(DEFAULT_RELAY, "laptop").to_uri();
        assert!(uri.len() <= 170, "{} chars", uri.len());
        assert!(
            uri.bytes()
                .all(|c| b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:".contains(&c))
        );
    }

    #[test]
    fn label_truncated_on_char_boundary() {
        let p = payload(DEFAULT_RELAY, &"é".repeat(40));
        assert_eq!(p.label.len(), 32);
        assert_eq!(
            SessionPayload::from_uri(&p.to_uri()).unwrap().label,
            p.label
        );
    }

    #[test]
    fn rejects_malformed() {
        let uri = payload(DEFAULT_RELAY, "x").to_uri();
        assert!(SessionPayload::from_uri("blox:s?p=abc").is_err());
        assert!(SessionPayload::from_uri(&uri[..uri.len() - 3]).is_err());
        assert!(SessionPayload::from_uri(&format!("{uri}00")).is_err());
    }
}
