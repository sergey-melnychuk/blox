//! The session payload carried by the QR code (§5.1): `blox:s?p=<base64url(json)>`.

use serde::{Deserialize, Serialize};

use crate::keys::{Psk, PublicKey};
use crate::mailbox::MailboxId;
use crate::{Error, Result, VERSION, b64};

pub const URI_PREFIX: &str = "blox:s?p=";

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SessionPayload {
    pub v: u8,
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
        Self {
            v: VERSION,
            relay: relay.into(),
            apk,
            ma,
            psk,
            label: label.into(),
        }
    }

    pub fn to_uri(&self) -> String {
        let json = serde_json::to_vec(self).expect("payload serializes");
        format!("{URI_PREFIX}{}", b64::encode(json))
    }

    pub fn from_uri(uri: &str) -> Result<Self> {
        let p = uri
            .strip_prefix(URI_PREFIX)
            .ok_or(Error::Malformed("not a blox session uri"))?;
        let payload: Self = serde_json::from_slice(&b64::decode(p)?)?;
        if payload.v != VERSION {
            return Err(Error::Version(payload.v));
        }
        if !payload.relay.starts_with("https://") && !payload.relay.starts_with("http://") {
            return Err(Error::Malformed("relay url"));
        }
        Ok(payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::KeyPair;
    use crate::mailbox::ReadSecret;

    #[test]
    fn uri_roundtrip_and_size() {
        let p = SessionPayload::new(
            "https://relay.example.com",
            KeyPair::generate().public(),
            ReadSecret::generate().mailbox_id(),
            Psk::generate(),
            "laptop",
        );
        let uri = p.to_uri();
        assert!(uri.len() < 300, "QR payload is {} chars", uri.len());
        assert_eq!(SessionPayload::from_uri(&uri).unwrap(), p);
        assert!(SessionPayload::from_uri("blox:pair?p=x").is_err());
    }
}
