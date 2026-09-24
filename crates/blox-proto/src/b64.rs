//! Unpadded base64url, used for every binary field in JSON and URLs.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use crate::{Error, Result};

pub fn encode(bytes: impl AsRef<[u8]>) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn decode(s: &str) -> Result<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|_| Error::Malformed("base64url"))
}

pub fn decode_array<const N: usize>(s: &str) -> Result<[u8; N]> {
    decode(s)?
        .try_into()
        .map_err(|_| Error::Malformed("base64url length"))
}

/// Serde helper for `[u8; N]` fields encoded as base64url strings.
pub mod array {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer, const N: usize>(v: &[u8; N], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&super::encode(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>, const N: usize>(
        d: D,
    ) -> Result<[u8; N], D::Error> {
        let s = String::deserialize(d)?;
        super::decode_array(&s).map_err(serde::de::Error::custom)
    }
}
