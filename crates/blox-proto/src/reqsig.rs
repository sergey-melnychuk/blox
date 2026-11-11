//! Relay request signatures (BLOX.md §4.4).
//!
//! ```text
//! Authorization: Blox <ts>.<sig, unpadded base64url>
//! sig = Ed25519("blox/v1/req" ‖ 0x00 ‖ method ‖ 0x00 ‖ path ‖ 0x00 ‖ ts(8, BE) ‖ SHA-256(body))
//! ```

use sha2::{Digest, Sha256};

use crate::b64;
use crate::ident::{SigningKey, VerifyingKey};

const DOMAIN: &[u8] = b"blox/v1/req";
const SCHEME: &str = "Blox ";
/// Allowed difference between the request's `ts` and the relay's clock (§8.4).
pub const MAX_SKEW_SECS: u64 = 60;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SigError {
    /// Missing or unparseable header.
    Malformed,
    /// `ts` is more than the allowed skew away from the relay's clock.
    Clock,
    /// The signature doesn't verify under the expected key.
    Signature,
}

fn message(method: &str, path: &str, ts: u64, body: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(DOMAIN.len() + method.len() + path.len() + 43);
    m.extend_from_slice(DOMAIN);
    m.push(0);
    m.extend_from_slice(method.to_ascii_uppercase().as_bytes());
    m.push(0);
    m.extend_from_slice(path.as_bytes());
    m.push(0);
    m.extend_from_slice(&ts.to_be_bytes());
    m.extend_from_slice(&Sha256::digest(body));
    m
}

/// Builds the `Authorization` header value for a request.
pub fn sign(key: &SigningKey, method: &str, path: &str, ts: u64, body: &[u8]) -> String {
    let sig = key.sign(&message(method, path, ts, body));
    format!("{SCHEME}{ts}.{}", b64::encode(sig))
}

/// Parses `Blox <ts>.<sig>`.
pub fn parse(header: &str) -> Result<(u64, [u8; 64]), SigError> {
    let rest = header.strip_prefix(SCHEME).ok_or(SigError::Malformed)?;
    let (ts, sig) = rest.split_once('.').ok_or(SigError::Malformed)?;
    if ts.is_empty() || !ts.bytes().all(|b| b.is_ascii_digit()) {
        return Err(SigError::Malformed);
    }
    let ts = ts.parse().map_err(|_| SigError::Malformed)?;
    let sig = b64::decode_array(sig).map_err(|_| SigError::Malformed)?;
    Ok((ts, sig))
}

/// Verifies a request against `key` and the relay's clock `now`, allowing `max_skew` seconds.
///
/// `path` is the API path starting at `/v1/`, without any base path of the relay URL.
pub fn verify(
    header: &str,
    key: &VerifyingKey,
    method: &str,
    path: &str,
    body: &[u8],
    now: u64,
    max_skew: u64,
) -> Result<(), SigError> {
    let (ts, sig) = parse(header)?;
    if ts.abs_diff(now) > max_skew {
        return Err(SigError::Clock);
    }
    key.verify(&message(method, path, ts, body), &sig)
        .map_err(|_| SigError::Signature)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify() {
        let k = SigningKey::generate();
        let pk = k.public();
        let h = sign(&k, "post", "/v1/inbox/x", 1000, b"body");
        assert!(h.starts_with("Blox 1000."));
        verify(&h, &pk, "POST", "/v1/inbox/x", b"body", 1030, MAX_SKEW_SECS).unwrap();
        let other = SigningKey::generate().public();
        for (key, method, path, body, now, want) in [
            (
                &pk,
                "POST",
                "/v1/inbox/x",
                &b"body"[..],
                1061,
                SigError::Clock,
            ),
            (&pk, "POST", "/v1/inbox/x", b"body", 939, SigError::Clock),
            (
                &pk,
                "GET",
                "/v1/inbox/x",
                b"body",
                1000,
                SigError::Signature,
            ),
            (
                &pk,
                "POST",
                "/v1/inbox/y",
                b"body",
                1000,
                SigError::Signature,
            ),
            (
                &pk,
                "POST",
                "/v1/inbox/x",
                b"bodY",
                1000,
                SigError::Signature,
            ),
            (
                &other,
                "POST",
                "/v1/inbox/x",
                b"body",
                1000,
                SigError::Signature,
            ),
        ] {
            assert_eq!(
                verify(&h, key, method, path, body, now, MAX_SKEW_SECS),
                Err(want)
            );
        }
        for bad in [
            "",
            "Bearer x",
            "Blox 12",
            "Blox .AA",
            "Blox -1.AA",
            "Blox 1.!!",
        ] {
            assert_eq!(parse(bad), Err(SigError::Malformed), "{bad}");
        }
    }
}
