//! Base45 (RFC 9285). Its alphabet is exactly QR's alphanumeric set, so QR
//! encoders use alphanumeric mode: ~8.25 bits per byte instead of 10.7 for
//! base64 in byte mode.

use crate::{Error, Result};

const ALPHABET: &[u8; 45] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:";

pub fn encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(2) * 3);
    for chunk in bytes.chunks(2) {
        let (mut n, digits) = match chunk {
            [a, b] => (u32::from(*a) * 256 + u32::from(*b), 3),
            [a] => (u32::from(*a), 2),
            _ => unreachable!(),
        };
        for _ in 0..digits {
            out.push(ALPHABET[(n % 45) as usize] as char);
            n /= 45;
        }
    }
    out
}

pub fn decode(s: &str) -> Result<Vec<u8>> {
    let bad = || Error::Malformed("base45");
    let digits: Vec<u32> = s
        .bytes()
        .map(|c| {
            ALPHABET
                .iter()
                .position(|&a| a == c)
                .map(|p| p as u32)
                .ok_or_else(bad)
        })
        .collect::<Result<_>>()?;
    let mut out = Vec::with_capacity(digits.len() / 3 * 2 + 1);
    for chunk in digits.chunks(3) {
        match *chunk {
            [c, d, e] => {
                let n = c + d * 45 + e * 45 * 45;
                if n > 0xffff {
                    return Err(bad());
                }
                out.extend_from_slice(&(n as u16).to_be_bytes());
            }
            [c, d] => {
                let n = c + d * 45;
                out.push(u8::try_from(n).map_err(|_| bad())?);
            }
            _ => return Err(bad()),
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc9285_examples() {
        assert_eq!(encode(b"AB"), "BB8");
        assert_eq!(encode(b"Hello!!"), "%69 VD92EX0");
        assert_eq!(encode(b"base-45"), "UJCLQE7W581");
        assert_eq!(decode("QED8WEX0").unwrap(), b"ietf!");
    }

    #[test]
    fn roundtrip_and_rejects() {
        for len in 0..40 {
            let v: Vec<u8> = (0..len).map(|i| (i * 37 + 11) as u8).collect();
            assert_eq!(decode(&encode(&v)).unwrap(), v);
        }
        assert!(decode("GGW").is_err()); // 65535 < value
        assert!(decode("a").is_err());
        assert!(decode("0").is_err());
    }
}
