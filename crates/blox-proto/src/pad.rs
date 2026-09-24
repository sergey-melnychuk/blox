//! Size bucketing (§4.5): append 0x80, then zeros up to the next bucket.

use crate::{Error, Result};

pub const BUCKETS: [usize; 5] = [1 << 10, 4 << 10, 16 << 10, 64 << 10, 256 << 10];
pub const MAX_PLAINTEXT: usize = (256 << 10) - 1;

pub fn pad(plaintext: &[u8]) -> Result<Vec<u8>> {
    let bucket = BUCKETS
        .iter()
        .copied()
        .find(|b| plaintext.len() < *b)
        .ok_or(Error::TooLarge)?;
    let mut out = Vec::with_capacity(bucket);
    out.extend_from_slice(plaintext);
    out.push(0x80);
    out.resize(bucket, 0);
    Ok(out)
}

pub fn unpad(mut padded: Vec<u8>) -> Result<Vec<u8>> {
    let end = padded
        .iter()
        .rposition(|b| *b != 0)
        .ok_or(Error::Malformed("padding"))?;
    if padded[end] != 0x80 {
        return Err(Error::Malformed("padding"));
    }
    padded.truncate(end);
    Ok(padded)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_buckets() {
        for (len, bucket) in [
            (0, 1024),
            (1023, 1024),
            (1024, 4096),
            (MAX_PLAINTEXT, 256 << 10),
        ] {
            let pt = vec![7u8; len];
            let p = pad(&pt).unwrap();
            assert_eq!(p.len(), bucket, "len {len}");
            assert_eq!(unpad(p).unwrap(), pt);
        }
    }

    #[test]
    fn trailing_zeros_in_plaintext_survive() {
        let pt = b"abc\0\0".to_vec();
        assert_eq!(unpad(pad(&pt).unwrap()).unwrap(), pt);
    }

    #[test]
    fn too_large_and_bad_padding() {
        assert!(matches!(
            pad(&vec![0; MAX_PLAINTEXT + 1]),
            Err(Error::TooLarge)
        ));
        assert!(unpad(vec![0; 16]).is_err());
        assert!(unpad(vec![1, 2, 3, 0]).is_err());
    }
}
