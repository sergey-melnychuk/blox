//! The connection statement the account signs (BLOX.md §5.2).
//!
//! The exact text matters: the requester rebuilds it from the token and compares
//! byte for byte before checking the account's signature.

use crate::ident::{Ticket, VerifyingKey};

pub struct Statement<'a> {
    /// The QR label (claimed by the requester).
    pub label: &'a str,
    pub requester: &'a VerifyingKey,
    pub keystore: &'a VerifyingKey,
    /// Checksummed EVM address.
    pub account: &'a str,
    pub ticket: &'a Ticket,
    /// Normalized relay URL.
    pub relay: &'a str,
    pub issued_at: u64,
    pub expires_at: u64,
}

impl Statement<'_> {
    pub fn render(&self) -> String {
        [
            "Blox connection".to_owned(),
            format!("Site: {} (claimed)", self.label),
            format!("Site key: {}", self.requester),
            format!("Keystore key: {}", self.keystore),
            format!("Account: {}", self.account),
            format!("Nonce: {}", self.ticket),
            format!("Relay: {}", self.relay),
            format!("Issued: {}", iso8601(self.issued_at)),
            format!("Expires: {}", iso8601(self.expires_at)),
        ]
        .join("\n")
    }
}

/// `YYYY-MM-DDTHH:MM:SSZ` for a unix time (UTC).
pub fn iso8601(ts: u64) -> String {
    let days = (ts / 86400) as i64;
    let secs = ts % 86400;
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        secs / 3600,
        secs % 3600 / 60,
        secs % 60
    )
}

/// Days since 1970-01-01 → (year, month, day). Howard Hinnant's algorithm.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ident::SigningKey;

    #[test]
    fn dates() {
        assert_eq!(iso8601(0), "1970-01-01T00:00:00Z");
        assert_eq!(iso8601(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(iso8601(1_762_776_000), "2025-11-10T12:00:00Z");
        assert_eq!(iso8601(4_102_444_799), "2099-12-31T23:59:59Z");
    }

    #[test]
    fn renders_exactly() {
        let s = SigningKey::from_bytes(&[1; 32]).public();
        let k = SigningKey::from_bytes(&[2; 32]).public();
        let text = Statement {
            label: "Example",
            requester: &s,
            keystore: &k,
            account: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
            ticket: &Ticket([7; 16]),
            relay: "https://relay.example.com",
            issued_at: 1_762_776_000,
            expires_at: 1_762_776_000 + 30 * 86400,
        }
        .render();
        let lines: Vec<&str> = text.split('\n').collect();
        assert_eq!(lines.len(), 9);
        assert_eq!(lines[0], "Blox connection");
        assert_eq!(lines[1], "Site: Example (claimed)");
        assert_eq!(lines[2], format!("Site key: {s}"));
        assert_eq!(lines[5], "Nonce: BwcHBwcHBwcHBwcHBwcHBw");
        assert_eq!(lines[7], "Issued: 2025-11-10T12:00:00Z");
        assert_eq!(lines[8], "Expires: 2025-12-10T12:00:00Z");
        assert!(!text.ends_with('\n'));
    }
}
