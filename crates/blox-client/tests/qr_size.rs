//! The offer's QR code stays small (BLOX.md §5.1): version 8 (49 modules) for a typical
//! label on the default relay, at most version 10 (57 modules).

use blox_proto::connection::ConnectAttempt;
use qrcode::{QrCode, Version};

fn modules(data: &str) -> i16 {
    match QrCode::new(data.as_bytes()).unwrap().version() {
        Version::Normal(v) => 17 + 4 * v,
        Version::Micro(_) => unreachable!(),
    }
}

#[test]
fn offer_qr_size() {
    let typical = ConnectAttempt::new("https://relay.example.com", "Example", None).unwrap();
    assert!(modules(&typical.uri()) <= 49, "{}", modules(&typical.uri()));
    let worst =
        ConnectAttempt::new("https://relay.example.org:8443", &"x".repeat(32), None).unwrap();
    assert!(modules(&worst.uri()) <= 57, "{}", modules(&worst.uri()));
}
