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

/// Pins a QR code module for module, for the TypeScript encoder (test-vectors/qr-v1.json).
/// Regenerate with `BLOX_REGEN_VECTORS=1`.
#[test]
fn qr_vectors() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../test-vectors/qr-v1.json");
    let vectors: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../test-vectors/proto-v1.json"
        ))
        .unwrap(),
    )
    .unwrap();
    let inputs = [
        vectors["offer"]["uri"].as_str().unwrap().to_owned(),
        "BLOX:HELLO".to_owned(),
        "https://example.com/lowercase bytes".to_owned(),
    ];
    let cases: Vec<serde_json::Value> = inputs
        .iter()
        .map(|data| {
            let code =
                qrcode::QrCode::with_error_correction_level(data.as_bytes(), qrcode::EcLevel::M)
                    .unwrap();
            let w = code.width();
            let rows: Vec<String> = code
                .to_colors()
                .chunks(w)
                .map(|r| {
                    r.iter()
                        .map(|c| if *c == qrcode::Color::Dark { '1' } else { '0' })
                        .collect()
                })
                .collect();
            serde_json::json!({ "data": data, "rows": rows })
        })
        .collect();
    let fresh = serde_json::json!({ "description": "QR codes at level M from the Rust qrcode crate, rows top to bottom, 1 = dark, no quiet zone.", "cases": cases });
    if std::env::var_os("BLOX_REGEN_VECTORS").is_some() {
        std::fs::write(path, serde_json::to_string_pretty(&fresh).unwrap() + "\n").unwrap();
    }
    let stored: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    assert_eq!(stored, fresh);
}
