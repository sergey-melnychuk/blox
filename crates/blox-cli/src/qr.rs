use qrcode::QrCode;
use qrcode::render::unicode::Dense1x2;

/// Renders `data` as a terminal QR code (Unicode half blocks).
pub fn render(data: &str) -> String {
    match QrCode::new(data.as_bytes()) {
        Ok(code) => code
            .render::<Dense1x2>()
            .dark_color(Dense1x2::Light)
            .light_color(Dense1x2::Dark)
            .quiet_zone(true)
            .build(),
        Err(_) => "(QR payload too large to render)".into(),
    }
}

#[cfg(test)]
mod tests {
    use blox_proto::keys::{KeyPair, Psk};
    use blox_proto::mailbox::ReadSecret;
    use blox_proto::session::{DEFAULT_RELAY, SessionPayload};
    use qrcode::{QrCode, Version};

    fn modules(data: &str) -> i16 {
        match QrCode::new(data.as_bytes()).unwrap().version() {
            Version::Normal(v) => 17 + 4 * v,
            Version::Micro(_) => unreachable!(),
        }
    }

    fn uri(label: &str) -> String {
        let (apk, ma) = (KeyPair::generate().public(), ReadSecret::generate().mailbox_id());
        SessionPayload::new(DEFAULT_RELAY, apk, ma, Psk::generate(), label).to_uri()
    }

    /// Session QR codes stay small: v7 (45 modules) for a typical label, and at most v8
    /// (49 modules, 57 columns with the quiet zone) for the longest allowed label.
    #[test]
    fn session_qr_size() {
        assert!(modules(&uri("laptop")) <= 45);
        assert!(modules(&uri(&"x".repeat(32))) <= 49);
        // The previous format (base64 JSON) needed 69 modules.
    }
}
