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
