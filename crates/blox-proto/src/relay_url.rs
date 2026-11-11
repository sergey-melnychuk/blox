//! Relay URLs: normalization (§4.3) and the QR code's relay field (§5.1).

use crate::{Error, Result};

pub const DEFAULT_RELAY: &str = "https://relay.example.com";

/// Normalizes a relay URL: lowercase scheme and host, no default port, no trailing slash.
/// Query strings, fragments and user info are refused.
pub fn normalize(url: &str) -> Result<String> {
    let bad = || Error::Malformed("relay url");
    let (scheme, rest) = url.split_once("://").ok_or_else(bad)?;
    let scheme = scheme.to_ascii_lowercase();
    let default_port = match scheme.as_str() {
        "https" => "443",
        "http" => "80",
        _ => return Err(bad()),
    };
    if rest.contains(['?', '#', '@']) || rest.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(bad());
    }
    let (authority, path) = match rest.find('/') {
        Some(i) => rest.split_at(i),
        None => (rest, ""),
    };
    let (host, port) = if let Some(v6) = authority.strip_prefix('[') {
        let end = v6.find(']').ok_or_else(bad)?;
        let host = &authority[..end + 2];
        match &authority[end + 2..] {
            "" => (host, None),
            p => (host, Some(p.strip_prefix(':').ok_or_else(bad)?)),
        }
    } else {
        match authority.rsplit_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (authority, None),
        }
    };
    if host.is_empty() {
        return Err(bad());
    }
    let port = match port {
        Some(p) if p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()) => return Err(bad()),
        Some(p) if p == default_port => None,
        p => p,
    };
    let mut out = format!("{scheme}://{}", host.to_ascii_lowercase());
    if let Some(p) = port {
        out.push(':');
        out.push_str(p);
    }
    out.push_str(path.trim_end_matches('/'));
    if out.len() > 255 {
        return Err(bad());
    }
    Ok(out)
}

/// The relay as written in the QR code: `""` for the default, `host[:port][/path]` for
/// HTTPS, and the full URL for plain HTTP (debug only).
pub fn to_qr_field(normalized: &str) -> &str {
    if normalized == DEFAULT_RELAY {
        ""
    } else {
        normalized.strip_prefix("https://").unwrap_or(normalized)
    }
}

/// Resolves the QR code's relay field to a normalized URL.
pub fn from_qr_field(field: &str) -> Result<String> {
    match field {
        "" => Ok(DEFAULT_RELAY.to_owned()),
        f if f.starts_with("http://") => normalize(f),
        f if f.contains("://") => Err(Error::Malformed("relay url")),
        f => normalize(&format!("https://{f}")),
    }
}

/// The host shown to users (`relay.example.com`, `my-computer.lan:8080`).
pub fn host(normalized: &str) -> &str {
    let rest = normalized.split_once("://").map_or(normalized, |(_, r)| r);
    rest.split('/').next().unwrap_or(rest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes() {
        for (input, want) in [
            ("https://relay.example.com", "https://relay.example.com"),
            ("HTTPS://Relay.Example.COM:443/", "https://relay.example.com"),
            (
                "https://r.example.org:8443/relay/",
                "https://r.example.org:8443/relay",
            ),
            ("http://my-computer.lan:80", "http://my-computer.lan"),
            ("http://my-computer.lan:8080", "http://my-computer.lan:8080"),
            ("https://[ipv6-host]:443/x", "https://[ipv6-host]/x"),
            ("https://[ipv6-host]:9000", "https://[ipv6-host]:9000"),
        ] {
            assert_eq!(normalize(input).unwrap(), want, "{input}");
        }
        for bad in [
            "relay.example.com",
            "ftp://x",
            "https://",
            "https://x?y=1",
            "https://x#f",
            "https://u@x",
            "https://x:",
            "https://x:12a",
            "https://a b",
        ] {
            assert!(normalize(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn qr_field_roundtrip() {
        for url in [
            DEFAULT_RELAY,
            "https://r.example.org:8443/relay",
            "http://my-computer.lan:8080",
        ] {
            assert_eq!(from_qr_field(to_qr_field(url)).unwrap(), url);
        }
        assert_eq!(to_qr_field(DEFAULT_RELAY), "");
        assert!(from_qr_field("ftp://x").is_err());
        assert_eq!(host("http://my-computer.lan:8080/p"), "my-computer.lan:8080");
        assert_eq!(host(DEFAULT_RELAY), "relay.example.com");
    }
}
