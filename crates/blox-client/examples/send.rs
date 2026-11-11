//! Connects to a phone (or the mock keystore) and sends one request.
//!
//! ```sh
//! cargo run -p blox-client --example send -- --relay http://localhost:8080 \
//!     --chain 31337 --to 0x70997970C51812dc3A010C7d01b50e0d17dc79C8 --value 1000000000000000
//! cargo run -p blox-client --example send -- --relay http://localhost:8080 --message hello
//! cargo run -p blox-client --example send -- --relay http://localhost:8080 --disconnect
//! ```
//!
//! The connection is stored in `--store` (default `blox-example.json`), so later runs need no
//! QR code. With `--print-uri` the QR string is printed on its own line (for the mock
//! keystore's stdin) instead of being drawn.

use std::sync::Arc;

use blox_client::{Config, FileStore, Requester, TxCall};
use blox_evm::{Address, U256};
use qrcode::QrCode;
use qrcode::render::unicode::Dense1x2;

fn arg(name: &str) -> Option<String> {
    let mut it = std::env::args().skip_while(|a| a != name);
    it.next()?;
    it.next()
}

fn flag(name: &str) -> bool {
    std::env::args().any(|a| a == name)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let relay = arg("--relay").unwrap_or_else(|| "https://relay.example.com".into());
    let store = arg("--store").unwrap_or_else(|| "blox-example.json".into());
    let print_uri = flag("--print-uri");
    let on_qr = Arc::new(move |uri: &str| {
        if print_uri {
            println!("{uri}");
        } else {
            let qr = QrCode::new(uri.as_bytes()).expect("fits in a QR code");
            let art = qr
                .render::<Dense1x2>()
                .dark_color(Dense1x2::Light)
                .light_color(Dense1x2::Dark)
                .quiet_zone(true)
                .build();
            eprintln!("{art}\nScan with the Blox app (120 s).");
        }
    });
    let mut cfg = Config::new(&relay, "Blox example");
    cfg.origin_url = Some("cli://blox-example".into());
    let r = Requester::new(cfg, Arc::new(FileStore::new(store)), on_qr)?;

    if flag("--disconnect") {
        r.disconnect().await?;
        eprintln!("Disconnected.");
        return Ok(());
    }
    let account = r.connect().await?;
    eprintln!("Connected as {account}");
    let chain: u64 = arg("--chain").map_or(Ok(1), |c| c.parse())?;
    if let Some(m) = arg("--message") {
        let s = r.personal_sign(chain, m.as_bytes()).await?;
        println!("{}", s.signature);
    } else if let Some(to) = arg("--to") {
        let call = TxCall {
            chain,
            to: Some(to.parse::<Address>()?),
            value: arg("--value").map_or(Ok(U256::ZERO), |v| v.parse())?,
            data: Vec::new(),
        };
        eprintln!("Approve in the Blox app…");
        let sent = r.send(call).await?;
        println!("{}", sent.tx_hash);
    }
    Ok(())
}
