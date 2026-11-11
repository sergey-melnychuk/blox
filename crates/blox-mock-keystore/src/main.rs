//! A runnable mock keystore for local runs and the SDK's tests (PLAN.md 4.4).
//!
//! Reads `BLOX:` offer URIs on stdin, one per line, connects each to the chosen signer,
//! and answers requests like the app would with automatic approval (app mode). Writes JSON
//! lines on stdout: `{"ready": …}`, then `{"connected": …}` or `{"error": …}` per offer.

use std::io::Write as _;
use std::time::Duration;

use blox_mock_keystore::{MockKeystore, Options, Signer};
use serde_json::json;
use tokio::io::{AsyncBufReadExt, BufReader};

const ANVIL_PHRASE: &str = "test test test test test test test test test test test junk";

const USAGE: &str = "usage: blox-mock-keystore [--mnemonic PHRASE] [--signers N] [--signer I]
                          [--endpoint CHAIN_ID=URL]... [--days D]
Reads BLOX: URIs on stdin; answers requests with automatic approval.
Defaults: anvil's test mnemonic, 2 signers, signer 0, 30 days, no endpoints.";

struct Args {
    mnemonic: String,
    signers: u32,
    signer: usize,
    endpoints: Vec<(u64, String)>,
    days: u64,
}

fn parse() -> Result<Args, String> {
    let mut a = Args {
        mnemonic: ANVIL_PHRASE.into(),
        signers: 2,
        signer: 0,
        endpoints: vec![],
        days: 30,
    };
    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        let mut value = || it.next().ok_or(format!("{flag} needs a value"));
        match flag.as_str() {
            "--mnemonic" => a.mnemonic = value()?,
            "--signers" => a.signers = value()?.parse().map_err(|_| "--signers")?,
            "--signer" => a.signer = value()?.parse().map_err(|_| "--signer")?,
            "--days" => a.days = value()?.parse().map_err(|_| "--days")?,
            "--endpoint" => {
                let v = value()?;
                let (chain, url) = v.split_once('=').ok_or("--endpoint CHAIN_ID=URL")?;
                a.endpoints.push((
                    chain.parse().map_err(|_| "--endpoint chain id")?,
                    url.into(),
                ));
            }
            "-h" | "--help" => return Err(USAGE.into()),
            other => return Err(format!("unknown argument {other}\n{USAGE}")),
        }
    }
    if a.signer >= a.signers as usize {
        return Err("--signer must be below --signers".into());
    }
    Ok(a)
}

fn emit(v: serde_json::Value) {
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "{v}");
    let _ = out.flush();
}

#[tokio::main]
async fn main() {
    let a = match parse() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(2);
        }
    };
    let signers: Vec<Signer> = (0..a.signers)
        .map(|i| Signer::from_mnemonic(&format!("Signer {i}"), &a.mnemonic, i))
        .collect();
    let addresses: Vec<String> = signers.iter().map(Signer::address).collect();
    let endpoints: Vec<(u64, &str)> = a.endpoints.iter().map(|(c, u)| (*c, u.as_str())).collect();
    let ks = MockKeystore::app(signers, &endpoints, Options::default());
    emit(json!({ "ready": { "signers": addresses } }));

    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        let uri = line.trim().to_owned();
        if uri.is_empty() {
            continue;
        }
        let ks = ks.clone();
        let lifetime = Duration::from_secs(a.days * 86400);
        let signer = a.signer;
        tokio::spawn(async move {
            match ks.accept(&uri, signer, lifetime).await {
                Ok(c) => emit(json!({ "connected": { "account": c.account, "label": c.label } })),
                Err(e) => emit(json!({ "error": e.to_string() })),
            }
        });
    }
    // stdin closed: keep serving until killed.
    std::future::pending::<()>().await;
}
