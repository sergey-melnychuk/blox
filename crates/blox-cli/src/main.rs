use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use blox_cli::{Config, DEFAULT_RELAY, qr, serve};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "blox",
    version,
    about = "Sign with your phone: a local JSON-RPC signer backed by a Blox keystore"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Serve a JSON-RPC endpoint whose signing methods go to your phone.
    Rpc(RpcArgs),
}

#[derive(clap::Args)]
struct RpcArgs {
    /// Upstream JSON-RPC for reads and broadcasts.
    #[arg(long, env = "BLOX_UPSTREAM")]
    upstream: String,
    #[arg(long, env = "BLOX_RELAY", default_value = DEFAULT_RELAY)]
    relay: String,
    #[arg(long, default_value = "localhost:8545")]
    listen: SocketAddr,
    /// Name shown on the phone (defaults to the hostname).
    #[arg(long)]
    label: Option<String>,
    /// Address to report from eth_accounts (repeatable).
    #[arg(long = "account")]
    accounts: Vec<blox_evm::Address>,
    /// Require `Authorization: Bearer <token>`.
    #[arg(long, env = "BLOX_TOKEN")]
    token: Option<String>,
    /// Browser origin allowed to call the endpoint (repeatable).
    #[arg(long = "allow-origin")]
    allow_origins: Vec<String>,
    /// Seconds a signing call may wait for approval.
    #[arg(long, default_value_t = 300)]
    timeout: u64,
    #[arg(long, default_value_t = 120)]
    join_timeout: u64,
    #[arg(long, default_value_t = 120)]
    idle_timeout: u64,
    #[arg(long, default_value_t = 1.0)]
    gas_multiplier: f64,
    /// Allow listening on a non-loopback address.
    #[arg(long)]
    i_know: bool,
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let Cmd::Rpc(a) = Cli::parse().cmd;
    if !a.listen.ip().is_loopback() && !a.i_know {
        eprintln!(
            "refusing to listen on {}: not a loopback address (pass --i-know to override)",
            a.listen
        );
        std::process::exit(2);
    }
    let label = a
        .label
        .unwrap_or_else(|| gethostname::gethostname().to_string_lossy().into_owned());
    let relay_host = a
        .relay
        .split("://")
        .nth(1)
        .unwrap_or(&a.relay)
        .trim_end_matches('/')
        .to_owned();
    let (qr_label, join) = (label.clone(), a.join_timeout);
    let on_qr = Arc::new(move |uri: &str| {
        eprintln!("\n{}", qr::render(uri));
        eprintln!("Scan with the Blox app · {qr_label} · {relay_host}");
        eprintln!("Waiting for phone… ({join} s)\n");
    });
    let cfg = Config {
        relay: a.relay,
        upstream: a.upstream,
        label,
        accounts: a.accounts,
        token: a.token,
        allow_origins: a.allow_origins,
        timeout: Duration::from_secs(a.timeout),
        join_timeout: Duration::from_secs(a.join_timeout),
        idle_timeout: Duration::from_secs(a.idle_timeout),
        gas_multiplier: a.gas_multiplier,
        state_dir: state_dir(),
        on_qr,
    };
    let listener = tokio::net::TcpListener::bind(a.listen).await?;
    eprintln!("blox rpc listening on http://{}", a.listen);
    eprintln!(
        "hint: Foundry gives up after 45 s by default; use --rpc-timeout 300, ETH_RPC_TIMEOUT=300 or eth_rpc_timeout = 300 in foundry.toml"
    );
    serve(cfg, listener).await
}

fn state_dir() -> Option<PathBuf> {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))?;
    Some(base.join("blox"))
}
