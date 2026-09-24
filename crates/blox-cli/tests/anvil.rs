//! M2 gate (§13.1–13.2): real tools → `blox rpc` → relay → mock keystore → anvil.
//! Needs `anvil` (and `cast` / `forge` for those tests) on PATH; skips otherwise.

use std::net::SocketAddr;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use alloy_primitives::TxKind;
use blox_cli::{Config, serve};
use blox_evm::sign::{prepare, sign, signer_from_mnemonic};
use blox_evm::tx::UnsignedTx;
use blox_mock_keystore::{Next, serve as keystore};
use blox_proto::message::{SignRequest, SignResponse, now};
use serde_json::{Value, json};

const MNEMONIC: &str = "test test test test test test test test test test test junk";
const ALICE: &str = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";
const BOB: &str = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";

fn have(bin: &str) -> bool {
    Command::new(bin)
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok()
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("localhost:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

struct Anvil(Child, String);

impl Drop for Anvil {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

async fn anvil() -> Anvil {
    let port = free_port();
    let mut child = Command::new("anvil")
        .args(["--port", &port.to_string(), "--silent"])
        .stdout(Stdio::null())
        .spawn()
        .expect("spawn anvil");
    let url = format!("http://localhost:{port}");
    for _ in 0..100 {
        if rpc_raw(&url, "eth_chainId", json!([])).await.is_ok() {
            return Anvil(child, url);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let _ = child.kill();
    let _ = child.wait();
    panic!("anvil did not start");
}

async fn rpc_raw(url: &str, method: &str, params: Value) -> reqwest::Result<Value> {
    reqwest::Client::new()
        .post(url)
        .json(&json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}))
        .send()
        .await?
        .json()
        .await
}

async fn relay() -> String {
    let listener = tokio::net::TcpListener::bind("localhost:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = blox_relay::router(blox_relay::AppState::new(
        blox_relay::Limits::default(),
        false,
    ))
    .into_make_service_with_connect_info::<SocketAddr>();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{addr}")
}

type Handler = Arc<dyn Fn(&SignRequest) -> SignResponse + Send + Sync>;

/// An honest auto-approving keystore holding anvil account 0.
fn honest() -> Handler {
    let signer = signer_from_mnemonic(MNEMONIC, 0).unwrap();
    Arc::new(move |req| match prepare(req, &[signer.address()], now()) {
        Ok((_, p)) => sign(&signer, p),
        Err(reason) => SignResponse::Rejected { reason },
    })
}

struct Harness {
    _anvil: Anvil,
    anvil: String,
    rpc: String,
    sessions: Arc<AtomicUsize>,
    nonces: Arc<Mutex<Vec<u64>>>,
}

async fn harness(handler: Handler, token: Option<&str>) -> Harness {
    let anvil = anvil().await;
    let relay = relay().await;
    let sessions = Arc::new(AtomicUsize::new(0));
    let nonces = Arc::new(Mutex::new(Vec::new()));
    let (s, n) = (sessions.clone(), nonces.clone());
    let on_qr = Arc::new(move |uri: &str| {
        s.fetch_add(1, Ordering::SeqCst);
        let (uri, n, h) = (uri.to_owned(), n.clone(), handler.clone());
        tokio::spawn(async move {
            let _ = keystore(&uri, move |req| {
                if let Some(tx) = req.payload.get("tx").and_then(Value::as_str) {
                    let bytes = hex_decode(tx);
                    n.lock()
                        .unwrap()
                        .push(UnsignedTx::decode(&bytes).unwrap().nonce());
                }
                (h(req), Next::Continue)
            })
            .await;
        });
    });
    let listener = tokio::net::TcpListener::bind("localhost:0").await.unwrap();
    let rpc = format!("http://localhost:{}", listener.local_addr().unwrap().port());
    let cfg = Config {
        relay,
        upstream: anvil.1.clone(),
        label: "test".into(),
        accounts: vec![],
        token: token.map(Into::into),
        allow_origins: vec![],
        timeout: Duration::from_secs(60),
        join_timeout: Duration::from_secs(10),
        idle_timeout: Duration::from_secs(60),
        gas_multiplier: 1.0,
        state_dir: None,
        on_qr,
    };
    tokio::spawn(async move { serve(cfg, listener).await.unwrap() });
    Harness {
        anvil: anvil.1.clone(),
        _anvil: anvil,
        rpc,
        sessions,
        nonces,
    }
}

fn hex_decode(s: &str) -> Vec<u8> {
    let s = s.trim_start_matches("0x");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

async fn call(url: &str, method: &str, params: Value) -> Value {
    rpc_raw(url, method, params).await.unwrap()
}

async fn nonce_now(url: &str) -> u64 {
    let v = call(url, "eth_getTransactionCount", json!([ALICE, "latest"])).await;
    u64::from_str_radix(v["result"].as_str().unwrap().trim_start_matches("0x"), 16).unwrap()
}

/// Mined nonce, polling briefly: anvil returns tx hashes before the block is mined.
async fn nonce(url: &str, expect: u64) -> u64 {
    for _ in 0..50 {
        let n = nonce_now(url).await;
        if n == expect {
            return n;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    nonce_now(url).await
}

#[tokio::test]
async fn cast_send() {
    if !have("anvil") || !have("cast") {
        return eprintln!("skipped: anvil/cast not on PATH");
    }
    let h = harness(honest(), None).await;
    let out = tokio::process::Command::new("cast")
        .args([
            "send",
            "--unlocked",
            "--from",
            ALICE,
            BOB,
            "--value",
            "1ether",
            "--rpc-url",
            &h.rpc,
            "--json",
        ])
        .env("ETH_RPC_TIMEOUT", "300")
        .output()
        .await
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let receipt: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(receipt["status"], "0x1");
    assert_eq!(nonce(&h.anvil, 1).await, 1);
}

#[tokio::test]
async fn forge_script_ten_transactions_one_session_in_nonce_order() {
    if !have("anvil") || !have("forge") {
        return eprintln!("skipped: anvil/forge not on PATH");
    }
    let h = harness(honest(), None).await;
    let dir = std::env::temp_dir().join(format!("blox-forge-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("S.s.sol"),
        r#"// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract C { uint x; function set(uint v) external { x = v; } }
interface Vm { function startBroadcast() external; function stopBroadcast() external; }
contract S {
    Vm constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    function run() external {
        vm.startBroadcast();
        C c = new C();
        for (uint i = 0; i < 9; i++) c.set(i);
        vm.stopBroadcast();
    }
}
"#,
    )
    .unwrap();
    let out = tokio::process::Command::new("forge")
        .args([
            "script",
            "S.s.sol:S",
            "--unlocked",
            "--sender",
            ALICE,
            "--rpc-url",
            &h.rpc,
            "--broadcast",
            "--rpc-timeout",
            "300",
        ])
        .current_dir(&dir)
        .output()
        .await
        .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        out.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(nonce(&h.anvil, 10).await, 10);
    assert_eq!(h.sessions.load(Ordering::SeqCst), 1, "expected one session");
    assert_eq!(
        *h.nonces.lock().unwrap(),
        (0..10).collect::<Vec<_>>(),
        "phone saw nonces out of order"
    );
}

/// Stands in for viem / ethers: the calls a JS wallet client makes.
#[tokio::test]
async fn json_rpc_signing_methods() {
    if !have("anvil") {
        return eprintln!("skipped: anvil not on PATH");
    }
    let h = harness(honest(), None).await;

    let sig = call(&h.rpc, "personal_sign", json!(["0x68656c6c6f", ALICE])).await;
    assert_eq!(sig["result"].as_str().unwrap().len(), 132, "{sig}");

    let typed = json!({
        "types": {"EIP712Domain":[{"name":"name","type":"string"},{"name":"chainId","type":"uint256"}],
                  "Mail":[{"name":"contents","type":"string"}]},
        "primaryType": "Mail", "domain": {"name":"Blox","chainId":31337}, "message": {"contents":"hi"}
    });
    let sig = call(
        &h.rpc,
        "eth_signTypedData_v4",
        json!([ALICE, typed.to_string()]),
    )
    .await;
    assert_eq!(sig["result"].as_str().unwrap().len(), 132, "{sig}");

    // Legacy, 2930 and 1559, with the adapter filling nonce, gas and fees.
    let legacy = json!({"from": ALICE, "to": BOB, "value": "0x1", "gasPrice": "0x77359400"});
    let t2930 = json!({"from": ALICE, "to": BOB, "value": "0x1", "gasPrice": "0x77359400", "accessList": []});
    let t1559 = json!({"from": ALICE, "to": BOB, "value": "0x1"});
    for tx in [legacy, t2930, t1559] {
        let res = call(&h.rpc, "eth_sendTransaction", json!([tx])).await;
        assert!(
            res["result"].as_str().is_some_and(|h| h.len() == 66),
            "{res}"
        );
    }
    assert_eq!(nonce(&h.anvil, 3).await, 3);

    let raw = call(
        &h.rpc,
        "eth_signTransaction",
        json!([{"from": ALICE, "to": BOB, "value": "0x1"}]),
    )
    .await;
    assert!(raw["result"].as_str().unwrap().starts_with("0x02"), "{raw}");
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        nonce_now(&h.anvil).await,
        3,
        "eth_signTransaction must not broadcast"
    );

    let refused = call(&h.rpc, "eth_sign", json!([ALICE, "0x00"])).await;
    assert_eq!(refused["error"]["code"], 4200);
    let bad = call(
        &h.rpc,
        "eth_sendTransaction",
        json!([{"from": ALICE, "input": "0x01", "data": "0x02"}]),
    )
    .await;
    assert_eq!(bad["error"]["code"], -32602);

    let accounts = call(&h.rpc, "eth_accounts", json!([])).await;
    assert_eq!(accounts["result"], json!([ALICE.to_lowercase()]));
    let forwarded = call(&h.rpc, "eth_blockNumber", json!([])).await;
    assert!(forwarded["result"].is_string());
}

#[tokio::test]
async fn substituted_transaction_is_caught_and_not_broadcast() {
    if !have("anvil") {
        return eprintln!("skipped: anvil not on PATH");
    }
    // A malicious keystore: signs a transaction to a different recipient.
    let signer = signer_from_mnemonic(MNEMONIC, 0).unwrap();
    let evil: Handler = Arc::new(move |req| {
        let (_, prepared) = prepare(req, &[signer.address()], now()).unwrap();
        let blox_evm::sign::Prepared::Tx(UnsignedTx::Eip1559(mut tx)) = prepared else {
            panic!()
        };
        tx.to = TxKind::Call(
            "0x000000000000000000000000000000000000dEaD"
                .parse()
                .unwrap(),
        );
        sign(
            &signer,
            blox_evm::sign::Prepared::Tx(UnsignedTx::Eip1559(tx)),
        )
    });
    let h = harness(evil, None).await;
    let res = call(
        &h.rpc,
        "eth_sendTransaction",
        json!([{"from": ALICE, "to": BOB, "value": "0x1"}]),
    )
    .await;
    assert_eq!(
        res["error"]["message"], "signer response failed verification",
        "{res}"
    );
    assert_eq!(nonce(&h.anvil, 0).await, 0);
}

async fn send(rb: reqwest::RequestBuilder) -> u16 {
    let body = json!({"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]});
    rb.json(&body).send().await.unwrap().status().as_u16()
}

#[tokio::test]
async fn local_endpoint_hardening() {
    if !have("anvil") {
        return eprintln!("skipped: anvil not on PATH");
    }
    let h = harness(honest(), Some("s3cret")).await;
    let port = h.rpc.rsplit(':').next().unwrap();
    let c = reqwest::Client::new();

    assert_eq!(send(c.post(&h.rpc)).await, 401, "token required");
    assert_eq!(send(c.post(&h.rpc).bearer_auth("s3cret")).await, 200);
    assert_eq!(
        send(
            c.post(&h.rpc)
                .bearer_auth("s3cret")
                .header("host", format!("evil.example:{port}"))
        )
        .await,
        403
    );
    assert_eq!(
        send(
            c.post(&h.rpc)
                .bearer_auth("s3cret")
                .header("origin", "https://evil.example")
        )
        .await,
        403
    );
}
