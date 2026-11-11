//! §13.1 gates against a local anvil: the mock keystore fills from anvil, signs and
//! broadcasts like the app. Each test skips with a message when anvil isn't installed.

use std::net::SocketAddr;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use blox_client::{Config, Error, MemoryStore, Requester, TxCall};
use blox_evm::{Address, U256};
use blox_mock_keystore::rpc::HttpRpc;
use blox_mock_keystore::{Crash, MockKeystore, Options, Signer};
use blox_proto::message::{RejectReason, SignRequest, SignResponse};
use blox_relay::{AppState, Limits, router};
use serde_json::{Value, json};

const PHRASE: &str = "test test test test test test test test test test test junk";
const CHAIN: u64 = 31337;
const BOB: Address = blox_evm::Address::new([0x42; 20]);

struct Anvil {
    child: Child,
    url: String,
}

impl Drop for Anvil {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn anvil_bin() -> Option<String> {
    if let Ok(p) = std::env::var("ANVIL") {
        return Some(p);
    }
    let home = std::env::var("HOME").unwrap_or_default();
    let foundry = format!("{home}/.foundry/bin/anvil");
    if std::path::Path::new(&foundry).exists() {
        return Some(foundry);
    }
    Command::new("anvil")
        .arg("--version")
        .output()
        .ok()
        .map(|_| "anvil".into())
}

async fn anvil(extra: &[&str]) -> Option<Anvil> {
    let Some(bin) = anvil_bin() else {
        eprintln!("skipping: anvil not found (install Foundry or set ANVIL)");
        return None;
    };
    let port = std::net::TcpListener::bind("localhost:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let child = Command::new(bin)
        .args(["--port", &port.to_string(), "--silent"])
        .args(extra)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("start anvil");
    let a = Anvil {
        child,
        url: format!("http://localhost:{port}"),
    };
    let rpc = HttpRpc::new(&a.url);
    for _ in 0..100 {
        if rpc.call_async("eth_chainId", json!([])).await.is_ok() {
            return Some(a);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("anvil did not start");
}

async fn relay() -> String {
    let listener = tokio::net::TcpListener::bind("localhost:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = router(AppState::new(Limits::default(), false))
        .into_make_service_with_connect_info::<SocketAddr>();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{addr}")
}

struct Setup {
    _anvil: Anvil,
    rpc: HttpRpc,
    ks: MockKeystore,
    r: Requester,
}

/// Anvil + relay + a mock keystore in app mode (two signers) + a requester connected to
/// signer `signer`.
async fn setup(anvil_args: &[&str], signer: usize) -> Option<Setup> {
    let a = anvil(anvil_args).await?;
    let base = relay().await;
    let signers = vec![
        Signer::from_mnemonic("Main", PHRASE, 0),
        Signer::from_mnemonic("Savings", PHRASE, 1),
    ];
    let ks = MockKeystore::app(signers, &[(CHAIN, &a.url)], Options::default());
    let k = ks.clone();
    let r = Requester::new(
        Config::new(&base, "Example"),
        Arc::new(MemoryStore::default()),
        Arc::new(move |uri| {
            let (k, uri) = (k.clone(), uri.to_owned());
            tokio::spawn(async move { k.accept(&uri, signer, Duration::from_secs(86400)).await });
        }),
    )
    .unwrap();
    r.connect().await.unwrap();
    Some(Setup {
        rpc: HttpRpc::new(&a.url),
        _anvil: a,
        ks,
        r,
    })
}

fn pay(value: u64, data: &[u8]) -> TxCall {
    TxCall {
        chain: CHAIN,
        to: Some(BOB),
        value: U256::from(value),
        data: data.to_vec(),
    }
}

async fn tx(rpc: &HttpRpc, hash: impl std::fmt::Display) -> Value {
    rpc.call_async("eth_getTransactionByHash", json!([hash.to_string()]))
        .await
        .unwrap()
}

/// The receipt, waiting briefly for anvil to mine.
async fn receipt(rpc: &HttpRpc, hash: impl std::fmt::Display) -> Value {
    let hash = hash.to_string();
    for _ in 0..50 {
        let r = rpc
            .call_async("eth_getTransactionReceipt", json!([hash]))
            .await
            .unwrap();
        if !r.is_null() {
            return r;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Value::Null
}

#[tokio::test(flavor = "multi_thread")]
async fn send_is_filled_signed_broadcast_and_mined() {
    let Some(s) = setup(&[], 0).await else { return };
    let sent = s.r.send(pay(1_000_000, &[0xca, 0xfe])).await.unwrap();
    assert_eq!(sent.account, s.ks.signer(0).address());
    let rc = receipt(&s.rpc, sent.tx_hash).await;
    assert_eq!(rc["status"], "0x1");
    let t = tx(&s.rpc, sent.tx_hash).await;
    assert_eq!(
        t["to"].as_str().unwrap().to_lowercase(),
        format!("{BOB:#x}")
    );
    assert_eq!(t["value"], "0xf4240");
    assert_eq!(t["input"], "0xcafe");
    assert_eq!(t["type"], "0x2");
    assert_eq!(
        t["from"].as_str().unwrap().to_lowercase(),
        s.ks.signer(0).address().to_lowercase()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn several_sends_get_consecutive_nonces() {
    let Some(s) = setup(&[], 0).await else { return };
    let mut nonces = Vec::new();
    for i in 0..3 {
        let sent = s.r.send(pay(i + 1, &[])).await.unwrap();
        assert_eq!(receipt(&s.rpc, sent.tx_hash).await["status"], "0x1");
        nonces.push(
            tx(&s.rpc, sent.tx_hash).await["nonce"]
                .as_str()
                .unwrap()
                .to_owned(),
        );
    }
    assert_eq!(nonces, ["0x0", "0x1", "0x2"]);
}

#[tokio::test(flavor = "multi_thread")]
async fn sign_tx_is_returned_not_broadcast() {
    let Some(s) = setup(&[], 0).await else { return };
    let from = s.ks.signer(0).address();
    let signed = s.r.sign_transaction(pay(7, &[])).await.unwrap();
    let count = s
        .rpc
        .call_async("eth_getTransactionCount", json!([from, "latest"]))
        .await
        .unwrap();
    assert_eq!(count, "0x0", "the keystore broadcast nothing");
    let hash = s
        .rpc
        .call_async(
            "eth_sendRawTransaction",
            json!([blox_evm::to_hex(&signed.raw)]),
        )
        .await
        .unwrap();
    assert_eq!(hash.as_str().unwrap(), blox_evm::to_hex(signed.tx_hash));
    assert_eq!(receipt(&s.rpc, signed.tx_hash).await["status"], "0x1");
}

#[tokio::test(flavor = "multi_thread")]
async fn legacy_on_a_chain_without_base_fee() {
    let Some(s) = setup(&["--hardfork", "berlin"], 0).await else {
        return;
    };
    let sent = s.r.send(pay(5, &[])).await.unwrap();
    let t = tx(&s.rpc, sent.tx_hash).await;
    assert_eq!(t["type"], "0x0");
    assert_eq!(t["chainId"], "0x7a69", "EIP-155");
    assert_eq!(receipt(&s.rpc, sent.tx_hash).await["status"], "0x1");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_reverting_call_is_would_fail_and_nothing_is_sent() {
    let Some(s) = setup(&[], 0).await else { return };
    // Init code that reverts: PUSH1 0 PUSH1 0 REVERT.
    let deploy = TxCall {
        chain: CHAIN,
        to: None,
        value: U256::ZERO,
        data: vec![0x60, 0x00, 0x60, 0x00, 0xfd],
    };
    assert!(matches!(
        s.r.send(deploy).await,
        Err(Error::Rejected(RejectReason::WouldFail))
    ));
    let n = s
        .rpc
        .call_async(
            "eth_getTransactionCount",
            json!([s.ks.signer(0).address(), "pending"]),
        )
        .await
        .unwrap();
    assert_eq!(n, "0x0");
}

#[tokio::test(flavor = "multi_thread")]
async fn no_endpoint_and_decode_failed() {
    let Some(s) = setup(&[], 0).await else { return };
    let mut other_chain = pay(1, &[]);
    other_chain.chain = 999;
    assert!(matches!(
        s.r.send(other_chain).await,
        Err(Error::Rejected(RejectReason::NoEndpoint))
    ));
    for extra in [json!({"nonce": "0x5"}), json!({"gas": "0x5208"})] {
        let mut payload = json!({"to": format!("{BOB:#x}"), "value": "0x1"});
        payload
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        let resp =
            s.r.request(SignRequest {
                chain: "eip155:31337".into(),
                kind: "evm.send".into(),
                payload,
                origin: None,
                expires_at: 0,
            })
            .await
            .unwrap();
        assert_eq!(
            resp,
            SignResponse::Rejected {
                reason: RejectReason::DecodeFailed
            }
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_connections_signer_signs() {
    let Some(s) = setup(&[], 1).await else { return };
    let sent = s.r.send(pay(1, &[])).await.unwrap();
    assert_eq!(sent.account, s.ks.signer(1).address());
    let t = tx(&s.rpc, sent.tx_hash).await;
    assert_eq!(
        t["from"].as_str().unwrap().to_lowercase(),
        s.ks.signer(1).address().to_lowercase()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn crash_after_answering_does_not_sign_twice() {
    let Some(s) = setup(&[], 0).await else { return };
    s.ks.crash_once(Crash::AfterAnswerBeforeAck);
    let sent = s.r.send(pay(1, &[])).await.unwrap();
    // "Restart": the unacknowledged request comes back and gets the stored answer.
    s.ks.go_offline();
    s.ks.go_online();
    tokio::time::sleep(Duration::from_millis(800)).await;
    assert_eq!(s.ks.handled(), 1);
    let n = s
        .rpc
        .call_async(
            "eth_getTransactionCount",
            json!([s.ks.signer(0).address(), "latest"]),
        )
        .await
        .unwrap();
    assert_eq!(n, "0x1", "one transaction only");
    assert_eq!(receipt(&s.rpc, sent.tx_hash).await["status"], "0x1");
}

#[tokio::test(flavor = "multi_thread")]
async fn crash_between_signing_and_broadcasting_answers_failed_with_the_hash() {
    let Some(s) = setup(&[], 0).await else { return };
    s.ks.crash_once(Crash::AfterSignBeforeBroadcast);
    let ks = s.ks.clone();
    let restart = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(1000)).await;
        ks.go_offline();
        ks.go_online();
    });
    let res = s.r.send(pay(1, &[])).await;
    restart.await.unwrap();
    let Err(Error::Failed { tx_hash, error }) = res else {
        panic!("expected failed, got {res:?}")
    };
    assert!(error.contains("restarted"), "{error}");
    // The requester can look the hash up: it was never broadcast.
    assert_eq!(tx(&s.rpc, tx_hash).await, Value::Null);
    // The next send reuses the nonce and goes through.
    let sent = s.r.send(pay(2, &[])).await.unwrap();
    assert_eq!(tx(&s.rpc, sent.tx_hash).await["nonce"], "0x0");
}

#[tokio::test(flavor = "multi_thread")]
async fn typed_data_on_the_chain() {
    let Some(s) = setup(&[], 0).await else { return };
    let td = json!({
        "types": {"EIP712Domain":[{"name":"name","type":"string"},{"name":"chainId","type":"uint256"}],
                  "Mail":[{"name":"contents","type":"string"}]},
        "primaryType": "Mail",
        "domain": {"name": "Blox", "chainId": CHAIN},
        "message": {"contents": "hello"}
    });
    let sig = s.r.sign_typed_data(CHAIN, td).await.unwrap();
    assert_eq!(sig.account, s.ks.signer(0).address());
    s.r.personal_sign(CHAIN, b"hello").await.unwrap();
}
