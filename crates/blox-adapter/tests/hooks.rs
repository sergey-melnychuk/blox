//! The integration points an embedding proxy (e.g. yevm-gate) relies on.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use alloy_consensus::TxEnvelope;
use alloy_eips::eip2718::Decodable2718;
use blox_adapter::{Adapter, Config, Event, Hooks, Review, RpcError, Upstream};
use blox_evm::sign::{prepare, sign, signer_from_mnemonic};
use blox_evm::tx::UnsignedTx;
use blox_mock_keystore::{Next, serve};
use blox_proto::message::{Origin, SignResponse, now};
use futures::future::BoxFuture;
use serde_json::{Value, json};

const MNEMONIC: &str = "test test test test test test test test test test test junk";
const ALICE: &str = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";

/// A chain that answers fill queries and records broadcasts.
#[derive(Default)]
struct FakeChain {
    broadcast: Mutex<Vec<(u64, String)>>,
}

impl Upstream for FakeChain {
    fn call<'a>(
        &'a self,
        chain_id: u64,
        method: &'a str,
        params: Value,
    ) -> BoxFuture<'a, Result<Value, RpcError>> {
        Box::pin(async move {
            Ok(match method {
                "eth_getTransactionCount" => json!("0x5"),
                "eth_maxPriorityFeePerGas" => json!("0x1"),
                "eth_getBlockByNumber" => json!({ "baseFeePerGas": "0x3b9aca00" }),
                "eth_estimateGas" => json!("0x5208"),
                "eth_sendRawTransaction" => {
                    self.broadcast
                        .lock()
                        .unwrap()
                        .push((chain_id, params[0].as_str().unwrap().to_owned()));
                    json!("0xhash")
                }
                m => return Err(RpcError::internal(format!("unexpected {m}"))),
            })
        })
    }
}

/// Starts a relay; every QR shown is joined by an honest auto-approving keystore.
struct TestHooks {
    qrs: Mutex<usize>,
    veto: bool,
    reviewed: Mutex<Vec<Vec<u8>>>,
    events: Mutex<Vec<Event>>,
    keystore_saw: Arc<Mutex<Vec<String>>>,
}

impl Hooks for TestHooks {
    fn show_qr(&self, uri: &str) {
        *self.qrs.lock().unwrap() += 1;
        let (uri, saw) = (uri.to_owned(), self.keystore_saw.clone());
        let signer = signer_from_mnemonic(MNEMONIC, 0).unwrap();
        tokio::spawn(async move {
            let _ = serve(&uri, move |req| {
                saw.lock()
                    .unwrap()
                    .push(req.payload["tx"].as_str().unwrap_or_default().to_owned());
                let resp = match prepare(req, &[signer.address()], now()) {
                    Ok((_, p)) => sign(&signer, p),
                    Err(reason) => SignResponse::Rejected { reason },
                };
                (resp, Next::Continue)
            })
            .await;
        });
    }

    fn before_sign<'a>(&'a self, review: Review<'a>) -> BoxFuture<'a, Result<(), RpcError>> {
        Box::pin(async move {
            if let Review::Tx { tx, .. } = review {
                self.reviewed.lock().unwrap().push(tx.encode_for_signing());
            }
            if self.veto {
                Err(RpcError::user_rejected("simulation says no"))
            } else {
                Ok(())
            }
        })
    }

    fn event(&self, e: Event) {
        self.events.lock().unwrap().push(e);
    }
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

async fn setup(veto: bool) -> (Adapter, Arc<FakeChain>, Arc<TestHooks>) {
    let chain = Arc::new(FakeChain::default());
    let hooks = Arc::new(TestHooks {
        qrs: Mutex::new(0),
        veto,
        reviewed: Mutex::default(),
        events: Mutex::default(),
        keystore_saw: Arc::default(),
    });
    let cfg = Config {
        relay: relay().await,
        label: "test".into(),
        accounts: vec![],
        timeout: Duration::from_secs(10),
        join_timeout: Duration::from_secs(5),
        idle_timeout: Duration::from_secs(30),
        gas_multiplier: 1.0,
    };
    (
        Adapter::new(cfg, chain.clone(), hooks.clone()),
        chain,
        hooks,
    )
}

fn send(to: &str) -> Value {
    json!([{ "from": ALICE, "to": to, "value": "0x1" }])
}

#[tokio::test]
async fn reviewed_bytes_are_exactly_what_is_signed_and_broadcast() {
    let (adapter, chain, hooks) = setup(false).await;
    let res = adapter
        .handle(1, "eth_sendTransaction", &send(ALICE), Origin::default())
        .await
        .unwrap();
    assert_eq!(res.unwrap(), json!("0xhash"));

    let reviewed = hooks.reviewed.lock().unwrap().clone();
    assert_eq!(reviewed.len(), 1);
    // Fully filled before review: nonce, gas and fees come from the chain.
    let tx = UnsignedTx::decode(&reviewed[0]).unwrap();
    assert_eq!((tx.chain_id(), tx.nonce()), (1, 5));
    // The phone saw the same bytes...
    assert_eq!(
        *hooks.keystore_saw.lock().unwrap(),
        [blox_evm::to_hex(&reviewed[0])]
    );
    // ...and the broadcast transaction is those bytes, signed.
    let (chain_id, raw) = chain.broadcast.lock().unwrap()[0].clone();
    assert_eq!(chain_id, 1);
    let env = TxEnvelope::decode_2718(&mut hex(&raw).as_slice()).unwrap();
    assert_eq!(
        UnsignedTx::from_envelope(&env)
            .unwrap()
            .encode_for_signing(),
        reviewed[0]
    );
    assert!(
        hooks
            .events
            .lock()
            .unwrap()
            .contains(&Event::AccountSeen(ALICE.parse().unwrap()))
    );
}

#[tokio::test]
async fn veto_stops_before_the_phone_is_involved() {
    let (adapter, chain, hooks) = setup(true).await;
    let err = adapter
        .handle(1, "eth_sendTransaction", &send(ALICE), Origin::default())
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(err, RpcError::user_rejected("simulation says no"));
    assert_eq!(*hooks.qrs.lock().unwrap(), 0, "no session should be opened");
    assert!(chain.broadcast.lock().unwrap().is_empty());
}

#[tokio::test]
async fn one_session_serves_every_chain() {
    let (adapter, chain, hooks) = setup(false).await;
    for chain_id in [1, 8453, 1] {
        adapter
            .handle(
                chain_id,
                "eth_sendTransaction",
                &send(ALICE),
                Origin::default(),
            )
            .await
            .unwrap()
            .unwrap();
    }
    assert_eq!(*hooks.qrs.lock().unwrap(), 1);
    let chains: Vec<u64> = chain
        .broadcast
        .lock()
        .unwrap()
        .iter()
        .map(|(c, _)| *c)
        .collect();
    assert_eq!(chains, [1, 8453, 1]);
    // Nonces are tracked per chain: chain 1 goes 5 then 6.
    let nonces: Vec<u64> = hooks
        .reviewed
        .lock()
        .unwrap()
        .iter()
        .map(|b| UnsignedTx::decode(b).unwrap().nonce())
        .collect();
    assert_eq!(nonces, [5, 5, 6]);
}

#[tokio::test]
async fn non_signing_methods_are_left_to_the_caller() {
    let (adapter, _, _) = setup(false).await;
    assert!(
        adapter
            .handle(1, "eth_blockNumber", &json!([]), Origin::default())
            .await
            .is_none()
    );
    let refused = adapter
        .handle(1, "eth_sign", &json!([ALICE, "0x00"]), Origin::default())
        .await
        .unwrap();
    assert_eq!(refused.unwrap_err().code, 4200);
}

fn hex(s: &str) -> Vec<u8> {
    let s = s.trim_start_matches("0x");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
