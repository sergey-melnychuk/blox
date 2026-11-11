//! Typed requester calls with their checks (§9.5), for message kinds (no chain needed).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use blox_client::{Config, Error, MemoryStore, Requester};
use blox_evm::keystore::{Approved, approve, rejected, review};
use blox_mock_keystore::{Handler, MockKeystore, Signer, handler};
use blox_proto::message::RejectReason;
use blox_relay::{AppState, Limits, router};

const PHRASE: &str = "test test test test test test test test test test test junk";

async fn relay() -> String {
    let listener = tokio::net::TcpListener::bind("localhost:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = router(AppState::new(Limits::default(), false))
        .into_make_service_with_connect_info::<SocketAddr>();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{addr}")
}

/// Signs messages like the app would (review → approve), optionally with the wrong key.
fn signing(liar: bool) -> Handler {
    handler(move |ctx| {
        let key = if liar {
            blox_evm::PrivateKeySigner::random()
        } else {
            ctx.signer.key.clone()
        };
        let rv = review(
            &ctx.request,
            ctx.ts,
            ctx.now,
            (ctx.signer.key.address(), &ctx.signer.label),
            |_| None,
            |_| None,
        );
        Some(match rv {
            Ok(rv) => match approve(&key, &rv) {
                Approved::Answer(a) => a,
                Approved::Broadcast { .. } => unreachable!("no endpoint"),
            },
            Err(_) => rejected(RejectReason::DecodeFailed),
        })
    })
}

async fn connected(h: Handler) -> (Requester, MockKeystore) {
    let base = relay().await;
    let ks = MockKeystore::new(vec![Signer::from_mnemonic("Main", PHRASE, 0)], h);
    let k = ks.clone();
    let r = Requester::new(
        Config::new(&base, "Example"),
        Arc::new(MemoryStore::default()),
        Arc::new(move |uri| {
            let (k, uri) = (k.clone(), uri.to_owned());
            tokio::spawn(async move { k.accept(&uri, 0, Duration::from_secs(86400)).await });
        }),
    )
    .unwrap();
    r.connect().await.unwrap();
    (r, ks)
}

fn typed() -> serde_json::Value {
    serde_json::json!({
        "types": {"EIP712Domain":[{"name":"name","type":"string"},{"name":"chainId","type":"uint256"}],
                  "Mail":[{"name":"contents","type":"string"}]},
        "primaryType": "Mail",
        "domain": {"name": "Blox", "chainId": 31337},
        "message": {"contents": "hello"}
    })
}

#[tokio::test]
async fn message_signatures_are_checked() {
    let (r, ks) = connected(signing(false)).await;
    let s = r.personal_sign(31337, b"hello").await.unwrap();
    assert_eq!(s.account, ks.signer(0).address());
    assert_eq!(s.signature.len(), 132);
    r.sign_typed_data(31337, typed()).await.unwrap();
    // A typed-data chain that doesn't match the request's chain is refused on the phone.
    assert!(matches!(
        r.sign_typed_data(1, typed()).await,
        Err(Error::Rejected(RejectReason::DecodeFailed))
    ));
}

#[tokio::test]
async fn a_lying_keystore_is_caught() {
    let (r, _) = connected(signing(true)).await;
    assert!(matches!(
        r.personal_sign(31337, b"hello").await,
        Err(Error::BadResponse(_))
    ));
}

#[tokio::test]
async fn rejections_surface_as_errors() {
    let (r, _) = connected(handler(|_| Some(rejected(RejectReason::User)))).await;
    assert!(matches!(
        r.personal_sign(31337, b"x").await,
        Err(Error::Rejected(RejectReason::User))
    ));
}
