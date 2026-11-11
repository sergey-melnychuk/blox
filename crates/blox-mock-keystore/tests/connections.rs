//! Connections through a real relay (PLAN.md 3.6; BLOX.md §13.1–§13.2).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use blox_client::{Config, ConnectionStore, Error, MemoryStore, RelayClient, Requester, WriteAuth};
use blox_mock_keystore::{Handler, MockKeystore, Options, Signer, handler};
use blox_proto::api::ErrorCode;
use blox_proto::connection::{ConnectAttempt, Keys};
use blox_proto::envelope;
use blox_proto::message::{SignRequest, SignResponse};
use blox_relay::{AppState, Limits, router};
use tokio::sync::mpsc;

const PHRASE: &str = "test test test test test test test test test test test junk";
const DAY: Duration = Duration::from_secs(86400);

async fn relay_with(limits: Limits) -> String {
    let listener = tokio::net::TcpListener::bind("localhost:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let state = AppState::new(limits, false);
    tokio::spawn(blox_relay::sweeper(state.clone()));
    let app = router(state).into_make_service_with_connect_info::<SocketAddr>();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{addr}")
}

async fn relay() -> String {
    relay_with(Limits::default()).await
}

fn signers(n: u32) -> Vec<Signer> {
    (0..n)
        .map(|i| Signer::from_mnemonic(&format!("Signer {i}"), PHRASE, i))
        .collect()
}

/// Answers `personal_sign` with the message itself as the "signature", so each caller
/// can tell its own response apart.
fn echo() -> Handler {
    handler(|ctx| {
        Some(SignResponse::Signed {
            account: format!("{}:{}", ctx.request.chain, ctx.signer.address()),
            signature: ctx.request.payload["message"].as_str().unwrap().to_owned(),
        })
    })
}

fn req(msg: &str) -> SignRequest {
    SignRequest {
        chain: "eip155:31337".into(),
        kind: "evm.personal_sign".into(),
        payload: serde_json::json!({ "message": format!("0x{}", hex(msg)) }),
        origin: None,
        expires_at: 0,
    }
}

fn hex(s: &str) -> String {
    s.bytes().map(|b| format!("{b:02x}")).collect()
}

fn signature(r: &SignResponse) -> &str {
    match r {
        SignResponse::Signed { signature, .. } => signature,
        other => panic!("unexpected {other:?}"),
    }
}

/// A requester whose QR callback hands the offer to `ks` for `signer`.
fn requester(base: &str, store: &MemoryStore, ks: &MockKeystore, signer: usize) -> Requester {
    requester_cfg(Config::new(base, "Example"), store, ks, signer)
}

fn requester_cfg(cfg: Config, store: &MemoryStore, ks: &MockKeystore, signer: usize) -> Requester {
    let ks = ks.clone();
    Requester::new(
        cfg,
        Arc::new(store.clone()),
        Arc::new(move |uri| {
            let (ks, uri) = (ks.clone(), uri.to_owned());
            tokio::spawn(async move { ks.accept(&uri, signer, 30 * DAY).await });
        }),
    )
    .unwrap()
}

/// A requester that must not show a QR code (it has a stored connection).
fn no_qr(base: &str, store: &MemoryStore) -> Requester {
    Requester::new(
        Config::new(base, "Example"),
        Arc::new(store.clone()),
        Arc::new(|_| panic!("no QR code expected")),
    )
    .unwrap()
}

async fn eventually(what: &str, f: impl Fn() -> bool) {
    for _ in 0..100 {
        if f() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("timed out waiting for {what}");
}

/// `connect()` returns once the requester has posted `bound`; the keystore records the
/// connection when its reader handles it, a moment later.
async fn recorded(ks: &MockKeystore, n: usize) {
    eventually("the keystore to record the connection", || {
        ks.connections().len() == n
    })
    .await;
}

#[tokio::test]
async fn connect_request_and_restart_from_the_store() {
    let base = relay().await;
    let ks = MockKeystore::new(signers(1), echo());
    let store = MemoryStore::default();
    let r = requester(&base, &store, &ks, 0);
    assert_eq!(r.connect().await.unwrap(), ks.signer(0).address());
    recorded(&ks, 1).await;
    assert_eq!(ks.connections().len(), 1);
    assert_eq!(ks.connections()[0].label, "Example");
    let resp = r.request(req("hello")).await.unwrap();
    assert_eq!(signature(&resp), format!("0x{}", hex("hello")));

    // The login proof verifies against the ticket (here the requester's own random one).
    let (statement, proof_sig) = r.connection_proof().await.unwrap();
    let nonce = blox_proto::statement::field(&statement, "Nonce")
        .unwrap()
        .to_owned();
    blox_client::verify_connection(
        &ks.signer(0).address(),
        &statement,
        &proof_sig,
        &blox_proto::ident::Ticket::parse(&nonce).unwrap(),
        r.relay().now(),
    )
    .unwrap();

    // A new requester over the same store needs no QR code.
    let again = no_qr(&base, &store);
    let resp = again.request(req("again")).await.unwrap();
    assert_eq!(signature(&resp), format!("0x{}", hex("again")));
    assert_eq!(ks.handled(), 2);
}

#[tokio::test]
async fn connections_and_tabs_are_isolated() {
    let base = relay().await;
    let ks = MockKeystore::new(signers(2), echo());
    let (sa, sb) = (MemoryStore::default(), MemoryStore::default());
    let a = requester(&base, &sa, &ks, 0);
    let b = requester(&base, &sb, &ks, 1);
    a.connect().await.unwrap();
    assert_eq!(b.connect().await.unwrap(), ks.signer(1).address());
    let (ra, rb) = tokio::join!(a.request(req("aa")), b.request(req("bb")));
    assert_eq!(signature(&ra.unwrap()), format!("0x{}", hex("aa")));
    assert_eq!(signature(&rb.unwrap()), format!("0x{}", hex("bb")));

    // Two "tabs" sharing one connection: both in flight, each gets only its own answer.
    let tab = no_qr(&base, &sa);
    let (r1, r2) = tokio::join!(a.request(req("tab1")), tab.request(req("tab2")));
    assert_eq!(signature(&r1.unwrap()), format!("0x{}", hex("tab1")));
    assert_eq!(signature(&r2.unwrap()), format!("0x{}", hex("tab2")));
}

#[tokio::test]
async fn abandoned_requests_are_cancelled() {
    let base = relay().await;
    let ks = MockKeystore::new(signers(1), handler(|_| None)); // the user never acts
    let store = MemoryStore::default();
    let r = Arc::new(requester(&base, &store, &ks, 0));
    r.connect().await.unwrap();

    let mut short = req("x");
    short.expires_at = r.relay().now() + 2;
    assert!(matches!(r.request(short).await, Err(Error::Timeout)));
    eventually("the timed-out request to be withdrawn", || {
        ks.open_requests() == 0
    })
    .await;

    // A caller that drops the call (a closed tab) withdraws it too.
    let r2 = r.clone();
    let call = tokio::spawn(async move { r2.request(req("y")).await });
    eventually("the request to reach the keystore", || {
        ks.open_requests() == 1
    })
    .await;
    call.abort();
    eventually("the dropped request to be withdrawn", || {
        ks.open_requests() == 0
    })
    .await;
}

#[tokio::test]
async fn disconnect_from_the_requester() {
    let base = relay().await;
    let ks = MockKeystore::new(signers(1), echo());
    let store = MemoryStore::default();
    let r = requester(&base, &store, &ks, 0);
    r.connect().await.unwrap();
    let copy = MemoryStore::default();
    copy.save(&store.load().unwrap().unwrap()).unwrap();

    r.disconnect().await.unwrap();
    assert!(store.load().unwrap().is_none());
    eventually("the keystore to drop the connection", || {
        ks.connections().is_empty()
    })
    .await;
    // A leftover copy of the connection is refused by the relay.
    let stale = no_qr(&base, &copy);
    assert!(matches!(
        stale.request(req("x")).await,
        Err(Error::Disconnected)
    ));
    assert!(copy.load().unwrap().is_none());
}

#[tokio::test]
async fn disconnect_from_the_keystore() {
    let base = relay().await;
    let ks = MockKeystore::new(signers(1), echo());
    let store = MemoryStore::default();
    let r = requester(&base, &store, &ks, 0);
    r.connect().await.unwrap();
    recorded(&ks, 1).await;
    let id = ks.connections()[0].id;
    ks.disconnect(&id).await.unwrap();
    assert!(matches!(
        r.request(req("x")).await,
        Err(Error::Disconnected)
    ));
    assert!(store.load().unwrap().is_none());
}

#[tokio::test]
async fn a_ticket_works_once() {
    let base = relay().await;
    let ks1 = MockKeystore::new(signers(1), echo());
    let ks2 = MockKeystore::new(vec![Signer::from_mnemonic("Other", PHRASE, 5)], echo());
    let (tx, mut rx) = mpsc::unbounded_channel();
    let (k1, k2) = (ks1.clone(), ks2.clone());
    let r = Requester::new(
        Config::new(&base, "Example"),
        Arc::new(MemoryStore::default()),
        Arc::new(move |uri| {
            for ks in [k1.clone(), k2.clone()] {
                let (uri, tx) = (uri.to_owned(), tx.clone());
                tokio::spawn(async move { tx.send(ks.accept(&uri, 0, DAY).await).unwrap() });
            }
        }),
    )
    .unwrap();
    let account = r.connect().await.unwrap();
    let results = [rx.recv().await.unwrap(), rx.recv().await.unwrap()];
    let used = results
        .iter()
        .filter(|r| matches!(r, Err(Error::Relay(ErrorCode::TicketUsed))))
        .count();
    assert_eq!(used, 1, "{results:?}");
    let winner = results.iter().find_map(|r| r.as_ref().ok()).unwrap();
    assert_eq!(winner.account, account);
}

#[tokio::test]
async fn missing_bound_revokes_the_half_signed_token() {
    let base = relay().await;
    let ks = MockKeystore::with_options(
        signers(1),
        echo(),
        Options {
            bound_timeout: Duration::from_secs(1),
            ..Options::default()
        },
    );
    // A requester that reads bind but never sends bound.
    let relay = RelayClient::new(&base);
    relay.sync_time().await.unwrap();
    let attempt = ConnectAttempt::new(&base, "Example", None).unwrap();
    let s = attempt.keys().sig.clone();
    relay
        .register_ticket(&s, &attempt.offer().ticket, relay.now() + 60)
        .await
        .unwrap();
    let mut sub = relay.subscribe(s.clone());
    let uri = attempt.uri();
    let ks2 = ks.clone();
    let accepted = tokio::spawn(async move { ks2.accept(&uri, 0, DAY).await });
    let d = sub.next().await.unwrap().unwrap();
    let cand = attempt.open_bind(&d.body, relay.now()).unwrap();
    assert!(matches!(accepted.await.unwrap(), Err(Error::Timeout)));

    let junk = envelope::seal_message(
        &Keys::generate().kem,
        cand.token.body.keystore.kem,
        &cand.token.body.keystore.sig,
        b"{}",
    )
    .unwrap()
    .to_bytes();
    let res = relay
        .post(
            &cand.token.body.keystore.sig,
            WriteAuth::Token {
                token: &cand.token,
                signer: &s,
            },
            &junk,
        )
        .await;
    assert!(
        matches!(res, Err(Error::Relay(ErrorCode::Revoked))),
        "{res:?}"
    );
}

#[tokio::test]
async fn a_bind_with_a_bad_account_signature_is_ignored() {
    let base = relay().await;
    let ks = MockKeystore::with_options(
        signers(1),
        echo(),
        Options {
            bound_timeout: Duration::from_secs(3),
            wrong_statement_key: true,
        },
    );
    let mut cfg = Config::new(&base, "Example");
    cfg.connect_timeout = Duration::from_secs(2);
    let r = requester_cfg(cfg, &MemoryStore::default(), &ks, 0);
    assert!(matches!(r.connect().await, Err(Error::NoSigner)));
}

#[tokio::test]
async fn a_requester_with_a_wrong_clock_still_works() {
    let base = relay().await;
    let ks = MockKeystore::new(signers(1), echo());
    for skew in [600, -600] {
        let mut cfg = Config::new(&base, "Example");
        cfg.local_clock_skew = skew;
        let r = requester_cfg(cfg, &MemoryStore::default(), &ks, 0);
        r.connect().await.unwrap();
        r.request(req("t")).await.unwrap();
    }
}

#[tokio::test]
async fn a_request_waits_for_the_app_to_open() {
    let base = relay().await;
    let ks = MockKeystore::new(signers(1), echo());
    let store = MemoryStore::default();
    let r = Arc::new(requester(&base, &store, &ks, 0));
    r.connect().await.unwrap();
    ks.go_offline();
    let r2 = r.clone();
    let call = tokio::spawn(async move { r2.request(req("later")).await });
    tokio::time::sleep(Duration::from_millis(800)).await;
    assert_eq!(ks.handled(), 0);
    ks.go_online();
    let resp = call.await.unwrap().unwrap();
    assert_eq!(signature(&resp), format!("0x{}", hex("later")));
}

#[tokio::test]
async fn a_request_older_than_the_relay_ttl_is_gone() {
    let base = relay_with(Limits {
        message_ttl: Duration::from_secs(1),
        ..Limits::default()
    })
    .await;
    let ks = MockKeystore::new(signers(1), echo());
    let r = requester(&base, &MemoryStore::default(), &ks, 0);
    r.connect().await.unwrap();
    ks.go_offline();
    let mut short = req("gone");
    short.expires_at = r.relay().now() + 2;
    assert!(matches!(r.request(short).await, Err(Error::Timeout)));
    // The sweeper runs every 10 s; wait for it to drop the expired request.
    tokio::time::sleep(Duration::from_secs(11)).await;
    ks.go_online();
    tokio::time::sleep(Duration::from_millis(800)).await;
    assert_eq!(ks.handled(), 0);
}
