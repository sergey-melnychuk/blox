//! §13.2: relay logs during connect and requests contain no inbox keys, tokens, tickets,
//! envelope bytes or IP addresses.

use std::io::Write;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use blox_client::{Config, ConnectionStore, MemoryStore, Requester};
use blox_mock_keystore::{MockKeystore, Signer, handler};
use blox_proto::message::{SignRequest, SignResponse};
use blox_proto::offer::Offer;
use blox_relay::{AppState, Limits, router};

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl Write for Capture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[tokio::test]
async fn relay_logs_leak_nothing() {
    let capture = Capture::default();
    let writer = capture.clone();
    tracing_subscriber::fmt()
        .with_env_filter(blox_relay::log_filter("trace"))
        .with_writer(move || writer.clone())
        .with_ansi(false)
        .init();

    let listener = tokio::net::TcpListener::bind("localhost:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let app = router(AppState::new(Limits::default(), false))
        .into_make_service_with_connect_info::<SocketAddr>();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let ks = MockKeystore::new(
        vec![Signer::from_mnemonic(
            "Main",
            "test test test test test test test test test test test junk",
            0,
        )],
        handler(|ctx| {
            Some(SignResponse::Signed {
                account: ctx.signer.address(),
                signature: "0xsig".into(),
            })
        }),
    );
    let uris = Arc::new(Mutex::new(Vec::new()));
    let (k, seen) = (ks.clone(), uris.clone());
    let store = MemoryStore::default();
    let r = Requester::new(
        Config::new(&base, "Example"),
        Arc::new(store.clone()),
        Arc::new(move |uri| {
            seen.lock().unwrap().push(uri.to_owned());
            let (k, uri) = (k.clone(), uri.to_owned());
            tokio::spawn(async move { k.accept(&uri, 0, Duration::from_secs(86400)).await });
        }),
    )
    .unwrap();
    r.connect().await.unwrap();
    r.request(SignRequest {
        chain: "eip155:1".into(),
        kind: "evm.personal_sign".into(),
        payload: serde_json::json!({"message": "0x68"}),
        origin: None,
        expires_at: 0,
    })
    .await
    .unwrap();
    r.disconnect().await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;

    let logs = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
    assert!(
        logs.contains("/v1/inbox/{id}"),
        "route templates are logged: {logs}"
    );
    let offer = Offer::from_uri(&uris.lock().unwrap()[0]).unwrap();
    let stored = store.load().unwrap();
    assert!(stored.is_none(), "disconnected");
    let secrets = [
        offer.requester.sig.to_string(),
        ks.signer(0).transport.inbox().to_string(),
        offer.ticket.to_string(),
        blox_proto::b64::encode(offer.requester.kem.0),
        "localhost".to_owned(),
    ];
    for s in secrets {
        assert!(!logs.contains(&s), "log contains {s}:\n{logs}");
    }
}
