//! §13.2: relay logs during a full session contain no mailbox ids, secrets or bodies.

use std::io::Write;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use blox_client::Signer;
use blox_mock_keystore::{Next, serve};
use blox_proto::message::{SignRequest, SignResponse, now};
use blox_proto::session::SessionPayload;
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

    let uri = Arc::new(Mutex::new(String::new()));
    let (tx, rx) = tokio::sync::oneshot::channel::<String>();
    tokio::spawn(async move {
        let uri = rx.await.unwrap();
        serve(&uri, |_| {
            (
                SignResponse::Approved {
                    signature: "0xsig".into(),
                    signed_tx: None,
                },
                Next::Stop,
            )
        })
        .await
    });
    let keep = uri.clone();
    let session = Signer::new(&base, "test")
        .connect(
            move |u| {
                *keep.lock().unwrap() = u.to_owned();
                tx.send(u.to_owned()).unwrap();
            },
            Duration::from_secs(5),
        )
        .await
        .unwrap();
    let req = SignRequest {
        chain: "eip155:1".into(),
        account: "eip155:1:0x0000000000000000000000000000000000000001".into(),
        kind: "evm.personal_sign".into(),
        payload: serde_json::json!({ "message": "0x68656c6c6f" }),
        origin: None,
        expires_at: now() + 300,
    };
    session.sign(req, Duration::from_secs(5)).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;

    let logs = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
    let payload = SessionPayload::from_uri(&uri.lock().unwrap()).unwrap();
    assert!(
        logs.contains("/v1/m/{mailbox_id}"),
        "access log missing:\n{logs}"
    );
    for needle in [
        payload.ma.to_string(),
        "Bearer".into(),
        "localhost".into(),
        "authorization".into(),
    ] {
        assert!(!logs.contains(&needle), "logs contain {needle:?}:\n{logs}");
    }
}
