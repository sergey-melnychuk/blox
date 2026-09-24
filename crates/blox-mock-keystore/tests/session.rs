//! Full sessions through a real relay (M1 gate).

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use blox_client::{Error, Signer};
use blox_mock_keystore::{Next, Outcome, serve};
use blox_proto::message::{CloseReason, RejectReason, SignRequest, SignResponse, now};
use blox_relay::{AppState, Limits, router};
use tokio::sync::oneshot;

async fn relay() -> String {
    let listener = tokio::net::TcpListener::bind("localhost:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let state = AppState::new(Limits::default(), false);
    tokio::spawn(blox_relay::sweeper(state.clone()));
    let app = router(state).into_make_service_with_connect_info::<SocketAddr>();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{addr}")
}

fn request(n: u64) -> SignRequest {
    SignRequest {
        chain: "eip155:31337".into(),
        account: "eip155:31337:0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266".into(),
        kind: "evm.personal_sign".into(),
        payload: serde_json::json!({ "message": format!("0x{n:02x}") }),
        origin: None,
        expires_at: now() + 300,
    }
}

const T: Duration = Duration::from_secs(5);

/// Connects a signer and hands the QR string to `keystore` once it's shown.
async fn connect_with<F, Fut>(base: &str, keystore: F) -> blox_client::Result<blox_client::Session>
where
    F: FnOnce(String) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    let (tx, rx) = oneshot::channel::<String>();
    tokio::spawn(async move { keystore(rx.await.unwrap()).await });
    Signer::new(base, "test")
        .connect(|uri| tx.send(uri.to_owned()).unwrap(), T)
        .await
}

#[tokio::test]
async fn session_with_several_requests_then_close() {
    let base = relay().await;
    let seen = Arc::new(Mutex::new(Vec::new()));
    let (done_tx, done_rx) = oneshot::channel();
    let log = seen.clone();
    let session = connect_with(&base, move |uri| async move {
        let outcome = serve(&uri, move |req| {
            log.lock()
                .unwrap()
                .push(req.payload["message"].as_str().unwrap().to_owned());
            (
                SignResponse::Approved {
                    signature: "0xsig".into(),
                    signed_tx: None,
                },
                Next::Continue,
            )
        })
        .await;
        done_tx.send(outcome).unwrap();
    })
    .await
    .unwrap();

    for n in 0..5 {
        let resp = session.sign(request(n), T).await.unwrap();
        assert!(matches!(resp, SignResponse::Approved { .. }));
    }
    session.close().await;
    assert_eq!(
        done_rx.await.unwrap().unwrap(),
        Outcome::Closed(CloseReason::Done)
    );
    assert_eq!(
        *seen.lock().unwrap(),
        ["0x00", "0x01", "0x02", "0x03", "0x04"]
    );
}

#[tokio::test]
async fn rejection_and_keystore_close_are_reported() {
    let base = relay().await;
    let session = connect_with(&base, |uri| async move {
        let _ = serve(&uri, |_| {
            (
                SignResponse::Rejected {
                    reason: RejectReason::User,
                },
                Next::Stop,
            )
        })
        .await;
    })
    .await
    .unwrap();

    let resp = session.sign(request(0), T).await.unwrap();
    assert_eq!(
        resp,
        SignResponse::Rejected {
            reason: RejectReason::User
        }
    );
    // The keystore closed after answering: the next request fails.
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(matches!(
        session.sign(request(1), T).await,
        Err(Error::Closed(CloseReason::Done))
    ));
}

#[tokio::test]
async fn second_device_contests_the_session() {
    let base = relay().await;
    let (k2_tx, k2_rx) = oneshot::channel();
    let session = connect_with(&base, move |uri| async move {
        let first = tokio::spawn({
            let uri = uri.clone();
            async move { serve(&uri, |_| unreachable!("no request after contest")).await }
        });
        tokio::time::sleep(Duration::from_millis(500)).await;
        let second = serve(&uri, |_| unreachable!("no request after contest")).await;
        k2_tx.send((first.await.unwrap(), second)).unwrap();
    })
    .await
    .unwrap();

    let (first, second) = k2_rx.await.unwrap();
    assert_eq!(first.unwrap(), Outcome::Closed(CloseReason::Contested));
    assert_eq!(second.unwrap(), Outcome::Closed(CloseReason::Contested));
    assert!(!session.is_open());
    assert!(matches!(
        session.sign(request(0), T).await,
        Err(Error::Contested)
    ));
}

#[tokio::test]
async fn nobody_joins() {
    let base = relay().await;
    let res = Signer::new(&base, "test")
        .connect(|_| {}, Duration::from_millis(500))
        .await;
    assert!(matches!(res, Err(Error::NoSignerJoined)));
}
