//! A keystore stand-in for tests (BLOX.md §13.1): joins a session from its QR
//! string and answers every request with a caller-supplied handler.

use blox_client::{Error, RelayClient, Result};
use blox_proto::message::{CloseReason, SignRequest, SignResponse, now};
use blox_proto::peer::{KeystoreEvent, KeystoreSession};

/// How the mock session ended.
#[derive(Debug, PartialEq)]
pub enum Outcome {
    /// The adapter closed the session.
    Closed(CloseReason),
    /// The handler asked to stop after answering `n` requests.
    Stopped { answered: usize },
}

/// What to do after answering a request.
pub enum Next {
    Continue,
    Stop,
}

/// Joins the session behind `uri` and serves requests until it closes.
pub async fn serve(
    uri: &str,
    mut handler: impl FnMut(&SignRequest) -> (SignResponse, Next),
) -> Result<Outcome> {
    let (mut session, hello) = KeystoreSession::join(uri)?;
    let relay = RelayClient::new(session.relay());
    let secret = session.read_secret().clone();
    let mut sub = relay.subscribe(secret.clone());
    relay.post(&hello).await?;

    let mut answered = 0;
    while let Some(delivery) = sub.next().await {
        let d = delivery?;
        let event = session.on_envelope(&d.body, now());
        relay.ack(&secret, d.seq).await?;
        match event {
            Ok(KeystoreEvent::Request(msg)) => {
                let blox_proto::message::Body::SignRequest(req) = &msg.body else {
                    unreachable!()
                };
                let (response, next) = handler(req);
                relay.post(&session.respond(&msg, response)?).await?;
                answered += 1;
                if let Next::Stop = next {
                    if let Some(bye) = session.close(CloseReason::Done)? {
                        relay.post(&bye).await?;
                    }
                    return Ok(Outcome::Stopped { answered });
                }
            }
            Ok(KeystoreEvent::Closed(reason)) => return Ok(Outcome::Closed(reason)),
            Err(_) => {} // not for us, replayed or stale
        }
    }
    Err(Error::Relay("subscription ended".into()))
}
