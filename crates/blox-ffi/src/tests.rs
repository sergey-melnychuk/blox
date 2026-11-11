//! Drives the bindings the way the app does, with a requester built from `blox-proto`.

use super::*;
use blox_proto::connection::ConnectAttempt;
use blox_proto::message::Origin;
use serde_json::json;
use std::collections::HashMap as Map;

const MNEMONIC: &[u8] = b"test test test test test test test test test test test junk";
const RELAY: &str = "https://relay.example.com";
const NOW: u64 = 1_762_776_000;

/// A scripted endpoint, implemented in Rust the way the app implements it in Kotlin.
struct FakeEndpoint(Map<&'static str, Result<String, (i64, String)>>);

impl EndpointRpc for FakeEndpoint {
    fn call(&self, method: String, _params_json: String) -> Result<String, RpcFailure> {
        match self.0.get(method.as_str()) {
            Some(Ok(v)) => Ok(v.clone()),
            Some(Err((code, message))) => Err(RpcFailure::Rpc {
                code: *code,
                detail: message.clone(),
            }),
            None => Err(RpcFailure::Rpc {
                code: -32601,
                detail: "method not found".into(),
            }),
        }
    }
}

fn anvil_like() -> Arc<dyn EndpointRpc> {
    let mut m = Map::new();
    m.insert("eth_chainId", Ok("\"0x7a69\"".into()));
    m.insert("eth_getTransactionCount", Ok("\"0x0\"".into()));
    m.insert("eth_estimateGas", Ok("\"0x5208\"".into()));
    m.insert(
        "eth_getBlockByNumber",
        Ok("{\"baseFeePerGas\":\"0x3b9aca00\"}".into()),
    );
    m.insert("eth_maxPriorityFeePerGas", Ok("\"0x1\"".into()));
    m.insert("eth_getBalance", Ok("\"0xde0b6b3a7640000\"".into()));
    m.insert(
        "eth_sendRawTransaction",
        Ok("\"0x0000000000000000000000000000000000000000000000000000000000000001\"".into()),
    );
    Arc::new(FakeEndpoint(m))
}

struct World {
    inbox: Arc<Inbox>,
    requester: Connection,
    record: ConnectionRecord,
}

fn connect() -> World {
    let keys = generate_transport_keys();
    let account = derive_evm_addresses(MNEMONIC.to_vec(), 0, 1)
        .unwrap()
        .remove(0);
    let inbox = Inbox::new(
        RELAY.into(),
        keys.sig_secret.clone(),
        keys.kem_secret.clone(),
        account.clone(),
        vec![],
    )
    .unwrap();
    assert_eq!(inbox.inbox_id(), keys.inbox);

    let attempt = ConnectAttempt::new(RELAY, "Example", None).unwrap();
    let info = parse_offer(attempt.uri()).unwrap();
    assert_eq!(
        (
            info.relay.as_str(),
            info.relay_host.as_str(),
            info.label.as_str()
        ),
        (RELAY, "relay.example.com", "Example")
    );

    let bind = inbox
        .accept_offer(attempt.uri(), MNEMONIC.to_vec(), 0, NOW, NOW + 86400)
        .unwrap();
    assert_eq!(bind.account, account);
    assert_eq!(bind.requester_inbox, attempt.keys().inbox().to_string());
    let cand = attempt.open_bind(&bind.body, NOW).unwrap();
    blox_evm::connect::verify_statement(&cand.statement, &cand.signature, &cand.account).unwrap();
    let (requester, bound) = attempt.accept(cand, NOW).unwrap();
    let Incoming::Connected { connection: record } = inbox.on_envelope(bound, NOW) else {
        panic!("expected connected")
    };
    assert_eq!(
        (record.label.as_str(), record.account.as_str()),
        ("Example", account.as_str())
    );
    World {
        inbox,
        requester,
        record,
    }
}

fn request(kind: &str, payload: serde_json::Value) -> Message {
    Message::at(
        Body::SignRequest(SignRequest {
            chain: "eip155:31337".into(),
            kind: kind.into(),
            payload,
            origin: Some(Origin {
                name: Some("Example".into()),
                url: Some("https://example.com".into()),
            }),
            expires_at: NOW + 300,
        }),
        NOW,
    )
}

fn incoming_request(w: &World, msg: &Message) -> Arc<IncomingRequest> {
    match w.inbox.on_envelope(w.requester.seal(msg).unwrap(), NOW) {
        Incoming::Request { request } => request,
        _ => panic!("expected a request"),
    }
}

#[test]
fn connect_sign_message_and_answer() {
    let mut w = connect();
    let msg = request("evm.personal_sign", json!({"message": "0x68656c6c6f"}));
    let req = incoming_request(&w, &msg);
    assert_eq!(req.id(), msg.id.to_string());
    assert_eq!(req.connection_id(), w.record.id);
    assert_eq!(req.origin_url().as_deref(), Some("https://example.com"));
    let ReviewOutcome::Ready { review } = req.review("Main".into(), None, None, None, NOW) else {
        panic!("expected ready")
    };
    assert_eq!(review.display().title, "Message signature");
    let ApproveOutcome::Answer { response } = review.approve(MNEMONIC.to_vec(), 0).unwrap() else {
        panic!("expected an answer")
    };
    let out = w
        .inbox
        .answer(req.connection_id(), req.id(), response, NOW)
        .unwrap();
    assert_eq!(out.inbox, w.record.requester_inbox);
    let reply = w.requester.open(&out.body, NOW).unwrap();
    assert_eq!(reply.re, Some(msg.id));
    let Body::SignResponse(resp) = reply.body else {
        panic!()
    };
    let Body::SignRequest(sent) = &msg.body else {
        unreachable!()
    };
    let account: Address = w.record.account.parse().unwrap();
    blox_evm::check::check(sent, &resp, account).unwrap();
    // The same envelope again (no acknowledgement reached the relay): recognised.
    let again = w.inbox.on_envelope(w.requester.seal(&msg).unwrap(), NOW);
    assert!(
        matches!(again, Incoming::Dropped),
        "a re-sealed copy is a replay by id"
    );
}

#[test]
fn redelivery_of_the_same_envelope() {
    let w = connect();
    let msg = request("evm.personal_sign", json!({"message": "0x01"}));
    let bytes = w.requester.seal(&msg).unwrap();
    assert!(matches!(
        w.inbox.on_envelope(bytes.clone(), NOW),
        Incoming::Request { .. }
    ));
    let Incoming::Redelivered {
        connection_id,
        request_id,
    } = w.inbox.on_envelope(bytes, NOW)
    else {
        panic!("expected redelivered")
    };
    assert_eq!(
        (connection_id, request_id),
        (w.record.id.clone(), msg.id.to_string())
    );
}

#[test]
fn send_review_approve_and_broadcast() {
    let w = connect();
    let msg = request(
        "evm.send",
        json!({"to": "0x70997970C51812dc3A010C7d01b50e0d17dc79C8", "value": "0x1"}),
    );
    let req = incoming_request(&w, &msg);
    assert_eq!(req.chain_id(), Some(31337));
    // No endpoint: rejected without asking.
    assert!(matches!(
        req.review("Main".into(), None, None, None, NOW),
        ReviewOutcome::Reject {
            reason: RejectReason::NoEndpoint
        }
    ));
    let ep = anvil_like();
    let ReviewOutcome::Ready { review } = req.review(
        "Main".into(),
        Some(ep.clone()),
        Some("anvil.local".into()),
        None,
        NOW,
    ) else {
        panic!("expected ready")
    };
    let d = review.display();
    assert!(
        d.fields
            .iter()
            .any(|f| f.label == "Sent via" && f.value == "anvil.local")
    );
    assert!(
        d.fields
            .iter()
            .any(|f| f.label == "Signer" && f.value.starts_with("Main · 0xf39F"))
    );
    let ApproveOutcome::Broadcast {
        raw,
        tx_hash,
        nonce,
        if_interrupted,
    } = review.approve(MNEMONIC.to_vec(), 0).unwrap()
    else {
        panic!("expected broadcast")
    };
    assert_eq!(nonce, 0);
    assert!(matches!(if_interrupted, Response::Failed { .. }));
    let resp =
        broadcast_transaction(ep, 31337, w.record.account.clone(), raw, tx_hash.clone()).unwrap();
    assert_eq!(
        resp,
        Response::Sent {
            account: format!("eip155:31337:{}", w.record.account),
            tx_hash
        }
    );
    // A wrong key is refused.
    let other = b"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    assert!(matches!(
        review.approve(other.to_vec(), 0),
        Err(FfiError::WrongAccount)
    ));
}

#[test]
fn would_fail_and_unreachable() {
    let w = connect();
    let msg = request("evm.send", json!({"to": null, "data": "0x60006000fd"}));
    let req = incoming_request(&w, &msg);
    let mut m = Map::new();
    m.insert("eth_chainId", Ok("\"0x7a69\"".to_owned()));
    m.insert("eth_getTransactionCount", Ok("\"0x0\"".to_owned()));
    m.insert("eth_estimateGas", Err((3, "execution reverted".to_owned())));
    let failing: Arc<dyn EndpointRpc> = Arc::new(FakeEndpoint(m));
    assert!(matches!(
        req.review("Main".into(), Some(failing), None, None, NOW),
        ReviewOutcome::WouldFail { .. }
    ));
    struct Down;
    impl EndpointRpc for Down {
        fn call(&self, _: String, _: String) -> Result<String, RpcFailure> {
            Err(RpcFailure::Unreachable {
                detail: "timeout".into(),
            })
        }
    }
    assert!(matches!(
        req.review("Main".into(), Some(Arc::new(Down)), None, None, NOW),
        ReviewOutcome::Unreachable { .. }
    ));
}

#[test]
fn cancel_unbind_and_keystore_disconnect() {
    let mut w = connect();
    let msg = request("evm.personal_sign", json!({"message": "0x01"}));
    let req = incoming_request(&w, &msg);
    let cancel = Message::reply_at(msg.id, Body::Cancel(Empty {}), NOW);
    let Incoming::Cancelled { request_id, .. } =
        w.inbox.on_envelope(w.requester.seal(&cancel).unwrap(), NOW)
    else {
        panic!("expected cancelled")
    };
    assert_eq!(request_id, req.id());

    // The keystore ends it: unbind for the requester, then the connection is gone.
    let out = w.inbox.unbind(w.record.id.clone(), NOW).unwrap();
    assert!(matches!(
        w.requester.open(&out.body, NOW).unwrap().body,
        Body::Unbind(_)
    ));
    assert!(matches!(
        w.inbox.answer(
            w.record.id.clone(),
            req.id(),
            Response::Rejected {
                reason: RejectReason::User
            },
            NOW
        ),
        Err(FfiError::UnknownConnection)
    ));
    let late = request("evm.personal_sign", json!({"message": "0x02"}));
    assert!(matches!(
        w.inbox.on_envelope(w.requester.seal(&late).unwrap(), NOW),
        Incoming::Dropped
    ));
}

#[test]
fn requester_unbind() {
    let w = connect();
    let bye = Message::at(Body::Unbind(Empty {}), NOW);
    let Incoming::Unbound { connection_id } =
        w.inbox.on_envelope(w.requester.seal(&bye).unwrap(), NOW)
    else {
        panic!("expected unbound")
    };
    assert_eq!(connection_id, w.record.id);
}

#[test]
fn stored_connections_reload() {
    let keys = generate_transport_keys();
    let account = derive_evm_addresses(MNEMONIC.to_vec(), 0, 1)
        .unwrap()
        .remove(0);
    let make = |records| {
        Inbox::new(
            RELAY.into(),
            keys.sig_secret.clone(),
            keys.kem_secret.clone(),
            account.clone(),
            records,
        )
        .unwrap()
    };
    let inbox = make(vec![]);
    let attempt = ConnectAttempt::new(RELAY, "Example", None).unwrap();
    let bind = inbox
        .accept_offer(attempt.uri(), MNEMONIC.to_vec(), 0, NOW, NOW + 86400)
        .unwrap();
    let (requester, bound) = attempt
        .accept(attempt.open_bind(&bind.body, NOW).unwrap(), NOW)
        .unwrap();
    let Incoming::Connected { connection } = inbox.on_envelope(bound, NOW) else {
        panic!()
    };
    let reloaded = make(vec![connection]);
    let msg = request("evm.personal_sign", json!({"message": "0x01"}));
    assert!(matches!(
        reloaded.on_envelope(requester.seal(&msg).unwrap(), NOW),
        Incoming::Request { .. }
    ));
}

#[test]
fn connect_refusals_and_abandon() {
    let keys = generate_transport_keys();
    let account = derive_evm_addresses(MNEMONIC.to_vec(), 0, 1)
        .unwrap()
        .remove(0);
    let inbox = Inbox::new(
        RELAY.into(),
        keys.sig_secret,
        keys.kem_secret,
        account,
        vec![],
    )
    .unwrap();
    let other_relay = ConnectAttempt::new("https://relay.example.org", "X", None).unwrap();
    assert!(matches!(
        inbox.accept_offer(other_relay.uri(), MNEMONIC.to_vec(), 0, NOW, NOW + 60),
        Err(FfiError::WrongRelay)
    ));
    let attempt = ConnectAttempt::new(RELAY, "X", None).unwrap();
    assert!(matches!(
        inbox.accept_offer(attempt.uri(), MNEMONIC.to_vec(), 1, NOW, NOW + 60),
        Err(FfiError::WrongAccount)
    ));
    assert!(matches!(
        parse_offer("BLOX:junk".into()),
        Err(FfiError::InvalidQr(_))
    ));
    let bind = inbox
        .accept_offer(attempt.uri(), MNEMONIC.to_vec(), 0, NOW, NOW + 60)
        .unwrap();
    let token = inbox.abandon_connect(bind.requester_inbox.clone()).unwrap();
    assert!(Token::from_header(&token).is_ok());
    assert!(inbox.abandon_connect(bind.requester_inbox).is_none());
}

#[test]
fn relay_request_signatures_and_helpers() {
    let keys = generate_transport_keys();
    let path = format!("/v1/inbox/{}", keys.inbox);
    let auth =
        sign_relay_request(keys.sig_secret, "GET".into(), path.clone(), NOW, vec![]).unwrap();
    let inbox = blox_proto::ident::InboxId::parse(&keys.inbox).unwrap();
    reqsig::verify(&auth, &inbox, "GET", &path, b"", NOW, 60).unwrap();
    assert_eq!(
        normalize_relay_url("HTTPS://Relay.Example.com/".into()).unwrap(),
        RELAY
    );
    assert_eq!(
        relay_host("http://my-computer.lan:8080".into()),
        "my-computer.lan:8080"
    );
    assert_eq!(endpoint_chain_id(anvil_like()).unwrap(), 31337);
}

#[test]
fn mnemonic_helpers() {
    let m = generate_mnemonic(12).unwrap();
    assert_eq!(std::str::from_utf8(&m).unwrap().split(' ').count(), 12);
    assert!(validate_mnemonic(m));
    assert!(!validate_mnemonic(b"test test".to_vec()));
    assert_eq!(
        derive_evm_addresses(MNEMONIC.to_vec(), 0, 2).unwrap(),
        [
            "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
            "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
        ]
    );
    assert_eq!(chain_name(8453).as_deref(), Some("Base"));
}
