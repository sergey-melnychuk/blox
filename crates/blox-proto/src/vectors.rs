//! Wire-format test vectors (`test-vectors/proto-v1.json`).
//!
//! The vectors pin the format for independent implementations (the TypeScript SDK passes
//! the same file). Regenerate with `BLOX_REGEN_VECTORS=1 cargo test -p blox-proto vectors`.

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::envelope::{self, Envelope, Kind};
use crate::ident::{SigningKey, Ticket};
use crate::keys::{KeyPair, Psk};
use crate::message::{Bind, Body, Message, MsgId, SignRequest};
use crate::offer::Offer;
use crate::statement::Statement;
use crate::token::{Party, PartyKeys, Token, TokenBody};
use crate::{b64, pad, relay_url, reqsig};

const PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../test-vectors/proto-v1.json"
);

/// Deterministic RNG: SHA-256(seed ‖ counter) blocks. Test use only.
struct TestRng {
    seed: [u8; 32],
    ctr: u64,
    buf: Vec<u8>,
}

impl TestRng {
    fn new(label: &str) -> Self {
        Self {
            seed: Sha256::digest(label.as_bytes()).into(),
            ctr: 0,
            buf: Vec::new(),
        }
    }
}

impl hpke::rand_core::TryRng for TestRng {
    type Error = core::convert::Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut b = [0; 4];
        self.try_fill_bytes(&mut b)?;
        Ok(u32::from_le_bytes(b))
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut b = [0; 8];
        self.try_fill_bytes(&mut b)?;
        Ok(u64::from_le_bytes(b))
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        while self.buf.len() < dst.len() {
            let mut h = Sha256::new();
            h.update(self.seed);
            h.update(self.ctr.to_be_bytes());
            self.ctr += 1;
            self.buf.extend_from_slice(&h.finalize());
        }
        let rest = self.buf.split_off(dst.len());
        dst.copy_from_slice(&self.buf);
        self.buf = rest;
        Ok(())
    }
}

impl hpke::rand_core::TryCryptoRng for TestRng {}

const ISSUED: u64 = 1_762_776_000;
const EXPIRES: u64 = ISSUED + 30 * 86400;
const ACCOUNT: &str = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";

struct Fixture {
    s_sig: SigningKey,
    s_kem: KeyPair,
    k_sig: SigningKey,
    k_kem: KeyPair,
    psk: Psk,
    ticket: Ticket,
}

fn fixture() -> Fixture {
    Fixture {
        s_sig: SigningKey::from_bytes(&[0x01; 32]),
        s_kem: KeyPair::derive(b"blox test requester key"),
        k_sig: SigningKey::from_bytes(&[0x02; 32]),
        k_kem: KeyPair::derive(b"blox test keystore key"),
        psk: Psk::from_bytes([0x33; 32]),
        ticket: Ticket([0x44; 16]),
    }
}

fn party(sig: &SigningKey, kem: &KeyPair) -> PartyKeys {
    PartyKeys {
        sig: sig.public(),
        kem: kem.public(),
    }
}

fn generate() -> Value {
    let f = fixture();
    let s = party(&f.s_sig, &f.s_kem);
    let k = party(&f.k_sig, &f.k_kem);
    let relay = relay_url::DEFAULT_RELAY;

    let body = TokenBody {
        requester: s,
        keystore: k,
        issued_at: ISSUED,
        expires_at: EXPIRES,
        relay: relay.into(),
    };
    let half = Token::issue(body, &f.k_sig).unwrap();
    let mut full = half.clone();
    full.countersign(&f.s_sig).unwrap();

    let statement = Statement {
        label: "Example",
        requester: &s.sig,
        keystore: &k.sig,
        account: ACCOUNT,
        ticket: &f.ticket,
        relay,
        issued_at: ISSUED,
        expires_at: EXPIRES,
    }
    .render();

    let bind_pt = Message {
        id: MsgId([0xa1; 16]),
        ts: ISSUED,
        re: None,
        body: Body::Bind(Bind {
            token: half.to_header(),
            account: ACCOUNT.into(),
            statement: statement.clone(),
            signature: "0x00".into(),
        }),
    }
    .to_json();
    let bind = envelope::seal_with_rng(
        Kind::Bind,
        &f.k_kem,
        s.kem,
        Some(&f.psk),
        &s.sig,
        &bind_pt,
        &mut TestRng::new("bind"),
    )
    .unwrap();

    let msg_pt = Message {
        id: MsgId([0xa2; 16]),
        ts: ISSUED + 1,
        re: None,
        body: Body::SignRequest(SignRequest {
            chain: "eip155:8453".into(),
            kind: "evm.send".into(),
            payload: json!({"to": "0x70997970C51812dc3A010C7d01b50e0d17dc79C8", "value": "0x2386f26fc10000", "data": "0x"}),
            origin: None,
            expires_at: ISSUED + 301,
        }),
    }
    .to_json();
    let msg = envelope::seal_with_rng(
        Kind::Message,
        &f.s_kem,
        k.kem,
        None,
        &k.sig,
        &msg_pt,
        &mut TestRng::new("message"),
    )
    .unwrap();

    let inbox_path = format!("/v1/inbox/{}", k.sig);
    let offer = Offer::new(relay, s, f.ticket, f.psk.clone(), "Example").unwrap();

    json!({
        "description": "Blox wire format v1 (BLOX.md §4, §5). Binary values are unpadded base64url unless noted.",
        "keys": {
            "note": "Ed25519 keys from 32-byte secrets; X25519 keys by RFC 9180 DeriveKeyPair(ikm) for DHKEM(X25519, HKDF-SHA256).",
            "requester_sig_secret": b64::encode([0x01u8; 32]),
            "requester_sig": s.sig.to_string(),
            "requester_kem_ikm_utf8": "blox test requester key",
            "requester_kem": b64::encode(s.kem.0),
            "keystore_sig_secret": b64::encode([0x02u8; 32]),
            "keystore_sig": k.sig.to_string(),
            "keystore_kem_ikm_utf8": "blox test keystore key",
            "keystore_kem": b64::encode(k.kem.0),
            "psk": b64::encode([0x33u8; 32]),
            "ticket": f.ticket.to_string(),
            "ticket_hash": b64::encode(f.ticket.hash())
        },
        "token": {
            "issued_at": ISSUED,
            "expires_at": EXPIRES,
            "relay": relay,
            "keystore_signed": half.to_header(),
            "countersigned": full.to_header(),
            "token_id": b64::encode(full.id())
        },
        "request_signature": {
            "signer": "requester",
            "method": "POST",
            "path": inbox_path,
            "ts": ISSUED,
            "body_hex": hex::encode(b"hello"),
            "authorization": reqsig::sign(&f.s_sig, "POST", &inbox_path, ISSUED, b"hello")
        },
        "relay_urls": [
            ["https://relay.example.com", "https://relay.example.com", ""],
            ["HTTPS://Relay.Example.COM:443/", "https://relay.example.com", ""],
            ["https://r.example.org:8443/relay/", "https://r.example.org:8443/relay", "r.example.org:8443/relay"],
            ["http://my-computer.lan:8080", "http://my-computer.lan:8080", "http://my-computer.lan:8080"]
        ],
        "padding": [
            { "plaintext_hex": "", "padded_len": 1024, "padded_prefix_hex": "80" },
            { "plaintext_hex": "68656c6c6f", "padded_len": 1024, "padded_prefix_hex": "68656c6c6f80" },
            { "plaintext_len": 1024, "padded_len": 4096 }
        ],
        "statement": {
            "label": "Example",
            "account": ACCOUNT,
            "text": statement
        },
        "envelopes": [
            {
                "name": "bind keystore→requester (mode_auth_psk)",
                "recipient": "requester",
                "plaintext_utf8": String::from_utf8(bind_pt).unwrap(),
                "envelope": b64::encode(bind.to_bytes())
            },
            {
                "name": "message requester→keystore (mode_auth)",
                "recipient": "keystore",
                "plaintext_utf8": String::from_utf8(msg_pt).unwrap(),
                "envelope": b64::encode(msg.to_bytes())
            }
        ],
        "offer": {
            "label": "Example",
            "uri": offer.to_uri()
        }
    })
}

#[test]
fn vectors() {
    let fresh = generate();
    if std::env::var_os("BLOX_REGEN_VECTORS").is_some() {
        std::fs::create_dir_all(std::path::Path::new(PATH).parent().unwrap()).unwrap();
        std::fs::write(PATH, serde_json::to_string_pretty(&fresh).unwrap() + "\n").unwrap();
    }
    let stored: Value = serde_json::from_str(
        &std::fs::read_to_string(PATH).expect("vectors file; set BLOX_REGEN_VECTORS=1"),
    )
    .unwrap();
    assert_eq!(
        stored, fresh,
        "wire format changed; regenerate only if intended"
    );

    // Independently of generation: the stored values check out with the stored keys.
    let f = fixture();
    let s_inbox = f.s_sig.public();
    let k_inbox = f.k_sig.public();
    for e in stored["envelopes"].as_array().unwrap() {
        let env = Envelope::parse(&b64::decode(e["envelope"].as_str().unwrap()).unwrap()).unwrap();
        let pt = match e["recipient"].as_str().unwrap() {
            "requester" => envelope::open_bind(&env, &f.s_kem, &f.psk, &s_inbox).unwrap(),
            _ => envelope::open_message(&env, &f.k_kem, f.s_kem.public(), &k_inbox).unwrap(),
        };
        assert_eq!(pt, e["plaintext_utf8"].as_str().unwrap().as_bytes());
    }
    let full = Token::from_header(stored["token"]["countersigned"].as_str().unwrap()).unwrap();
    full.verify(Party::Keystore).unwrap();
    full.verify(Party::Requester).unwrap();
    let rs = &stored["request_signature"];
    reqsig::verify(
        rs["authorization"].as_str().unwrap(),
        &s_inbox,
        "POST",
        rs["path"].as_str().unwrap(),
        b"hello",
        ISSUED,
        60,
    )
    .unwrap();
    for u in stored["relay_urls"].as_array().unwrap() {
        let normalized = relay_url::normalize(u[0].as_str().unwrap()).unwrap();
        assert_eq!(normalized, u[1].as_str().unwrap());
        assert_eq!(relay_url::to_qr_field(&normalized), u[2].as_str().unwrap());
    }
    for p in stored["padding"].as_array().unwrap() {
        if let Some(h) = p["plaintext_hex"].as_str() {
            let padded = pad::pad(&hex::decode(h).unwrap()).unwrap();
            assert_eq!(padded.len() as u64, p["padded_len"].as_u64().unwrap());
            assert!(hex::encode(&padded).starts_with(p["padded_prefix_hex"].as_str().unwrap()));
        }
    }
    let offer = Offer::from_uri(stored["offer"]["uri"].as_str().unwrap()).unwrap();
    assert_eq!(offer.requester.sig, s_inbox);
}
