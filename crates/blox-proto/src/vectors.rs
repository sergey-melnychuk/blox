//! Wire-format test vectors (`test-vectors/proto-v1.json`).
//!
//! The vectors pin the format for independent implementations. Regenerate with
//! `BLOX_REGEN_VECTORS=1 cargo test -p blox-proto vectors`.

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::envelope::{self, Envelope, Kind};
use crate::keys::{KeyPair, Psk};
use crate::mailbox::ReadSecret;
use crate::message::{Body, Hello, Message, MsgId};
use crate::session::SessionPayload;
use crate::{b64, pad};

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

fn generate() -> Value {
    let read_secret_a = [0x11u8; 32];
    let read_secret_k = [0x22u8; 32];
    let ma = ReadSecret::from_bytes(read_secret_a).mailbox_id();
    let mk = ReadSecret::from_bytes(read_secret_k).mailbox_id();
    let adapter = KeyPair::derive(b"blox test adapter key");
    let keystore = KeyPair::derive(b"blox test keystore key");
    let psk = Psk::from_bytes([0x33; 32]);

    let hello_pt = Message {
        id: MsgId([0xa1; 16]),
        ts: 1_760_000_000,
        re: None,
        body: Body::Hello(Hello { mk }),
    }
    .to_json();
    let hello = envelope::seal_with_rng(
        Kind::Hello,
        &keystore,
        adapter.public(),
        &psk,
        &ma,
        &hello_pt,
        &mut TestRng::new("hello"),
    )
    .unwrap();

    let msg_pt = br#"{"id":"oqKioqKioqKioqKioqKiog","ts":1760000001,"type":"close","body":{"reason":"done"}}"#;
    let msg = envelope::seal_with_rng(
        Kind::Message,
        &adapter,
        keystore.public(),
        &psk,
        &mk,
        msg_pt,
        &mut TestRng::new("message"),
    )
    .unwrap();

    let session = SessionPayload::new(
        "https://relay.example.com",
        adapter.public(),
        ma,
        psk.clone(),
        "laptop",
    );

    json!({
        "description": "Blox wire format v1 (BLOX.md §2.1, §4, §5.1). Binary values are base64url without padding unless noted.",
        "mailbox": [
            { "read_secret": b64::encode(read_secret_a), "mailbox_id": ma.to_string() },
            { "read_secret": b64::encode(read_secret_k), "mailbox_id": mk.to_string() }
        ],
        "padding": [
            { "plaintext_hex": "", "padded_len": 1024, "padded_prefix_hex": "80" },
            { "plaintext_hex": "68656c6c6f", "padded_len": 1024, "padded_prefix_hex": "68656c6c6f80" },
            { "plaintext_len": 1024, "padded_len": 4096 }
        ],
        "keys": {
            "note": "RFC 9180 DeriveKeyPair(ikm) for DHKEM(X25519, HKDF-SHA256)",
            "adapter_ikm_utf8": "blox test adapter key",
            "adapter_pk": b64::encode(adapter.public().0),
            "keystore_ikm_utf8": "blox test keystore key",
            "keystore_pk": b64::encode(keystore.public().0),
            "psk": b64::encode([0x33u8; 32])
        },
        "envelopes": [
            {
                "name": "hello keystore→adapter",
                "recipient_mailbox": ma.to_string(),
                "sender": "keystore",
                "plaintext_utf8": String::from_utf8(hello_pt).unwrap(),
                "envelope": b64::encode(hello.to_bytes())
            },
            {
                "name": "message adapter→keystore",
                "recipient_mailbox": mk.to_string(),
                "sender": "adapter",
                "plaintext_utf8": std::str::from_utf8(msg_pt).unwrap(),
                "envelope": b64::encode(msg.to_bytes())
            }
        ],
        "session_uri": session.to_uri()
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

    // Independently of generation: every stored envelope opens with the stored keys.
    let adapter = KeyPair::derive(b"blox test adapter key");
    let keystore = KeyPair::derive(b"blox test keystore key");
    let psk = Psk::from_bytes([0x33; 32]);
    for e in stored["envelopes"].as_array().unwrap() {
        let env = Envelope::parse(&b64::decode(e["envelope"].as_str().unwrap()).unwrap()).unwrap();
        let mb =
            crate::mailbox::MailboxId::parse(e["recipient_mailbox"].as_str().unwrap()).unwrap();
        let (recipient, sender_pk) = match e["sender"].as_str().unwrap() {
            "keystore" => (&adapter, env.spk.unwrap()),
            _ => (&keystore, adapter.public()),
        };
        let pt = envelope::open(&env, recipient, sender_pk, &psk, &mb).unwrap();
        assert_eq!(pt, e["plaintext_utf8"].as_str().unwrap().as_bytes());
    }
    for p in stored["padding"].as_array().unwrap() {
        if let Some(h) = p["plaintext_hex"].as_str() {
            let padded = pad::pad(&hex::decode(h).unwrap()).unwrap();
            assert_eq!(padded.len() as u64, p["padded_len"].as_u64().unwrap());
            assert!(hex::encode(&padded).starts_with(p["padded_prefix_hex"].as_str().unwrap()));
        }
    }
}
