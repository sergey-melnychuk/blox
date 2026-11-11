//! Sans-IO connection state machines (BLOX.md §5).
//!
//! Callers do the networking: post the returned envelope bytes to the named inbox, and
//! feed envelopes read from their own inbox back in. Time is always passed in (relay
//! time, §4.8). The account signature on the statement is checked by the caller, which
//! has the chain's crypto (`blox-evm` for EVM).

use crate::envelope::{self, Envelope, Kind};
use crate::ident::{InboxId, SigningKey, Ticket};
use crate::keys::{KeyPair, Psk};
use crate::message::{Bind, Body, Bound, Message};
use crate::offer::Offer;
use crate::replay::Seen;
use crate::statement::Statement;
use crate::token::{MAX_LIFETIME_SECS, Party, PartyKeys, Token, TokenBody};
use crate::{Error, Result};

/// How far `bind`'s `issued_at` may be from the requester's (relay) time.
pub const BIND_SKEW_SECS: u64 = 300;
/// How long either side waits for the other during connect (§5.1, §5.2).
pub const CONNECT_TIMEOUT_SECS: u64 = 120;

/// One side's Ed25519 and X25519 secrets: `S`/`s` for a requester's connection, `K`/`k`
/// for a keystore's signer.
#[derive(Clone, Debug)]
pub struct Keys {
    pub sig: SigningKey,
    pub kem: KeyPair,
}

impl Keys {
    pub fn generate() -> Self {
        Self {
            sig: SigningKey::generate(),
            kem: KeyPair::generate(),
        }
    }

    pub fn public(&self) -> PartyKeys {
        PartyKeys {
            sig: self.sig.public(),
            kem: self.kem.public(),
        }
    }

    pub fn inbox(&self) -> InboxId {
        self.sig.public()
    }
}

// ---- requester -------------------------------------------------------------------

/// A requester's connect attempt: the offer behind the QR code, until `bind` (§5.1, §5.3).
pub struct ConnectAttempt {
    keys: Keys,
    offer: Offer,
}

/// A `bind` that passed every check except the account signature.
#[derive(Clone, Debug)]
pub struct BindCandidate {
    pub token: Token,
    pub account: String,
    pub statement: String,
    pub signature: String,
}

impl ConnectAttempt {
    /// New keys `S`/`s`, a PSK, and `ticket` (a fresh one if `None`, §9.2's server nonce if given).
    pub fn new(relay: &str, label: &str, ticket: Option<Ticket>) -> Result<Self> {
        let keys = Keys::generate();
        let offer = Offer::new(
            relay,
            keys.public(),
            ticket.unwrap_or_else(Ticket::generate),
            Psk::generate(),
            label,
        )?;
        Ok(Self { keys, offer })
    }

    pub fn offer(&self) -> &Offer {
        &self.offer
    }

    /// The `BLOX:…` string for the QR code. Holds the ticket and the PSK.
    pub fn uri(&self) -> String {
        self.offer.to_uri()
    }

    pub fn keys(&self) -> &Keys {
        &self.keys
    }

    /// Opens and checks a `bind` (§5.3, step 1, without the account signature).
    pub fn open_bind(&self, bytes: &[u8], now: u64) -> Result<BindCandidate> {
        let env = Envelope::parse(bytes)?;
        if env.kind != Kind::Bind {
            return Err(Error::Malformed("expected bind"));
        }
        let pt = envelope::open_bind(&env, &self.keys.kem, &self.offer.psk, &self.keys.inbox())?;
        let msg = Message::from_json(&pt)?;
        if msg.ts.abs_diff(now) > crate::replay::MAX_SKEW_SECS {
            return Err(Error::Stale);
        }
        let Body::Bind(bind) = msg.body else {
            return Err(Error::Malformed("bind envelope without bind body"));
        };
        let token = Token::from_header(&bind.token)?;
        token.verify(Party::Keystore)?;
        let b = &token.body;
        if b.requester != self.keys.public() || b.relay != self.offer.relay {
            return Err(Error::Malformed("token is for another connect attempt"));
        }
        if env.spk != b.keystore.kem {
            return Err(Error::Malformed(
                "bind sender is not the token's keystore key",
            ));
        }
        if b.issued_at.abs_diff(now) > BIND_SKEW_SECS
            || b.expires_at <= now
            || b.expires_at < b.issued_at
            || b.expires_at - b.issued_at > MAX_LIFETIME_SECS
        {
            return Err(Error::Malformed("token times"));
        }
        if !is_evm_address(&bind.account) {
            return Err(Error::Malformed("account"));
        }
        let expected = Statement {
            label: &self.offer.label,
            requester: &b.requester.sig,
            keystore: &b.keystore.sig,
            account: &bind.account,
            ticket: &self.offer.ticket,
            relay: &b.relay,
            issued_at: b.issued_at,
            expires_at: b.expires_at,
        }
        .render();
        if bind.statement != expected {
            return Err(Error::Malformed("statement differs from the token"));
        }
        Ok(BindCandidate {
            token,
            account: bind.account,
            statement: bind.statement,
            signature: bind.signature,
        })
    }

    /// Countersigns the token and builds `bound` for the keystore's inbox (§5.3, step 2).
    /// Call only after checking the account signature.
    pub fn accept(&self, candidate: BindCandidate, now: u64) -> Result<(Connection, Vec<u8>)> {
        let mut token = candidate.token;
        token.countersign(&self.keys.sig)?;
        let conn = Connection::new(Party::Requester, token, self.keys.kem.clone())?;
        let bound = Message::at(
            Body::Bound(Bound {
                token: conn.token.to_header(),
            }),
            now,
        );
        let bytes = conn.seal(&bound)?;
        Ok((conn, bytes))
    }
}

fn is_evm_address(s: &str) -> bool {
    s.len() == 42 && s.starts_with("0x") && s[2..].bytes().all(|b| b.is_ascii_hexdigit())
}

// ---- keystore --------------------------------------------------------------------

/// The keystore's side between `bind` and `bound` (§5.2, §5.4).
pub struct PendingConnection {
    token: Token,
    kem: KeyPair,
    pub label: String,
    pub account: String,
}

/// What [`accept_offer`] produces.
pub struct Accepted {
    pub pending: PendingConnection,
    /// The `bind` envelope, to post to the requester's inbox with `Blox-Ticket`.
    pub bind: Vec<u8>,
    pub requester_inbox: InboxId,
    pub ticket: Ticket,
}

/// Builds the token and `bind` for an approved offer (§5.2, steps 4–5).
///
/// `sign_statement` signs the statement text with the signer's account (EIP-191) and
/// returns the `0x…` signature.
pub fn accept_offer(
    offer: &Offer,
    signer: &Keys,
    account: &str,
    now: u64,
    expires_at: u64,
    sign_statement: impl FnOnce(&str) -> Result<String>,
) -> Result<Accepted> {
    if !is_evm_address(account) {
        return Err(Error::Malformed("account"));
    }
    let body = TokenBody {
        requester: offer.requester,
        keystore: signer.public(),
        issued_at: now,
        expires_at,
        relay: offer.relay.clone(),
    };
    let token = Token::issue(body, &signer.sig)?;
    let statement = Statement {
        label: &offer.label,
        requester: &offer.requester.sig,
        keystore: &signer.sig.public(),
        account,
        ticket: &offer.ticket,
        relay: &offer.relay,
        issued_at: now,
        expires_at,
    }
    .render();
    let signature = sign_statement(&statement)?;
    let msg = Message::at(
        Body::Bind(Bind {
            token: token.to_header(),
            account: account.to_owned(),
            statement,
            signature,
        }),
        now,
    );
    let env = envelope::seal_bind(
        &signer.kem,
        offer.requester.kem,
        &offer.psk,
        &offer.requester.sig,
        &msg.to_json(),
    )?;
    Ok(Accepted {
        pending: PendingConnection {
            token,
            kem: signer.kem.clone(),
            label: offer.label.clone(),
            account: account.to_owned(),
        },
        bind: env.to_bytes(),
        requester_inbox: offer.requester.sig,
        ticket: offer.ticket,
    })
}

impl PendingConnection {
    /// The half-signed token, to revoke if `bound` never comes (§5.4).
    pub fn token(&self) -> &Token {
        &self.token
    }

    /// The requester's X25519 key: `bound` arrives with this `spk`.
    pub fn requester_kem(&self) -> crate::keys::PublicKey {
        self.token.body.requester.kem
    }

    /// Opens `bound` and checks it carries this token, countersigned (§5.4).
    pub fn open_bound(&self, bytes: &[u8], now: u64) -> Result<Connection> {
        let env = Envelope::parse(bytes)?;
        let b = &self.token.body;
        let pt = envelope::open_message(&env, &self.kem, b.requester.kem, &b.keystore.sig)?;
        let msg = Message::from_json(&pt)?;
        if msg.ts.abs_diff(now) > crate::replay::MAX_SKEW_SECS {
            return Err(Error::Stale);
        }
        let Body::Bound(bound) = msg.body else {
            return Err(Error::Malformed("expected bound"));
        };
        let token = Token::from_header(&bound.token)?;
        if token.id() != self.token.id() {
            return Err(Error::Malformed("bound carries another token"));
        }
        token.verify(Party::Keystore)?;
        token.verify(Party::Requester)?;
        Connection::new(Party::Keystore, token, self.kem.clone())
    }
}

// ---- both sides ------------------------------------------------------------------

/// A live connection, from one side's point of view.
pub struct Connection {
    role: Party,
    token: Token,
    kem: KeyPair,
    seen: Seen,
}

impl Connection {
    /// Rebuilds a connection from stored parts. The token must carry both signatures, and
    /// `kem` must be this side's key in it.
    pub fn new(role: Party, token: Token, kem: KeyPair) -> Result<Self> {
        token.verify(Party::Keystore)?;
        token.verify(Party::Requester)?;
        if token.body.keys(role).kem != kem.public() {
            return Err(Error::Malformed("key is not this side's key in the token"));
        }
        Ok(Self {
            role,
            token,
            kem,
            seen: Seen::default(),
        })
    }

    pub fn role(&self) -> Party {
        self.role
    }

    pub fn token(&self) -> &Token {
        &self.token
    }

    pub fn id(&self) -> [u8; 32] {
        self.token.id()
    }

    pub fn expires_at(&self) -> u64 {
        self.token.body.expires_at
    }

    pub fn relay(&self) -> &str {
        &self.token.body.relay
    }

    pub fn my_inbox(&self) -> InboxId {
        self.token.body.keys(self.role).sig
    }

    pub fn peer(&self) -> &PartyKeys {
        self.token.body.keys(self.role.other())
    }

    pub fn peer_inbox(&self) -> InboxId {
        self.peer().sig
    }

    /// Seals `msg` for the peer's inbox.
    pub fn seal(&self, msg: &Message) -> Result<Vec<u8>> {
        let peer = self.peer();
        Ok(envelope::seal_message(&self.kem, peer.kem, &peer.sig, &msg.to_json())?.to_bytes())
    }

    /// Opens a message from the peer read from this side's inbox, with replay checks.
    pub fn open(&mut self, bytes: &[u8], now: u64) -> Result<Message> {
        let env = Envelope::parse(bytes)?;
        let peer = *self.peer();
        let pt = envelope::open_message(&env, &self.kem, peer.kem, &self.my_inbox())?;
        let msg = Message::from_json(&pt)?;
        self.seen.check(&msg, now)?;
        Ok(msg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::{Empty, SignRequest};

    const ACCOUNT: &str = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";
    const NOW: u64 = 1_762_776_000;

    fn sign_ok(_: &str) -> Result<String> {
        Ok(format!("0x{}", "11".repeat(65)))
    }

    fn connect() -> (Connection, Connection) {
        let attempt = ConnectAttempt::new("https://relay.example.com", "Example", None).unwrap();
        let offer = Offer::from_uri(&attempt.uri()).unwrap();
        let signer = Keys::generate();
        let acc = accept_offer(&offer, &signer, ACCOUNT, NOW, NOW + 86400, sign_ok).unwrap();
        assert_eq!(acc.requester_inbox, attempt.keys().inbox());
        let cand = attempt.open_bind(&acc.bind, NOW + 2).unwrap();
        assert_eq!(cand.account, ACCOUNT);
        assert!(cand.statement.contains("Site: Example (claimed)"));
        let (req_conn, bound) = attempt.accept(cand, NOW + 3).unwrap();
        let ks_conn = acc.pending.open_bound(&bound, NOW + 4).unwrap();
        assert_eq!(req_conn.id(), ks_conn.id());
        (req_conn, ks_conn)
    }

    #[test]
    fn full_connect_and_messages_both_ways() {
        let (mut r, mut k) = connect();
        assert_eq!(r.peer_inbox(), k.my_inbox());
        let req = Message::at(
            Body::SignRequest(SignRequest {
                chain: "eip155:1".into(),
                kind: "evm.personal_sign".into(),
                payload: serde_json::json!({"message": "0x68"}),
                origin: None,
                expires_at: NOW + 300,
            }),
            NOW + 5,
        );
        let bytes = r.seal(&req).unwrap();
        assert_eq!(k.open(&bytes, NOW + 6).unwrap(), req);
        assert!(matches!(k.open(&bytes, NOW + 6), Err(Error::Replay)));
        let bye = Message::reply_at(req.id, Body::Unbind(Empty {}), NOW + 7);
        assert_eq!(r.open(&k.seal(&bye).unwrap(), NOW + 8).unwrap(), bye);
    }

    #[test]
    fn messages_from_other_connections_are_rejected() {
        let (_, mut k1) = connect();
        let (r2, _) = connect();
        let msg = Message::at(Body::Unbind(Empty {}), NOW);
        assert!(k1.open(&r2.seal(&msg).unwrap(), NOW).is_err());
    }

    #[test]
    fn bind_checks() {
        let attempt = ConnectAttempt::new("https://relay.example.com", "Example", None).unwrap();
        let offer = attempt.offer().clone();
        let signer = Keys::generate();
        let bind = |offer: &Offer, now, sign: fn(&str) -> Result<String>| {
            accept_offer(offer, &signer, ACCOUNT, now, now + 86400, sign)
                .unwrap()
                .bind
        };
        // Fine.
        attempt.open_bind(&bind(&offer, NOW, sign_ok), NOW).unwrap();
        // Stale.
        assert!(
            attempt
                .open_bind(&bind(&offer, NOW - 400, sign_ok), NOW)
                .is_err()
        );
        // For another attempt (different requester keys) — doesn't even open.
        let other = ConnectAttempt::new("https://relay.example.com", "Example", None).unwrap();
        assert!(
            attempt
                .open_bind(&bind(other.offer(), NOW, sign_ok), NOW)
                .is_err()
        );
        // Another relay in the offer the keystore saw.
        let moved = Offer {
            relay: "https://evil.example".into(),
            ..offer.clone()
        };
        assert!(attempt.open_bind(&bind(&moved, NOW, sign_ok), NOW).is_err());
        // A different label (the statement no longer matches what the requester showed).
        let renamed = Offer {
            label: "Other".into(),
            ..offer.clone()
        };
        assert!(
            attempt
                .open_bind(&bind(&renamed, NOW, sign_ok), NOW)
                .is_err()
        );
        // A different ticket.
        let reticketed = Offer {
            ticket: Ticket::generate(),
            ..offer.clone()
        };
        assert!(
            attempt
                .open_bind(&bind(&reticketed, NOW, sign_ok), NOW)
                .is_err()
        );
        // Wrong PSK.
        let wrong_psk = Offer {
            psk: Psk::generate(),
            ..offer.clone()
        };
        assert!(
            attempt
                .open_bind(&bind(&wrong_psk, NOW, sign_ok), NOW)
                .is_err()
        );
        // Too long a lifetime.
        let long = accept_offer(&offer, &signer, ACCOUNT, NOW, NOW + 91 * 86400, sign_ok).unwrap();
        assert!(attempt.open_bind(&long.bind, NOW).is_err());
    }

    #[test]
    fn bind_from_a_key_other_than_the_tokens_is_rejected() {
        let attempt = ConnectAttempt::new("https://relay.example.com", "Example", None).unwrap();
        let offer = attempt.offer().clone();
        let signer = Keys::generate();
        let acc = accept_offer(&offer, &signer, ACCOUNT, NOW, NOW + 86400, sign_ok).unwrap();
        // Re-seal the same plaintext from a different X25519 key: spk ≠ token's k.
        let env = Envelope::parse(&acc.bind).unwrap();
        let pt = envelope::open_bind(
            &env,
            &attempt.keys().kem,
            &offer.psk,
            &attempt.keys().inbox(),
        )
        .unwrap();
        let resealed = envelope::seal_bind(
            &KeyPair::generate(),
            offer.requester.kem,
            &offer.psk,
            &offer.requester.sig,
            &pt,
        )
        .unwrap();
        assert!(attempt.open_bind(&resealed.to_bytes(), NOW).is_err());
    }

    #[test]
    fn bound_must_carry_the_countersigned_token() {
        let attempt = ConnectAttempt::new("https://relay.example.com", "Example", None).unwrap();
        let acc = accept_offer(
            attempt.offer(),
            &Keys::generate(),
            ACCOUNT,
            NOW,
            NOW + 86400,
            sign_ok,
        )
        .unwrap();
        let cand = attempt.open_bind(&acc.bind, NOW).unwrap();
        // A bound with the half-signed token.
        let half = Message::at(
            Body::Bound(Bound {
                token: cand.token.to_header(),
            }),
            NOW,
        );
        let b = &cand.token.body;
        let env = envelope::seal_message(
            &attempt.keys().kem,
            b.keystore.kem,
            &b.keystore.sig,
            &half.to_json(),
        )
        .unwrap();
        assert!(acc.pending.open_bound(&env.to_bytes(), NOW).is_err());
        let (_, bound) = attempt.accept(cand, NOW).unwrap();
        acc.pending.open_bound(&bound, NOW).unwrap();
    }

    #[test]
    fn stored_parts_rebuild_a_connection() {
        let (r, _) = connect();
        let again = Connection::new(
            Party::Requester,
            Token::from_bytes(&r.token().to_bytes()).unwrap(),
            KeyPair::from_secret_bytes(&r.kem.to_secret_bytes()).unwrap(),
        )
        .unwrap();
        assert_eq!(again.id(), r.id());
        assert!(Connection::new(Party::Requester, r.token().clone(), KeyPair::generate()).is_err());
    }
}
