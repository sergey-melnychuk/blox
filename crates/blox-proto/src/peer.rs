//! Sans-IO session state machines for both ends (§5).
//!
//! Callers do the networking: post the returned `(mailbox, bytes)` pairs to the
//! relay and feed envelopes read from their own mailbox into `on_envelope`.

use crate::envelope::{self, Envelope, Kind};
use crate::keys::{KeyPair, Psk, PublicKey};
use crate::mailbox::{MailboxId, ReadSecret};
use crate::message::{Body, Close, CloseReason, Hello, Message, MsgId, SignRequest, SignResponse};
use crate::replay::Seen;
use crate::session::SessionPayload;
use crate::{Error, Result};

/// An envelope to post: `(recipient mailbox, envelope bytes)`.
pub type Outgoing = (MailboxId, Vec<u8>);

#[derive(Debug, PartialEq)]
pub enum AdapterEvent {
    /// The first valid hello: the session is now joined.
    Joined,
    /// A second valid hello arrived. The session is aborted; post these `close` messages.
    Contested(Vec<Outgoing>),
    Response {
        re: MsgId,
        response: SignResponse,
    },
    Closed(CloseReason),
    /// Valid but irrelevant (e.g. a duplicate delivery).
    Ignored,
}

struct Peer {
    pk: PublicKey,
    mailbox: MailboxId,
}

/// The adapter end: creates the session and its QR payload.
pub struct AdapterSession {
    kp: KeyPair,
    read_secret: ReadSecret,
    ma: MailboxId,
    psk: Psk,
    payload: SessionPayload,
    peer: Option<Peer>,
    seen: Seen,
    closed: bool,
}

impl AdapterSession {
    pub fn new(relay: &str, label: &str) -> Self {
        let kp = KeyPair::generate();
        let read_secret = ReadSecret::generate();
        let ma = read_secret.mailbox_id();
        let psk = Psk::generate();
        let payload = SessionPayload::new(relay, kp.public(), ma, psk.clone(), label);
        Self {
            kp,
            read_secret,
            ma,
            psk,
            payload,
            peer: None,
            seen: Seen::default(),
            closed: false,
        }
    }

    /// The `blox:s?p=…` string to render as a QR code.
    pub fn uri(&self) -> String {
        self.payload.to_uri()
    }

    pub fn read_secret(&self) -> &ReadSecret {
        &self.read_secret
    }

    pub fn is_joined(&self) -> bool {
        self.peer.is_some() && !self.closed
    }

    pub fn is_closed(&self) -> bool {
        self.closed
    }

    pub fn on_envelope(&mut self, bytes: &[u8], now: u64) -> Result<AdapterEvent> {
        let env = Envelope::parse(bytes)?;
        match env.kind {
            Kind::Hello => {
                let spk = env.spk.ok_or(Error::Malformed("hello without spk"))?;
                let msg = self.open(&env, spk, now)?;
                let Body::Hello(Hello { mk }) = msg.body else {
                    return Err(Error::Malformed("hello envelope without hello body"));
                };
                match &self.peer {
                    None if !self.closed => {
                        self.peer = Some(Peer {
                            pk: spk,
                            mailbox: mk,
                        });
                        Ok(AdapterEvent::Joined)
                    }
                    Some(first) if first.pk == spk => Ok(AdapterEvent::Ignored),
                    _ => {
                        let mut out = Vec::new();
                        if let Some(first) = self.peer.take() {
                            out.push(self.seal_to(first.pk, &first.mailbox, contested())?);
                        }
                        out.push(self.seal_to(spk, &mk, contested())?);
                        self.closed = true;
                        Ok(AdapterEvent::Contested(out))
                    }
                }
            }
            Kind::Message => {
                let peer_pk = self
                    .peer
                    .as_ref()
                    .ok_or(Error::Malformed("message before hello"))?
                    .pk;
                let msg = self.open(&env, peer_pk, now)?;
                match msg.body {
                    Body::SignResponse(response) => {
                        let re = msg.re.ok_or(Error::Malformed("response without re"))?;
                        Ok(AdapterEvent::Response { re, response })
                    }
                    Body::Close(Close { reason }) => {
                        self.closed = true;
                        Ok(AdapterEvent::Closed(reason))
                    }
                    _ => Err(Error::Malformed("unexpected message for adapter")),
                }
            }
        }
    }

    /// Seals a signing request to the joined keystore.
    pub fn request(&self, req: SignRequest) -> Result<(MsgId, Outgoing)> {
        let peer = self.joined_peer()?;
        let msg = Message::new(Body::SignRequest(req));
        let id = msg.id;
        Ok((id, self.seal_to(peer.pk, &peer.mailbox, msg)?))
    }

    /// Closes the session; returns the `close` to post if a keystore had joined.
    pub fn close(&mut self, reason: CloseReason) -> Result<Option<Outgoing>> {
        let out = match (&self.peer, self.closed) {
            (Some(peer), false) => Some(self.seal_to(peer.pk, &peer.mailbox, close(reason))?),
            _ => None,
        };
        self.closed = true;
        Ok(out)
    }

    fn joined_peer(&self) -> Result<&Peer> {
        match (&self.peer, self.closed) {
            (Some(p), false) => Ok(p),
            _ => Err(Error::Malformed("session not joined")),
        }
    }

    fn open(&mut self, env: &Envelope, sender: PublicKey, now: u64) -> Result<Message> {
        let pt = envelope::open(env, &self.kp, sender, &self.psk, &self.ma)?;
        let msg = Message::from_json(&pt)?;
        self.seen.check(&msg, now)?;
        Ok(msg)
    }

    fn seal_to(&self, pk: PublicKey, mailbox: &MailboxId, msg: Message) -> Result<Outgoing> {
        let env = envelope::seal(
            Kind::Message,
            &self.kp,
            pk,
            &self.psk,
            mailbox,
            &msg.to_json(),
        )?;
        Ok((*mailbox, env.to_bytes()))
    }
}

#[derive(Debug, PartialEq)]
pub enum KeystoreEvent {
    Request(Box<Message>),
    Closed(CloseReason),
}

/// The keystore end: joins a session from a scanned QR payload.
pub struct KeystoreSession {
    kp: KeyPair,
    read_secret: ReadSecret,
    mk: MailboxId,
    payload: SessionPayload,
    seen: Seen,
    closed: bool,
}

impl KeystoreSession {
    /// Parses the QR payload and builds the `hello` to post to the adapter's mailbox.
    pub fn join(uri: &str) -> Result<(Self, Outgoing)> {
        let payload = SessionPayload::from_uri(uri)?;
        let kp = KeyPair::generate();
        let read_secret = ReadSecret::generate();
        let mk = read_secret.mailbox_id();
        let hello = Message::new(Body::Hello(Hello { mk }));
        let env = envelope::seal(
            Kind::Hello,
            &kp,
            payload.apk,
            &payload.psk,
            &payload.ma,
            &hello.to_json(),
        )?;
        let out = (payload.ma, env.to_bytes());
        Ok((
            Self {
                kp,
                read_secret,
                mk,
                payload,
                seen: Seen::default(),
                closed: false,
            },
            out,
        ))
    }

    pub fn relay(&self) -> &str {
        &self.payload.relay
    }

    pub fn label(&self) -> &str {
        &self.payload.label
    }

    pub fn read_secret(&self) -> &ReadSecret {
        &self.read_secret
    }

    pub fn is_closed(&self) -> bool {
        self.closed
    }

    pub fn on_envelope(&mut self, bytes: &[u8], now: u64) -> Result<KeystoreEvent> {
        let env = Envelope::parse(bytes)?;
        if env.kind != Kind::Message {
            return Err(Error::Malformed("keystore expects messages only"));
        }
        let pt = envelope::open(
            &env,
            &self.kp,
            self.payload.apk,
            &self.payload.psk,
            &self.mk,
        )?;
        let msg = Message::from_json(&pt)?;
        self.seen.check(&msg, now)?;
        match msg.body {
            Body::SignRequest(_) => Ok(KeystoreEvent::Request(Box::new(msg))),
            Body::Close(Close { reason }) => {
                self.closed = true;
                Ok(KeystoreEvent::Closed(reason))
            }
            _ => Err(Error::Malformed("unexpected message for keystore")),
        }
    }

    pub fn respond(&self, request: &Message, response: SignResponse) -> Result<Outgoing> {
        self.seal(Message::reply(request, Body::SignResponse(response)))
    }

    pub fn close(&mut self, reason: CloseReason) -> Result<Option<Outgoing>> {
        if self.closed {
            return Ok(None);
        }
        self.closed = true;
        self.seal(close(reason)).map(Some)
    }

    fn seal(&self, msg: Message) -> Result<Outgoing> {
        let p = &self.payload;
        let env = envelope::seal(
            Kind::Message,
            &self.kp,
            p.apk,
            &p.psk,
            &p.ma,
            &msg.to_json(),
        )?;
        Ok((p.ma, env.to_bytes()))
    }
}

fn close(reason: CloseReason) -> Message {
    Message::new(Body::Close(Close { reason }))
}

fn contested() -> Message {
    close(CloseReason::Contested)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::{RejectReason, now};

    fn request() -> SignRequest {
        SignRequest {
            chain: "eip155:1".into(),
            account: "eip155:1:0x0000000000000000000000000000000000000001".into(),
            kind: "evm.personal_sign".into(),
            payload: serde_json::json!({"message": "0x68"}),
            origin: None,
            expires_at: now() + 300,
        }
    }

    #[test]
    fn full_exchange() {
        let mut a = AdapterSession::new("https://relay.example.com", "laptop");
        let (mut k, (to, hello)) = KeystoreSession::join(&a.uri()).unwrap();
        assert_eq!(to, a.read_secret().mailbox_id());
        assert_eq!(k.label(), "laptop");
        assert_eq!(a.on_envelope(&hello, now()).unwrap(), AdapterEvent::Joined);
        // At-least-once delivery: the same hello again is a replay, not a contest.
        assert!(matches!(a.on_envelope(&hello, now()), Err(Error::Replay)));

        let (id, (to, req)) = a.request(request()).unwrap();
        assert_eq!(to, k.read_secret().mailbox_id());
        let KeystoreEvent::Request(msg) = k.on_envelope(&req, now()).unwrap() else {
            panic!()
        };
        assert_eq!(msg.id, id);

        let resp = SignResponse::Rejected {
            reason: RejectReason::User,
        };
        let (_, bytes) = k.respond(&msg, resp.clone()).unwrap();
        assert_eq!(
            a.on_envelope(&bytes, now()).unwrap(),
            AdapterEvent::Response {
                re: id,
                response: resp
            }
        );

        let (_, bye) = k.close(CloseReason::Done).unwrap().unwrap();
        assert_eq!(
            a.on_envelope(&bye, now()).unwrap(),
            AdapterEvent::Closed(CloseReason::Done)
        );
        assert!(a.request(request()).is_err());
    }

    #[test]
    fn second_join_contests_the_session() {
        let mut a = AdapterSession::new("https://relay.example.com", "laptop");
        let (mut k1, (_, h1)) = KeystoreSession::join(&a.uri()).unwrap();
        let (mut k2, (_, h2)) = KeystoreSession::join(&a.uri()).unwrap();
        a.on_envelope(&h1, now()).unwrap();
        let AdapterEvent::Contested(out) = a.on_envelope(&h2, now()).unwrap() else {
            panic!()
        };
        assert_eq!(out.len(), 2);
        assert!(a.is_closed());
        assert_eq!(
            k1.on_envelope(&out[0].1, now()).unwrap(),
            KeystoreEvent::Closed(CloseReason::Contested)
        );
        assert_eq!(
            k2.on_envelope(&out[1].1, now()).unwrap(),
            KeystoreEvent::Closed(CloseReason::Contested)
        );
    }

    #[test]
    fn foreign_session_messages_are_rejected() {
        let mut a1 = AdapterSession::new("https://relay.example.com", "one");
        let a2 = AdapterSession::new("https://relay.example.com", "two");
        let (mut k, (_, hello)) = KeystoreSession::join(&a1.uri()).unwrap();
        a1.on_envelope(&hello, now()).unwrap();
        // A hello sealed for a different session (different PSK and adapter key).
        let (_, (_, other_hello)) = KeystoreSession::join(&a2.uri()).unwrap();
        assert!(a1.on_envelope(&other_hello, now()).is_err());
        // A request from a different adapter.
        let (_, (_, req)) = {
            let mut a3 = AdapterSession::new("https://relay.example.com", "three");
            let (_, (_, h)) = KeystoreSession::join(&a3.uri()).unwrap();
            a3.on_envelope(&h, now()).unwrap();
            a3.request(request()).unwrap()
        };
        assert!(k.on_envelope(&req, now()).is_err());
    }

    #[test]
    fn stale_messages_are_rejected() {
        let mut a = AdapterSession::new("https://relay.example.com", "laptop");
        let (_, (_, hello)) = KeystoreSession::join(&a.uri()).unwrap();
        assert!(matches!(
            a.on_envelope(&hello, now() + 301),
            Err(Error::Stale)
        ));
    }
}
