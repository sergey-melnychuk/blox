//! A keystore stand-in for tests and local runs (BLOX.md §13.1).
//!
//! It holds signers (each with its transport keys `K`/`k`), accepts offers from QR
//! strings, keeps connections, reads its inboxes, and answers requests with a
//! caller-supplied handler. Delivery follows §10.6: a request is acknowledged only once it
//! is answered, cancelled or expired, and answers are stored so a redelivered request gets
//! the same answer again.

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use blox_client::{Error, RelayClient, Result, WriteAuth};
use blox_evm::PrivateKeySigner;
use blox_proto::connection::{Connection, Keys, PendingConnection, accept_offer};
use blox_proto::envelope::Envelope;
use blox_proto::keys::PublicKey;
use blox_proto::message::{Body, Empty, Message, MsgId, SignRequest, SignResponse};
use blox_proto::offer::Offer;
use tokio::sync::oneshot;

/// One seed's account plus its transport keys.
pub struct Signer {
    pub label: String,
    pub key: PrivateKeySigner,
    pub transport: Keys,
}

impl Signer {
    pub fn from_mnemonic(label: &str, phrase: &str, index: u32) -> Self {
        Self {
            label: label.to_owned(),
            key: blox_evm::sign::signer_from_mnemonic(phrase, index).expect("valid test mnemonic"),
            transport: Keys::generate(),
        }
    }

    /// Checksummed address.
    pub fn address(&self) -> String {
        self.key.address().to_checksum(None)
    }
}

/// What a handler sees for one request.
pub struct RequestCtx {
    pub signer: Arc<Signer>,
    pub connection_label: String,
    pub id: MsgId,
    /// The message's `ts` and the keystore's (relay) time.
    pub ts: u64,
    pub now: u64,
    pub request: SignRequest,
}

/// Answers a request; `None` leaves it unanswered (the user hasn't acted).
pub type Handler = Arc<
    dyn Fn(RequestCtx) -> Pin<Box<dyn Future<Output = Option<SignResponse>> + Send>> + Send + Sync,
>;

/// Builds a [`Handler`] from a synchronous closure.
pub fn handler(f: impl Fn(&RequestCtx) -> Option<SignResponse> + Send + Sync + 'static) -> Handler {
    let f = Arc::new(f);
    Arc::new(move |ctx| {
        let out = f(&ctx);
        Box::pin(async move { out })
    })
}

#[derive(Clone, Debug)]
pub struct ConnectionInfo {
    pub id: [u8; 32],
    pub label: String,
    pub account: String,
    pub signer: usize,
    pub relay: String,
    pub expires_at: u64,
}

pub struct Options {
    /// How long to wait for `bound` before revoking the token (§5.4).
    pub bound_timeout: Duration,
    /// Test hook: sign the statement with the wrong key.
    pub wrong_statement_key: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            bound_timeout: Duration::from_secs(120),
            wrong_statement_key: false,
        }
    }
}

struct Entry {
    signer: usize,
    conn: Connection,
    label: String,
    account: String,
}

struct Pending {
    signer: usize,
    pending: PendingConnection,
    done: oneshot::Sender<Connection>,
}

#[derive(Default)]
struct State {
    connections: HashMap<[u8; 32], Entry>,
    /// Pending connects, by the requester's X25519 key.
    pending: HashMap<[u8; 32], Pending>,
    /// Request id → stored answer (sealed), for redelivery.
    answers: HashMap<MsgId, Vec<u8>>,
    /// Requests seen but not answered yet: id → relay seq.
    open_requests: HashMap<MsgId, u64>,
    cancelled: HashSet<MsgId>,
    /// Envelope digest → message id, to recognise redeliveries.
    delivered: HashMap<[u8; 32], MsgId>,
    handled: usize,
}

struct Inner {
    signers: Vec<Arc<Signer>>,
    handler: Handler,
    options: Options,
    state: Mutex<State>,
    relays: Mutex<HashMap<String, RelayClient>>,
    readers: Mutex<HashMap<(String, usize), tokio::task::JoinHandle<()>>>,
    online: AtomicBool,
}

#[derive(Clone)]
pub struct MockKeystore(Arc<Inner>);

impl MockKeystore {
    pub fn new(signers: Vec<Signer>, handler: Handler) -> Self {
        Self::with_options(signers, handler, Options::default())
    }

    pub fn with_options(signers: Vec<Signer>, handler: Handler, options: Options) -> Self {
        Self(Arc::new(Inner {
            signers: signers.into_iter().map(Arc::new).collect(),
            handler,
            options,
            state: Mutex::default(),
            relays: Mutex::default(),
            readers: Mutex::default(),
            online: AtomicBool::new(true),
        }))
    }

    pub fn signer(&self, i: usize) -> &Arc<Signer> {
        &self.0.signers[i]
    }

    fn relay(&self, url: &str) -> RelayClient {
        self.0
            .relays
            .lock()
            .unwrap()
            .entry(url.to_owned())
            .or_insert_with(|| RelayClient::new(url))
            .clone()
    }

    /// Accepts the offer behind `uri` for signer `signer`, remembering it for `lifetime`.
    /// Returns once `bound` arrives; without it, revokes the token (§5.4).
    pub async fn accept(
        &self,
        uri: &str,
        signer: usize,
        lifetime: Duration,
    ) -> Result<ConnectionInfo> {
        let offer = Offer::from_uri(uri)?;
        let relay = self.relay(&offer.relay);
        relay.sync_time().await?;
        self.ensure_reader(&offer.relay, signer);
        let s = self.0.signers[signer].clone();
        let now = relay.now();
        let statement_key = if self.0.options.wrong_statement_key {
            PrivateKeySigner::random()
        } else {
            s.key.clone()
        };
        let acc = accept_offer(
            &offer,
            &s.transport,
            &s.address(),
            now,
            now + lifetime.as_secs(),
            |text| Ok(blox_evm::connect::sign_statement(&statement_key, text)),
        )?;
        let (done, wait) = oneshot::channel();
        let half = acc.pending.token().clone();
        let label = acc.pending.label.clone();
        let account = acc.pending.account.clone();
        self.0.state.lock().unwrap().pending.insert(
            acc.pending.requester_kem().0,
            Pending {
                signer,
                pending: acc.pending,
                done,
            },
        );
        let posted = relay
            .post(
                &acc.requester_inbox,
                WriteAuth::Ticket(&acc.ticket),
                &acc.bind,
            )
            .await;
        if let Err(e) = posted {
            self.0
                .state
                .lock()
                .unwrap()
                .pending
                .remove(&half.body.requester.kem.0);
            return Err(e);
        }
        match tokio::time::timeout(self.0.options.bound_timeout, wait).await {
            Ok(Ok(conn)) => {
                let info = ConnectionInfo {
                    id: conn.id(),
                    label: label.clone(),
                    account: account.clone(),
                    signer,
                    relay: offer.relay.clone(),
                    expires_at: conn.expires_at(),
                };
                self.0.state.lock().unwrap().connections.insert(
                    conn.id(),
                    Entry {
                        signer,
                        conn,
                        label,
                        account,
                    },
                );
                Ok(info)
            }
            _ => {
                self.0
                    .state
                    .lock()
                    .unwrap()
                    .pending
                    .remove(&half.body.requester.kem.0);
                let _ = relay.revoke(&half, &s.transport.sig).await;
                Err(Error::Timeout)
            }
        }
    }

    pub fn connections(&self) -> Vec<ConnectionInfo> {
        let st = self.0.state.lock().unwrap();
        st.connections
            .values()
            .map(|e| ConnectionInfo {
                id: e.conn.id(),
                label: e.label.clone(),
                account: e.account.clone(),
                signer: e.signer,
                relay: e.conn.relay().to_owned(),
                expires_at: e.conn.expires_at(),
            })
            .collect()
    }

    /// Requests handled (answered) so far.
    pub fn handled(&self) -> usize {
        self.0.state.lock().unwrap().handled
    }

    /// Requests waiting for an answer.
    pub fn open_requests(&self) -> usize {
        self.0.state.lock().unwrap().open_requests.len()
    }

    pub fn was_cancelled(&self, id: &MsgId) -> bool {
        self.0.state.lock().unwrap().cancelled.contains(id)
    }

    /// Ends a connection from the keystore side: `unbind` and revoke (§5.5).
    pub async fn disconnect(&self, id: &[u8; 32]) -> Result<()> {
        let entry = self.0.state.lock().unwrap().connections.remove(id);
        let Some(e) = entry else { return Ok(()) };
        let relay = self.relay(e.conn.relay());
        let signer = &self.0.signers[e.signer];
        let bye = Message::at(Body::Unbind(Empty {}), relay.now());
        let auth = WriteAuth::Token {
            token: e.conn.token(),
            signer: &signer.transport.sig,
        };
        let _ = relay
            .post(&e.conn.peer_inbox(), auth, &e.conn.seal(&bye)?)
            .await;
        relay.revoke(e.conn.token(), &signer.transport.sig).await
    }

    /// Stops reading inboxes (the app went to the background).
    pub fn go_offline(&self) {
        self.0.online.store(false, Ordering::SeqCst);
        for (_, h) in self.0.readers.lock().unwrap().drain() {
            h.abort();
        }
    }

    /// Starts reading every inbox that has connections (the app was opened).
    pub fn go_online(&self) {
        self.0.online.store(true, Ordering::SeqCst);
        let wanted: HashSet<(String, usize)> = {
            let st = self.0.state.lock().unwrap();
            st.connections
                .values()
                .map(|e| (e.conn.relay().to_owned(), e.signer))
                .collect()
        };
        for (relay, signer) in wanted {
            self.ensure_reader(&relay, signer);
        }
    }

    fn ensure_reader(&self, relay_url: &str, signer: usize) {
        if !self.0.online.load(Ordering::SeqCst) {
            return;
        }
        let mut readers = self.0.readers.lock().unwrap();
        let key = (relay_url.to_owned(), signer);
        if readers.get(&key).is_some_and(|h| !h.is_finished()) {
            return;
        }
        let me = self.clone();
        let relay = self.relay(relay_url);
        readers.insert(
            key,
            tokio::spawn(async move { me.read_loop(relay, signer).await }),
        );
    }

    async fn read_loop(self, relay: RelayClient, signer: usize) {
        let s = self.0.signers[signer].clone();
        let mut sub = relay.subscribe(s.transport.sig.clone());
        while let Some(d) = sub.next().await {
            let Ok(d) = d else { return };
            let ack = self.handle(&relay, signer, &d.body, d.seq).await;
            if ack {
                let _ = relay.ack(&s.transport.sig, d.seq).await;
            }
        }
    }

    /// Handles one delivery; returns whether to acknowledge it now.
    async fn handle(&self, relay: &RelayClient, signer: usize, bytes: &[u8], seq: u64) -> bool {
        let now = relay.now();
        let Ok(env) = Envelope::parse(bytes) else {
            return true;
        };
        // A `bound` for a pending connect?
        let pending = self.0.state.lock().unwrap().pending.remove(&env.spk.0);
        if let Some(p) = pending {
            if p.signer == signer
                && let Ok(conn) = p.pending.open_bound(bytes, now)
            {
                let _ = p.done.send(conn);
            }
            return true;
        }
        let opened = {
            let mut st = self.0.state.lock().unwrap();
            let Some(entry) = find_by_peer(&mut st.connections, signer, env.spk) else {
                return true; // not from a live connection: drop (§10.4)
            };
            let label = entry.label.clone();
            entry
                .conn
                .open(bytes, now)
                .map(|m| (m, label, entry.conn.id()))
        };
        let (msg, label, conn_id) = match opened {
            Ok(x) => {
                self.0
                    .state
                    .lock()
                    .unwrap()
                    .delivered
                    .insert(digest(bytes), x.0.id);
                x
            }
            Err(blox_proto::Error::Replay) => {
                // Redelivered: answer again from the stored answer, if any.
                return self.resend_if_answered(relay, signer, bytes, env.spk).await;
            }
            Err(_) => return true,
        };
        match msg.body {
            Body::SignRequest(request) => {
                let stored = {
                    let mut st = self.0.state.lock().unwrap();
                    if st.cancelled.contains(&msg.id) {
                        return true;
                    }
                    let stored = st.answers.get(&msg.id).cloned();
                    if stored.is_none() {
                        st.open_requests.insert(msg.id, seq);
                    }
                    stored
                };
                if let Some(answer) = stored {
                    return self.post_answer(relay, signer, &conn_id, answer).await;
                }
                let ctx = RequestCtx {
                    signer: self.0.signers[signer].clone(),
                    connection_label: label,
                    id: msg.id,
                    ts: msg.ts,
                    now,
                    request,
                };
                let Some(resp) = (self.0.handler)(ctx).await else {
                    return false; // unanswered: stays on the relay
                };
                let sealed = {
                    let mut st = self.0.state.lock().unwrap();
                    if st.cancelled.contains(&msg.id) {
                        st.open_requests.remove(&msg.id);
                        return true;
                    }
                    let Some(entry) = st.connections.get(&conn_id) else {
                        return true;
                    };
                    let reply = Message::reply_at(msg.id, Body::SignResponse(resp), relay.now());
                    let Ok(sealed) = entry.conn.seal(&reply) else {
                        return true;
                    };
                    st.answers.insert(msg.id, sealed.clone());
                    st.open_requests.remove(&msg.id);
                    st.handled += 1;
                    sealed
                };
                self.post_answer(relay, signer, &conn_id, sealed).await
            }
            Body::Cancel(_) => {
                if let Some(re) = msg.re {
                    let mut st = self.0.state.lock().unwrap();
                    st.cancelled.insert(re);
                    if let Some(req_seq) = st.open_requests.remove(&re) {
                        let relay = relay.clone();
                        let key = self.0.signers[signer].transport.sig.clone();
                        tokio::spawn(async move {
                            let _ = relay.ack(&key, req_seq).await;
                        });
                    }
                }
                true
            }
            Body::Unbind(_) => {
                self.0.state.lock().unwrap().connections.remove(&conn_id);
                true
            }
            _ => true,
        }
    }

    /// A redelivered message (already opened once): answer again from the stored answer;
    /// leave an unanswered request on the relay.
    async fn resend_if_answered(
        &self,
        relay: &RelayClient,
        signer: usize,
        bytes: &[u8],
        spk: PublicKey,
    ) -> bool {
        let (conn_id, id) = {
            let mut st = self.0.state.lock().unwrap();
            let Some(conn_id) = find_by_peer(&mut st.connections, signer, spk).map(|e| e.conn.id())
            else {
                return true;
            };
            (conn_id, st.delivered.get(&digest(bytes)).copied())
        };
        let Some(id) = id else { return true };
        let answer = self.0.state.lock().unwrap().answers.get(&id).cloned();
        match answer {
            Some(a) => self.post_answer(relay, signer, &conn_id, a).await,
            None => !self.0.state.lock().unwrap().open_requests.contains_key(&id),
        }
    }

    async fn post_answer(
        &self,
        relay: &RelayClient,
        signer: usize,
        conn_id: &[u8; 32],
        sealed: Vec<u8>,
    ) -> bool {
        let (token, peer) = {
            let st = self.0.state.lock().unwrap();
            let Some(e) = st.connections.get(conn_id) else {
                return true;
            };
            (e.conn.token().clone(), e.conn.peer_inbox())
        };
        let auth = WriteAuth::Token {
            token: &token,
            signer: &self.0.signers[signer].transport.sig,
        };
        // Acknowledge only once the answer is out; otherwise the relay redelivers.
        relay.post(&peer, auth, &sealed).await.is_ok()
    }
}

fn find_by_peer(
    conns: &mut HashMap<[u8; 32], Entry>,
    signer: usize,
    spk: PublicKey,
) -> Option<&mut Entry> {
    conns
        .values_mut()
        .find(|e| e.signer == signer && e.conn.peer().kem == spk)
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    use sha2::Digest as _;
    sha2::Sha256::digest(bytes).into()
}
