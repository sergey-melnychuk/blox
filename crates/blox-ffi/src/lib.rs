//! Mobile bindings (UniFFI) for the keystore side of Blox (BLOX.md §10).
//!
//! The app does storage, HTTP, the Android Keystore and the UI. Everything else happens
//! here, in the same code the tests and the mock keystore use: offers, tokens, the
//! connection statement, envelopes, request checks, filling (through [`EndpointRpc`], which
//! the app implements over OkHttp), display, signing and relay request signatures.
//!
//! Secrets cross the boundary as byte arrays (never `String`, which can't be wiped on the
//! JVM). Rust wipes its copies; callers must wipe theirs. Times are relay time (§4.8).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use blox_evm::display::Display;
use blox_evm::keystore::{self, Approved, Endpoint, ReviewError};
use blox_evm::rpc::{ChainRpc, RpcError};
use blox_evm::sign::signer_from_mnemonic;
use blox_evm::{Address, B256};
use blox_proto::connection::{Connection, Keys, PendingConnection, accept_offer};
use blox_proto::envelope::Envelope;
use blox_proto::ident::SigningKey;
use blox_proto::keys::KeyPair;
use blox_proto::message::{self, Body, Empty, Message, MsgId, SignRequest, SignResponse};
use blox_proto::offer::Offer;
use blox_proto::token::{Party, Token};
use blox_proto::{b64, relay_url, reqsig};
use zeroize::Zeroizing;

uniffi::setup_scaffolding!();

#[derive(Debug, thiserror::Error, uniffi::Error)]
#[uniffi(flat_error)]
pub enum FfiError {
    #[error("invalid QR code: {0}")]
    InvalidQr(String),
    #[error("invalid recovery phrase")]
    InvalidMnemonic,
    #[error("the key does not match the signer")]
    WrongAccount,
    #[error("unknown connection")]
    UnknownConnection,
    #[error("the QR code is for another relay")]
    WrongRelay,
    #[error("{0}")]
    Internal(String),
}

fn internal(e: impl std::fmt::Display) -> FfiError {
    FfiError::Internal(e.to_string())
}

// ---- keys and relay helpers ---------------------------------------------------------

/// A signer's transport keys (§2.1, §10.2). Store the secrets encrypted under the
/// non-authenticated wrapping key `blox.transport.wrap.v1`.
#[derive(uniffi::Record)]
pub struct TransportKeys {
    /// Ed25519 secret (`K`), 32 bytes.
    pub sig_secret: Vec<u8>,
    /// X25519 secret (`k`), 32 bytes.
    pub kem_secret: Vec<u8>,
    /// The signer's inbox id on every relay.
    pub inbox: String,
}

#[uniffi::export]
pub fn generate_transport_keys() -> TransportKeys {
    let k = Keys::generate();
    TransportKeys {
        sig_secret: k.sig.to_bytes().to_vec(),
        kem_secret: k.kem.to_secret_bytes().to_vec(),
        inbox: k.inbox().to_string(),
    }
}

fn keys_from(sig_secret: &[u8], kem_secret: &[u8]) -> Result<Keys, FfiError> {
    let sig: Zeroizing<[u8; 32]> = Zeroizing::new(
        sig_secret
            .try_into()
            .map_err(|_| internal("sig secret length"))?,
    );
    let kem: Zeroizing<[u8; 32]> = Zeroizing::new(
        kem_secret
            .try_into()
            .map_err(|_| internal("kem secret length"))?,
    );
    Ok(Keys {
        sig: SigningKey::from_bytes(&sig),
        kem: KeyPair::from_secret_bytes(&kem).map_err(internal)?,
    })
}

/// `Authorization` header for a relay request signed with the signer's `K` (§4.4).
/// `path` starts at `/v1/`. Wipes `sig_secret`.
#[uniffi::export]
pub fn sign_relay_request(
    sig_secret: Vec<u8>,
    method: String,
    path: String,
    ts: u64,
    body: Vec<u8>,
) -> Result<String, FfiError> {
    let secret = Zeroizing::new(sig_secret);
    let arr: Zeroizing<[u8; 32]> = Zeroizing::new(
        secret
            .as_slice()
            .try_into()
            .map_err(|_| internal("sig secret length"))?,
    );
    Ok(reqsig::sign(
        &SigningKey::from_bytes(&arr),
        &method,
        &path,
        ts,
        &body,
    ))
}

/// Normalizes a relay URL (§4.3); errors on anything but `http(s)://host[:port][/path]`.
#[uniffi::export]
pub fn normalize_relay_url(url: String) -> Result<String, FfiError> {
    relay_url::normalize(&url).map_err(internal)
}

/// The host shown to the user (`relay.example.com`).
#[uniffi::export]
pub fn relay_host(url: String) -> String {
    relay_url::host(&url).to_owned()
}

/// What the connect screen shows before anything is signed (§5.2 steps 1–3).
#[derive(uniffi::Record)]
pub struct OfferInfo {
    /// Normalized relay URL; check it against the relay list (§10.3).
    pub relay: String,
    pub relay_host: String,
    /// The requester's name (a claim).
    pub label: String,
}

#[uniffi::export]
pub fn parse_offer(uri: String) -> Result<OfferInfo, FfiError> {
    let o = Offer::from_uri(&uri).map_err(|e| FfiError::InvalidQr(e.to_string()))?;
    Ok(OfferInfo {
        relay_host: relay_url::host(&o.relay).to_owned(),
        relay: o.relay,
        label: o.label,
    })
}

// ---- endpoints ------------------------------------------------------------------------

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum RpcFailure {
    #[error("unreachable: {message}")]
    Unreachable { message: String },
    #[error("{message}")]
    Rpc { code: i64, message: String },
}

/// A chain endpoint the user configured (§10.3). The app implements this over HTTP:
/// POST a JSON-RPC request with `method` and `params_json` (a JSON array), return the
/// `result` as JSON text, or the JSON-RPC error. Called from background threads.
#[uniffi::export(with_foreign)]
pub trait EndpointRpc: Send + Sync {
    fn call(&self, method: String, params_json: String) -> Result<String, RpcFailure>;
}

struct RpcAdapter(Arc<dyn EndpointRpc>);

impl ChainRpc for RpcAdapter {
    fn call(&self, method: &str, params: serde_json::Value) -> Result<serde_json::Value, RpcError> {
        match self.0.call(method.to_owned(), params.to_string()) {
            Ok(json) => serde_json::from_str(&json)
                .map_err(|_| RpcError::Unreachable("the endpoint's answer is not JSON".into())),
            Err(RpcFailure::Unreachable { message }) => Err(RpcError::Unreachable(message)),
            Err(RpcFailure::Rpc { code, message }) => Err(RpcError::Rpc { code, message }),
        }
    }
}

/// The endpoint's chain id (`eth_chainId`), to check a new endpoint in Settings.
#[uniffi::export]
pub fn endpoint_chain_id(endpoint: Arc<dyn EndpointRpc>) -> Result<u64, FfiError> {
    blox_evm::rpc::Rpc(&RpcAdapter(endpoint))
        .chain_id()
        .map_err(internal)
}

// ---- display and responses ------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct UiField {
    pub label: String,
    pub value: String,
    pub full: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct UiDanger {
    pub message: String,
    /// Text the user must type to continue, if any.
    pub confirm: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct UiDisplay {
    pub title: String,
    pub fields: Vec<UiField>,
    pub decoded: Option<String>,
    pub dangers: Vec<UiDanger>,
    pub warnings: Vec<String>,
}

impl From<Display> for UiDisplay {
    fn from(d: Display) -> Self {
        Self {
            title: d.title,
            fields: d
                .fields
                .into_iter()
                .map(|f| UiField {
                    label: f.label,
                    value: f.value,
                    full: f.full,
                })
                .collect(),
            decoded: d.decoded,
            dangers: d
                .dangers
                .into_iter()
                .map(|x| UiDanger {
                    message: x.message,
                    confirm: x.confirm,
                })
                .collect(),
            warnings: d.warnings,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum RejectReason {
    User,
    Expired,
    Unsupported,
    DecodeFailed,
    NoEndpoint,
    WouldFail,
}

impl From<message::RejectReason> for RejectReason {
    fn from(r: message::RejectReason) -> Self {
        use message::RejectReason as R;
        match r {
            R::User => Self::User,
            R::Expired => Self::Expired,
            R::Unsupported => Self::Unsupported,
            R::DecodeFailed => Self::DecodeFailed,
            R::NoEndpoint => Self::NoEndpoint,
            R::WouldFail => Self::WouldFail,
        }
    }
}

impl From<RejectReason> for message::RejectReason {
    fn from(r: RejectReason) -> Self {
        match r {
            RejectReason::User => Self::User,
            RejectReason::Expired => Self::Expired,
            RejectReason::Unsupported => Self::Unsupported,
            RejectReason::DecodeFailed => Self::DecodeFailed,
            RejectReason::NoEndpoint => Self::NoEndpoint,
            RejectReason::WouldFail => Self::WouldFail,
        }
    }
}

/// An answer to a request (§6.4), for the audit log and the screen.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum Response {
    Sent {
        account: String,
        tx_hash: String,
    },
    SignedTx {
        account: String,
        tx_hash: String,
        raw: String,
    },
    Signed {
        account: String,
        signature: String,
    },
    Failed {
        account: String,
        tx_hash: String,
        error: String,
    },
    Rejected {
        reason: RejectReason,
    },
}

impl From<SignResponse> for Response {
    fn from(r: SignResponse) -> Self {
        match r {
            SignResponse::Sent { account, tx_hash } => Self::Sent { account, tx_hash },
            SignResponse::SignedTx {
                account,
                tx_hash,
                raw,
            } => Self::SignedTx {
                account,
                tx_hash,
                raw,
            },
            SignResponse::Signed { account, signature } => Self::Signed { account, signature },
            SignResponse::Failed {
                account,
                tx_hash,
                error,
            } => Self::Failed {
                account,
                tx_hash,
                error,
            },
            SignResponse::Rejected { reason } => Self::Rejected {
                reason: reason.into(),
            },
        }
    }
}

impl From<Response> for SignResponse {
    fn from(r: Response) -> Self {
        match r {
            Response::Sent { account, tx_hash } => Self::Sent { account, tx_hash },
            Response::SignedTx {
                account,
                tx_hash,
                raw,
            } => Self::SignedTx {
                account,
                tx_hash,
                raw,
            },
            Response::Signed { account, signature } => Self::Signed { account, signature },
            Response::Failed {
                account,
                tx_hash,
                error,
            } => Self::Failed {
                account,
                tx_hash,
                error,
            },
            Response::Rejected { reason } => Self::Rejected {
                reason: reason.into(),
            },
        }
    }
}

// ---- connections and the inbox --------------------------------------------------------

/// A connection, as the app stores it (unencrypted, §10.2).
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct ConnectionRecord {
    /// The token id, base64url: stable for the connection's life.
    pub id: String,
    /// The countersigned token (`Blox-Token` encoding).
    pub token: String,
    /// The requester's name (a claim).
    pub label: String,
    /// Checksummed address of the signer's account.
    pub account: String,
    pub relay: String,
    pub requester_inbox: String,
    pub issued_at: u64,
    pub expires_at: u64,
}

fn record(conn: &Connection, label: &str, account: &str) -> ConnectionRecord {
    let b = &conn.token().body;
    ConnectionRecord {
        id: b64::encode(conn.id()),
        token: conn.token().to_header(),
        label: label.to_owned(),
        account: account.to_owned(),
        relay: b.relay.clone(),
        requester_inbox: conn.peer_inbox().to_string(),
        issued_at: b.issued_at,
        expires_at: b.expires_at,
    }
}

/// An envelope to post: `POST {relay}/v1/inbox/{inbox}` with `Blox-Token: token` and the
/// request signed by the signer's `K`.
#[derive(Clone, Debug, uniffi::Record)]
pub struct Outgoing {
    pub inbox: String,
    pub body: Vec<u8>,
    pub token: String,
}

/// What [`Inbox::accept_offer`] produces (§5.2 step 5).
#[derive(uniffi::Record)]
pub struct BindToPost {
    /// Post to `POST {relay}/v1/inbox/{requester_inbox}` with `Blox-Ticket: ticket`
    /// (no Authorization). 409 → "already used"; 401 → "expired".
    pub requester_inbox: String,
    pub ticket: String,
    pub body: Vec<u8>,
    pub account: String,
}

/// One envelope read from the signer's inbox, as the app should treat it (§10.6).
#[derive(uniffi::Enum)]
pub enum Incoming {
    /// `bound` arrived: store the connection, acknowledge.
    Connected { connection: ConnectionRecord },
    /// A request to review. Acknowledge only once answered, cancelled or expired.
    Request { request: Arc<IncomingRequest> },
    /// A request opened before (in this process). If an answer is stored for `request_id`,
    /// post it again and acknowledge; if it's still pending, leave it.
    Redelivered {
        connection_id: String,
        request_id: String,
    },
    /// The requester withdrew `request_id`: drop it (§6.5). Acknowledge both.
    Cancelled {
        connection_id: String,
        request_id: String,
    },
    /// The requester ended the connection: forget it. Acknowledge.
    Unbound { connection_id: String },
    /// Not from a live connection, stale, or malformed: acknowledge and drop.
    Dropped,
}

struct Entry {
    conn: Connection,
    label: String,
}

struct InboxState {
    connections: HashMap<[u8; 32], Entry>,
    /// Pending connects, by the requester's X25519 key.
    pending: HashMap<[u8; 32], PendingConnection>,
    /// Envelope digest → (connection id, message id), to recognise redeliveries.
    delivered: HashMap<[u8; 32], ([u8; 32], MsgId)>,
}

/// One signer's inbox on one relay: its connections there and the protocol state.
#[derive(uniffi::Object)]
pub struct Inbox {
    relay: String,
    keys: Keys,
    signer: Address,
    state: Mutex<InboxState>,
}

#[uniffi::export]
impl Inbox {
    /// `relay` is normalized; `connections` are this signer's stored connections on it.
    #[uniffi::constructor]
    pub fn new(
        relay: String,
        sig_secret: Vec<u8>,
        kem_secret: Vec<u8>,
        signer_address: String,
        connections: Vec<ConnectionRecord>,
    ) -> Result<Arc<Self>, FfiError> {
        let (sig_secret, kem_secret) = (Zeroizing::new(sig_secret), Zeroizing::new(kem_secret));
        let keys = keys_from(&sig_secret, &kem_secret)?;
        let signer: Address = signer_address.parse().map_err(internal)?;
        let inbox = Self {
            relay: relay_url::normalize(&relay).map_err(internal)?,
            keys,
            signer,
            state: Mutex::new(InboxState {
                connections: HashMap::new(),
                pending: HashMap::new(),
                delivered: HashMap::new(),
            }),
        };
        for c in connections {
            inbox.add_connection(c)?;
        }
        Ok(Arc::new(inbox))
    }

    /// The inbox id (`GET /v1/inbox/{id}`), the signer's `K`.
    pub fn inbox_id(&self) -> String {
        self.keys.inbox().to_string()
    }

    pub fn add_connection(&self, connection: ConnectionRecord) -> Result<(), FfiError> {
        let token = Token::from_header(&connection.token).map_err(internal)?;
        let conn =
            Connection::new(Party::Keystore, token, self.keys.kem.clone()).map_err(internal)?;
        if conn.my_inbox() != self.keys.inbox() {
            return Err(internal("connection belongs to another signer"));
        }
        self.state.lock().unwrap().connections.insert(
            conn.id(),
            Entry {
                conn,
                label: connection.label,
            },
        );
        Ok(())
    }

    pub fn remove_connection(&self, connection_id: String) {
        if let Ok(id) = b64::decode_array::<32>(&connection_id) {
            self.state.lock().unwrap().connections.remove(&id);
        }
    }

    /// Builds the token, signs the statement with the account and seals `bind`
    /// (§5.2 steps 4–5). `mnemonic` is the biometric-unlocked phrase; it is wiped here.
    pub fn accept_offer(
        &self,
        uri: String,
        mnemonic: Vec<u8>,
        index: u32,
        now: u64,
        expires_at: u64,
    ) -> Result<BindToPost, FfiError> {
        let offer = Offer::from_uri(&uri).map_err(|e| FfiError::InvalidQr(e.to_string()))?;
        if offer.relay != self.relay {
            return Err(FfiError::WrongRelay);
        }
        let phrase = Zeroizing::new(mnemonic);
        let phrase = std::str::from_utf8(&phrase).map_err(|_| FfiError::InvalidMnemonic)?;
        let key = signer_from_mnemonic(phrase, index).map_err(|_| FfiError::InvalidMnemonic)?;
        if key.address() != self.signer {
            return Err(FfiError::WrongAccount);
        }
        let account = key.address().to_checksum(None);
        let acc = accept_offer(&offer, &self.keys, &account, now, expires_at, |text| {
            Ok(blox_evm::connect::sign_statement(&key, text))
        })
        .map_err(internal)?;
        let out = BindToPost {
            requester_inbox: acc.requester_inbox.to_string(),
            ticket: acc.ticket.to_string(),
            body: acc.bind,
            account,
        };
        let kem = acc.pending.requester_kem().0;
        self.state.lock().unwrap().pending.insert(kem, acc.pending);
        Ok(out)
    }

    /// Gives up on a connect whose `bound` didn't come (§5.4). Returns the half-signed
    /// token to revoke (`POST /v1/revoke`, signed by `K`).
    pub fn abandon_connect(&self, requester_inbox: String) -> Option<String> {
        let mut st = self.state.lock().unwrap();
        let key = st
            .pending
            .iter()
            .find(|(_, p)| p.token().body.requester.sig.to_string() == requester_inbox)
            .map(|(k, _)| *k)?;
        st.pending.remove(&key).map(|p| p.token().to_header())
    }

    /// Handles one envelope read from this inbox (§10.4 step 1, §10.6).
    pub fn on_envelope(&self, body: Vec<u8>, now: u64) -> Incoming {
        let Ok(env) = Envelope::parse(&body) else {
            return Incoming::Dropped;
        };
        let mut st = self.state.lock().unwrap();
        if let Some(p) = st.pending.remove(&env.spk.0) {
            return match p.open_bound(&body, now) {
                Ok(conn) => {
                    let rec = record(&conn, &p.label, &p.account);
                    st.connections.insert(
                        conn.id(),
                        Entry {
                            conn,
                            label: p.label.clone(),
                        },
                    );
                    Incoming::Connected { connection: rec }
                }
                Err(_) => Incoming::Dropped,
            };
        }
        let Some((conn_id, entry)) = st
            .connections
            .iter_mut()
            .find(|(_, e)| e.conn.peer().kem == env.spk)
        else {
            return Incoming::Dropped;
        };
        let conn_id = *conn_id;
        let opened = entry.conn.open(&body, now);
        let label = entry.label.clone();
        let digest = sha(&body);
        match opened {
            Ok(msg) => {
                st.delivered.insert(digest, (conn_id, msg.id));
                let cid = b64::encode(conn_id);
                match msg.body {
                    Body::SignRequest(request) => Incoming::Request {
                        request: Arc::new(IncomingRequest {
                            connection_id: cid,
                            connection_label: label,
                            id: msg.id,
                            ts: msg.ts,
                            request,
                            signer: self.signer,
                        }),
                    },
                    Body::Cancel(_) => match msg.re {
                        Some(re) => Incoming::Cancelled {
                            connection_id: cid,
                            request_id: re.to_string(),
                        },
                        None => Incoming::Dropped,
                    },
                    Body::Unbind(_) => {
                        st.connections.remove(&conn_id);
                        Incoming::Unbound { connection_id: cid }
                    }
                    _ => Incoming::Dropped,
                }
            }
            Err(blox_proto::Error::Replay) => match st.delivered.get(&digest) {
                Some((c, id)) => Incoming::Redelivered {
                    connection_id: b64::encode(c),
                    request_id: id.to_string(),
                },
                None => Incoming::Dropped,
            },
            Err(_) => Incoming::Dropped,
        }
    }

    /// Seals the answer to `request_id` for the connection's requester. Store the returned
    /// body with the request id before posting it (§10.6).
    pub fn answer(
        &self,
        connection_id: String,
        request_id: String,
        response: Response,
        now: u64,
    ) -> Result<Outgoing, FfiError> {
        let re = MsgId(b64::decode_array(&request_id).map_err(internal)?);
        self.seal(
            &connection_id,
            Message::reply_at(re, Body::SignResponse(response.into()), now),
        )
    }

    /// `unbind` for a connection the user ends (§5.5). Post it, then revoke the token,
    /// then forget the connection.
    pub fn unbind(&self, connection_id: String, now: u64) -> Result<Outgoing, FfiError> {
        let out = self.seal(&connection_id, Message::at(Body::Unbind(Empty {}), now))?;
        self.remove_connection(connection_id);
        Ok(out)
    }
}

impl Inbox {
    fn seal(&self, connection_id: &str, msg: Message) -> Result<Outgoing, FfiError> {
        let id = b64::decode_array::<32>(connection_id).map_err(|_| FfiError::UnknownConnection)?;
        let st = self.state.lock().unwrap();
        let e = st.connections.get(&id).ok_or(FfiError::UnknownConnection)?;
        Ok(Outgoing {
            inbox: e.conn.peer_inbox().to_string(),
            body: e.conn.seal(&msg).map_err(internal)?,
            token: e.conn.token().to_header(),
        })
    }
}

fn sha(bytes: &[u8]) -> [u8; 32] {
    use sha2::Digest as _;
    sha2::Sha256::digest(bytes).into()
}

// ---- requests -------------------------------------------------------------------------

/// A request opened from the inbox, before review.
#[derive(uniffi::Object)]
pub struct IncomingRequest {
    connection_id: String,
    connection_label: String,
    id: MsgId,
    ts: u64,
    request: SignRequest,
    signer: Address,
}

/// What reviewing a request led to (§10.4).
#[derive(uniffi::Enum)]
pub enum ReviewOutcome {
    /// Show it (§10.5).
    Ready { review: Arc<ReviewedRequest> },
    /// Answer `rejected` with this reason without asking.
    Reject { reason: RejectReason },
    /// "This transaction would fail": offer only Reject, which answers `would_fail`.
    WouldFail { message: String },
    /// The endpoint couldn't be reached: offer Retry and Reject.
    Unreachable { message: String },
}

#[uniffi::export]
impl IncomingRequest {
    pub fn id(&self) -> String {
        self.id.to_string()
    }

    pub fn connection_id(&self) -> String {
        self.connection_id.clone()
    }

    pub fn connection_label(&self) -> String {
        self.connection_label.clone()
    }

    pub fn kind(&self) -> String {
        self.request.kind.clone()
    }

    /// The EVM chain id, if the chain is `eip155:…` (to look up the endpoint).
    pub fn chain_id(&self) -> Option<u64> {
        blox_evm::caip::parse_chain(&self.request.chain).ok()
    }

    /// The request's expiry, capped at `ts + 300` (§6.2).
    pub fn expires_at(&self) -> u64 {
        self.request
            .expires_at
            .min(self.ts + blox_evm::intent::MAX_REQUEST_SECS)
    }

    /// The claimed origin (§6.2): shown muted, as "claims to be from".
    pub fn origin_name(&self) -> Option<String> {
        self.request.origin.as_ref().and_then(|o| o.name.clone())
    }

    pub fn origin_url(&self) -> Option<String> {
        self.request.origin.as_ref().and_then(|o| o.url.clone())
    }

    /// Checks, decodes and (for transactions) fills the request. Blocks on the endpoint:
    /// call it off the main thread. `last_sent_nonce` is the last nonce the app sent for
    /// this chain and account since it started (§10.4).
    pub fn review(
        &self,
        signer_label: String,
        endpoint: Option<Arc<dyn EndpointRpc>>,
        endpoint_host: Option<String>,
        last_sent_nonce: Option<u64>,
        now: u64,
    ) -> ReviewOutcome {
        let adapter = endpoint.map(RpcAdapter);
        let host = endpoint_host.unwrap_or_default();
        let result = keystore::review(
            &self.request,
            self.ts,
            now,
            (self.signer, &signer_label),
            |_| {
                adapter.as_ref().map(|a| Endpoint {
                    rpc: a as &dyn ChainRpc,
                    host: &host,
                })
            },
            |_| last_sent_nonce,
        );
        match result {
            Ok(rv) => ReviewOutcome::Ready {
                review: Arc::new(ReviewedRequest {
                    review: rv,
                    signer: self.signer,
                }),
            },
            Err(ReviewError::Reject(r)) => ReviewOutcome::Reject { reason: r.into() },
            Err(ReviewError::WouldFail(message)) => ReviewOutcome::WouldFail { message },
            Err(ReviewError::Unreachable(message)) => ReviewOutcome::Unreachable { message },
        }
    }
}

/// A reviewed (and, for transactions, filled) request: exactly what is shown and signed.
#[derive(uniffi::Object)]
pub struct ReviewedRequest {
    review: keystore::Review,
    signer: Address,
}

/// What approving led to (§10.8).
#[derive(uniffi::Enum)]
pub enum ApproveOutcome {
    /// Answer with this.
    Answer { response: Response },
    /// `evm.send`: store `if_interrupted` as the answer to the request first (§10.8), then
    /// call [`broadcast_transaction`] and answer with its result.
    Broadcast {
        raw: Vec<u8>,
        tx_hash: String,
        nonce: u64,
        if_interrupted: Response,
    },
}

#[uniffi::export]
impl ReviewedRequest {
    pub fn display(&self) -> UiDisplay {
        self.review.display.clone().into()
    }

    pub fn chain_id(&self) -> u64 {
        self.review.chain_id
    }

    /// Signs with the signer's key. `mnemonic` is the biometric-unlocked phrase; it is
    /// wiped here, and the caller must wipe its own copy.
    pub fn approve(&self, mnemonic: Vec<u8>, index: u32) -> Result<ApproveOutcome, FfiError> {
        let phrase = Zeroizing::new(mnemonic);
        let phrase = std::str::from_utf8(&phrase).map_err(|_| FfiError::InvalidMnemonic)?;
        let key = signer_from_mnemonic(phrase, index).map_err(|_| FfiError::InvalidMnemonic)?;
        if key.address() != self.signer {
            return Err(FfiError::WrongAccount);
        }
        Ok(match keystore::approve(&key, &self.review) {
            Approved::Answer(a) => ApproveOutcome::Answer { response: a.into() },
            Approved::Broadcast {
                raw,
                tx_hash,
                nonce,
            } => ApproveOutcome::Broadcast {
                if_interrupted: keystore::failed(
                    self.review.chain_id,
                    self.signer,
                    tx_hash,
                    "the keystore restarted before confirming the broadcast",
                )
                .into(),
                raw,
                tx_hash: blox_evm::to_hex(tx_hash),
                nonce,
            },
        })
    }
}

/// Calls `eth_sendRawTransaction` once and returns `sent` or `failed` (§10.8). Blocks.
#[uniffi::export]
pub fn broadcast_transaction(
    endpoint: Arc<dyn EndpointRpc>,
    chain_id: u64,
    from: String,
    raw: Vec<u8>,
    tx_hash: String,
) -> Result<Response, FfiError> {
    let from: Address = from.parse().map_err(internal)?;
    let hash: B256 = tx_hash.parse().map_err(internal)?;
    Ok(keystore::broadcast(&RpcAdapter(endpoint), chain_id, from, &raw, hash).into())
}

// ---- mnemonics ------------------------------------------------------------------------

/// A new BIP-39 English recovery phrase (12 or 24 words), as UTF-8 bytes.
#[uniffi::export]
pub fn generate_mnemonic(words: u32) -> Result<Vec<u8>, FfiError> {
    let len = match words {
        12 => 16,
        24 => 32,
        _ => return Err(FfiError::Internal("12 or 24 words".into())),
    };
    let mut entropy = Zeroizing::new(vec![0u8; len]);
    getrandom::fill(&mut entropy).map_err(internal)?;
    let m = bip39::Mnemonic::from_entropy(&entropy).map_err(internal)?;
    Ok(m.to_string().into_bytes())
}

/// Checks a recovery phrase (word list and checksum). Wipes its input.
#[uniffi::export]
pub fn validate_mnemonic(mnemonic: Vec<u8>) -> bool {
    let phrase = Zeroizing::new(mnemonic);
    std::str::from_utf8(&phrase).is_ok_and(|p| bip39::Mnemonic::parse_normalized(p).is_ok())
}

/// EVM addresses at `m/44'/60'/0'/0/{start..start+count}`, checksummed. Wipes its input.
#[uniffi::export]
pub fn derive_evm_addresses(
    mnemonic: Vec<u8>,
    start: u32,
    count: u32,
) -> Result<Vec<String>, FfiError> {
    let phrase = Zeroizing::new(mnemonic);
    let phrase = std::str::from_utf8(&phrase).map_err(|_| FfiError::InvalidMnemonic)?;
    (start..start.saturating_add(count))
        .map(|i| {
            signer_from_mnemonic(phrase, i)
                .map(|s| s.address().to_checksum(None))
                .map_err(|_| FfiError::InvalidMnemonic)
        })
        .collect()
}

/// Display name for an EVM chain id, if known.
#[uniffi::export]
pub fn chain_name(chain_id: u64) -> Option<String> {
    blox_evm::display::chain_name(chain_id).map(str::to_owned)
}

#[cfg(test)]
mod tests;
