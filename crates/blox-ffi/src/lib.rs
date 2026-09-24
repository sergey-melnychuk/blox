//! Mobile bindings (UniFFI) for the keystore side of Blox (BLOX.md §10).
//!
//! The app does networking, storage and UI only. Protocol handling, request
//! checks, decoding for display and signing all happen here, in the same code
//! the adapter uses.
//!
//! Secrets cross the boundary as byte arrays (never `String`, which can't be
//! wiped on the JVM). Rust wipes its copies; callers must wipe theirs.

use std::sync::{Arc, Mutex};

use blox_evm::Address;
use blox_evm::display::{Display, describe};
use blox_evm::sign::{Prepared, prepare, sign, signer_from_mnemonic};
use blox_proto::message::{self, Body, Message, SignResponse};
use blox_proto::peer::{KeystoreEvent, KeystoreSession, Outgoing as ProtoOutgoing};
use zeroize::Zeroizing;

uniffi::setup_scaffolding!();

#[derive(Debug, thiserror::Error, uniffi::Error)]
#[uniffi(flat_error)]
pub enum FfiError {
    #[error("invalid QR code: {0}")]
    InvalidQr(String),
    #[error("invalid recovery phrase")]
    InvalidMnemonic,
    #[error("the key does not match the requested account")]
    WrongAccount,
    #[error("session is closed")]
    SessionClosed,
    #[error("{0}")]
    Internal(String),
}

/// An envelope to POST to `{relay}/v1/m/{mailbox_id}`.
#[derive(Clone, Debug, uniffi::Record)]
pub struct Outgoing {
    pub mailbox_id: String,
    pub body: Vec<u8>,
}

impl From<ProtoOutgoing> for Outgoing {
    fn from((mb, body): ProtoOutgoing) -> Self {
        Self {
            mailbox_id: mb.to_string(),
            body,
        }
    }
}

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
    /// Untrusted, informational ("claims to be from").
    pub origin_client: Option<String>,
}

impl UiDisplay {
    fn new(d: Display, origin_client: Option<String>) -> Self {
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
            origin_client,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum RejectReason {
    User,
    Expired,
    Unsupported,
    DecodeFailed,
    AccountUnknown,
}

impl From<message::RejectReason> for RejectReason {
    fn from(r: message::RejectReason) -> Self {
        match r {
            message::RejectReason::User => Self::User,
            message::RejectReason::Expired => Self::Expired,
            message::RejectReason::Unsupported => Self::Unsupported,
            message::RejectReason::DecodeFailed => Self::DecodeFailed,
            message::RejectReason::AccountUnknown => Self::AccountUnknown,
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
            RejectReason::AccountUnknown => Self::AccountUnknown,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum CloseReason {
    Done,
    Contested,
    Timeout,
    Shutdown,
}

impl From<message::CloseReason> for CloseReason {
    fn from(r: message::CloseReason) -> Self {
        match r {
            message::CloseReason::Done => Self::Done,
            message::CloseReason::Contested => Self::Contested,
            message::CloseReason::Timeout => Self::Timeout,
            message::CloseReason::Shutdown => Self::Shutdown,
        }
    }
}

impl From<CloseReason> for message::CloseReason {
    fn from(r: CloseReason) -> Self {
        match r {
            CloseReason::Done => Self::Done,
            CloseReason::Contested => Self::Contested,
            CloseReason::Timeout => Self::Timeout,
            CloseReason::Shutdown => Self::Shutdown,
        }
    }
}

/// What an envelope from the relay turned out to be.
#[derive(uniffi::Enum)]
pub enum Incoming {
    /// Show this request and ask the user.
    Request {
        request: Arc<PendingRequest>,
    },
    /// The request failed the checks (§10.4); post `reply` without asking the user.
    AutoRejected {
        reason: RejectReason,
        reply: Outgoing,
    },
    Closed {
        reason: CloseReason,
    },
    /// Not for this session, replayed or stale. Acknowledge and drop.
    Ignored,
}

/// A checked request waiting for the user's decision.
#[derive(uniffi::Object)]
pub struct PendingRequest {
    message: Message,
    prepared: Prepared,
    account: Address,
    display: UiDisplay,
}

#[uniffi::export]
impl PendingRequest {
    pub fn display(&self) -> UiDisplay {
        self.display.clone()
    }

    /// Checksummed address of the account asked to sign.
    pub fn account(&self) -> String {
        self.account.to_checksum(None)
    }

    pub fn expires_at(&self) -> u64 {
        match &self.message.body {
            Body::SignRequest(r) => r.expires_at,
            _ => 0,
        }
    }
}

/// One joined session (§5.2). Wipe it by dropping it when the session ends.
#[derive(uniffi::Object)]
pub struct Session {
    inner: Mutex<KeystoreSession>,
    hello: Outgoing,
    accounts: Vec<Address>,
}

#[uniffi::export]
impl Session {
    /// Joins the session in a scanned `BLOX:…` QR payload. `accounts` are
    /// the keystore's EVM addresses; requests for other accounts are refused.
    #[uniffi::constructor]
    pub fn join(uri: String, accounts: Vec<String>) -> Result<Arc<Self>, FfiError> {
        let accounts = accounts
            .iter()
            .map(|a| {
                a.parse::<Address>()
                    .map_err(|_| FfiError::Internal(format!("bad account {a}")))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let (inner, hello) =
            KeystoreSession::join(&uri).map_err(|e| FfiError::InvalidQr(e.to_string()))?;
        Ok(Arc::new(Self {
            inner: Mutex::new(inner),
            hello: hello.into(),
            accounts,
        }))
    }

    /// The `hello` to post right after joining.
    pub fn hello(&self) -> Outgoing {
        self.hello.clone()
    }

    pub fn relay_url(&self) -> String {
        self.inner.lock().unwrap().relay().to_owned()
    }

    /// The adapter's label, shown as "Connected to …".
    pub fn label(&self) -> String {
        self.inner.lock().unwrap().label().to_owned()
    }

    /// This keystore's mailbox, for `GET /v1/m/{id}`.
    pub fn mailbox_id(&self) -> String {
        self.inner
            .lock()
            .unwrap()
            .read_secret()
            .mailbox_id()
            .to_string()
    }

    /// Value for `Authorization: Bearer …` when reading or acknowledging.
    pub fn bearer(&self) -> String {
        self.inner.lock().unwrap().read_secret().to_bearer()
    }

    pub fn is_closed(&self) -> bool {
        self.inner.lock().unwrap().is_closed()
    }

    /// Handles one envelope read from this session's mailbox.
    pub fn on_envelope(&self, body: Vec<u8>, now: u64) -> Incoming {
        let mut inner = self.inner.lock().unwrap();
        match inner.on_envelope(&body, now) {
            Ok(KeystoreEvent::Request(msg)) => {
                let Body::SignRequest(req) = &msg.body else {
                    return Incoming::Ignored;
                };
                match prepare(req, &self.accounts, now) {
                    Ok((account, prepared)) => {
                        let origin = req.origin.as_ref().and_then(|o| o.client.clone());
                        let display = UiDisplay::new(describe(&prepared, account), origin);
                        Incoming::Request {
                            request: Arc::new(PendingRequest {
                                message: *msg,
                                prepared,
                                account,
                                display,
                            }),
                        }
                    }
                    Err(reason) => match inner.respond(&msg, SignResponse::Rejected { reason }) {
                        Ok(out) => Incoming::AutoRejected {
                            reason: reason.into(),
                            reply: out.into(),
                        },
                        Err(_) => Incoming::Ignored,
                    },
                }
            }
            Ok(KeystoreEvent::Closed(reason)) => Incoming::Closed {
                reason: reason.into(),
            },
            Err(_) => Incoming::Ignored,
        }
    }

    /// Signs an approved request. `mnemonic` is the decrypted recovery phrase
    /// (UTF-8); it is wiped here, and the caller must wipe its own copy.
    pub fn approve(
        &self,
        request: Arc<PendingRequest>,
        mnemonic: Vec<u8>,
        index: u32,
    ) -> Result<Outgoing, FfiError> {
        let phrase = Zeroizing::new(mnemonic);
        let phrase = std::str::from_utf8(&phrase).map_err(|_| FfiError::InvalidMnemonic)?;
        let signer = signer_from_mnemonic(phrase, index).map_err(|_| FfiError::InvalidMnemonic)?;
        if signer.address() != request.account {
            return Err(FfiError::WrongAccount);
        }
        let response = sign(&signer, request.prepared.clone());
        self.reply(&request, response)
    }

    pub fn reject(
        &self,
        request: Arc<PendingRequest>,
        reason: RejectReason,
    ) -> Result<Outgoing, FfiError> {
        self.reply(
            &request,
            SignResponse::Rejected {
                reason: reason.into(),
            },
        )
    }

    /// Ends the session; returns the `close` message to post, if any.
    /// (Named `end` so it can't be confused with Kotlin's `close()`, which frees the object.)
    pub fn end(&self, reason: CloseReason) -> Option<Outgoing> {
        self.inner
            .lock()
            .unwrap()
            .close(reason.into())
            .ok()
            .flatten()
            .map(Into::into)
    }
}

impl Session {
    fn reply(
        &self,
        request: &PendingRequest,
        response: SignResponse,
    ) -> Result<Outgoing, FfiError> {
        let inner = self.inner.lock().unwrap();
        if inner.is_closed() {
            return Err(FfiError::SessionClosed);
        }
        inner
            .respond(&request.message, response)
            .map(Into::into)
            .map_err(|e| FfiError::Internal(e.to_string()))
    }
}

/// A new BIP-39 English recovery phrase (12 or 24 words), as UTF-8 bytes.
#[uniffi::export]
pub fn generate_mnemonic(words: u32) -> Result<Vec<u8>, FfiError> {
    let len = match words {
        12 => 16,
        24 => 32,
        _ => return Err(FfiError::Internal("12 or 24 words".into())),
    };
    let mut entropy = Zeroizing::new(vec![0u8; len]);
    getrandom::fill(&mut entropy).map_err(|e| FfiError::Internal(e.to_string()))?;
    let m =
        bip39::Mnemonic::from_entropy(&entropy).map_err(|e| FfiError::Internal(e.to_string()))?;
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
mod tests {
    use super::*;
    use blox_evm::to_hex;
    use blox_proto::message::{SignRequest, now};
    use blox_proto::peer::{AdapterEvent, AdapterSession};

    const MNEMONIC: &[u8] = b"test test test test test test test test test test test junk";

    #[test]
    fn mnemonic_helpers() {
        let m = generate_mnemonic(12).unwrap();
        assert_eq!(String::from_utf8(m.clone()).unwrap().split(' ').count(), 12);
        assert!(validate_mnemonic(m));
        assert!(!validate_mnemonic(b"test test test".to_vec()));
        let a = derive_evm_addresses(MNEMONIC.to_vec(), 0, 2).unwrap();
        assert_eq!(a[0], "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266");
        assert_eq!(a[1], "0x70997970C51812dc3A010C7d01b50e0d17dc79C8");
    }

    fn request(account: &str, kind: &str, payload: serde_json::Value) -> SignRequest {
        SignRequest {
            chain: "eip155:31337".into(),
            account: format!("eip155:31337:{account}"),
            kind: kind.into(),
            payload,
            origin: None,
            expires_at: now() + 300,
        }
    }

    /// The app's whole flow, without networking: join, receive, display, approve, verify.
    #[test]
    fn keystore_flow_through_bindings() {
        let accounts = derive_evm_addresses(MNEMONIC.to_vec(), 0, 1).unwrap();
        let mut adapter = AdapterSession::new("https://relay.example.com", "laptop");
        let session = Session::join(adapter.uri(), accounts.clone()).unwrap();
        assert_eq!(session.label(), "laptop");
        assert_eq!(
            adapter.on_envelope(&session.hello().body, now()).unwrap(),
            AdapterEvent::Joined
        );

        let req = request(
            &accounts[0],
            "evm.personal_sign",
            serde_json::json!({"message": to_hex(b"hello")}),
        );
        let (id, (_, bytes)) = adapter.request(req.clone()).unwrap();
        let Incoming::Request { request: pending } = session.on_envelope(bytes, now()) else {
            panic!("expected request")
        };
        assert_eq!(pending.display().decoded.as_deref(), Some("hello"));

        let out = session.approve(pending, MNEMONIC.to_vec(), 0).unwrap();
        let AdapterEvent::Response { re, response } =
            adapter.on_envelope(&out.body, now()).unwrap()
        else {
            panic!()
        };
        assert_eq!(re, id);
        blox_evm::verify::verify(&req, &response).unwrap();
    }

    #[test]
    fn unknown_account_is_auto_rejected_and_wrong_key_refused() {
        let accounts = derive_evm_addresses(MNEMONIC.to_vec(), 0, 1).unwrap();
        let mut adapter = AdapterSession::new("https://relay.example.com", "laptop");
        let session = Session::join(adapter.uri(), accounts.clone()).unwrap();
        adapter.on_envelope(&session.hello().body, now()).unwrap();

        let stranger = "0x000000000000000000000000000000000000dEaD";
        let (_, (_, bytes)) = adapter
            .request(request(
                stranger,
                "evm.personal_sign",
                serde_json::json!({"message":"0x00"}),
            ))
            .unwrap();
        assert!(matches!(
            session.on_envelope(bytes, now()),
            Incoming::AutoRejected {
                reason: RejectReason::AccountUnknown,
                ..
            }
        ));

        let (_, (_, bytes)) = adapter
            .request(request(
                &accounts[0],
                "evm.personal_sign",
                serde_json::json!({"message":"0x00"}),
            ))
            .unwrap();
        let Incoming::Request { request: pending } = session.on_envelope(bytes, now()) else {
            panic!()
        };
        assert!(matches!(
            session.approve(pending, MNEMONIC.to_vec(), 1),
            Err(FfiError::WrongAccount)
        ));
    }

    #[test]
    fn bad_qr() {
        assert!(matches!(
            Session::join("https://example.com".into(), vec![]),
            Err(FfiError::InvalidQr(_))
        ));
    }
}
