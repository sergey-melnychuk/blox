//! Typed calls with the requester-side checks (BLOX.md §9.2, §9.5).

use blox_evm::{Address, B256, U256};
use blox_proto::message::{Origin, SignRequest, SignResponse};
use serde_json::{Value, json};

use crate::{Error, Requester, Result};

/// A transaction intent: everything else is filled on the phone (§6.3).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TxCall {
    pub chain: u64,
    /// `None` deploys a contract.
    pub to: Option<Address>,
    pub value: U256,
    pub data: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sent {
    /// Checksummed address.
    pub account: String,
    pub tx_hash: B256,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedTx {
    pub account: String,
    pub tx_hash: B256,
    /// EIP-2718 encoding, ready for `eth_sendRawTransaction`.
    pub raw: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MessageSignature {
    pub account: String,
    /// `0x` + r‖s‖v (65 bytes, v = 27 or 28).
    pub signature: String,
}

impl Requester {
    /// The phone fills, signs and broadcasts; returns the hash (§6.3 `evm.send`).
    pub async fn send(&self, call: TxCall) -> Result<Sent> {
        let (account, resp) = self
            .checked(tx_request("evm.send", &call, self.origin()))
            .await?;
        match resp {
            SignResponse::Sent { tx_hash, .. } => Ok(Sent {
                account,
                tx_hash: hash(&tx_hash)?,
            }),
            other => Err(unexpected(other)),
        }
    }

    /// The phone fills and signs; returns the signed transaction without broadcasting it.
    pub async fn sign_transaction(&self, call: TxCall) -> Result<SignedTx> {
        let (account, resp) = self
            .checked(tx_request("evm.sign_tx", &call, self.origin()))
            .await?;
        match resp {
            SignResponse::SignedTx { tx_hash, raw, .. } => Ok(SignedTx {
                account,
                tx_hash: hash(&tx_hash)?,
                raw: bytes(&raw)?,
            }),
            other => Err(unexpected(other)),
        }
    }

    /// EIP-191 signature over `message`.
    pub async fn personal_sign(&self, chain: u64, message: &[u8]) -> Result<MessageSignature> {
        let req = request(
            chain,
            "evm.personal_sign",
            json!({ "message": blox_evm::to_hex(message) }),
            self.origin(),
        );
        self.signature(req).await
    }

    /// EIP-712 signature over `data` (the typed-data JSON object).
    pub async fn sign_typed_data(&self, chain: u64, data: Value) -> Result<MessageSignature> {
        let req = request(
            chain,
            "evm.typed_data",
            json!({ "data": data }),
            self.origin(),
        );
        self.signature(req).await
    }

    async fn signature(&self, req: SignRequest) -> Result<MessageSignature> {
        let (account, resp) = self.checked(req).await?;
        match resp {
            SignResponse::Signed { signature, .. } => Ok(MessageSignature { account, signature }),
            other => Err(unexpected(other)),
        }
    }

    /// Sends the request, checks the response (§9.5), and turns `rejected` and `failed`
    /// into errors.
    async fn checked(&self, req: SignRequest) -> Result<(String, SignResponse)> {
        let resp = self.request(req.clone()).await?;
        let account = self.account().await.ok_or(Error::Disconnected)?;
        let addr: Address = account
            .parse()
            .map_err(|_| Error::BadResponse("stored account".into()))?;
        blox_evm::check::check(&req, &resp, addr).map_err(|e| Error::BadResponse(e.to_string()))?;
        match resp {
            SignResponse::Rejected { reason } => Err(Error::Rejected(reason)),
            SignResponse::Failed { tx_hash, error, .. } => Err(Error::Failed {
                tx_hash: hash(&tx_hash)?,
                error,
            }),
            ok => Ok((account, ok)),
        }
    }
}

fn request(chain: u64, kind: &str, payload: Value, origin: Option<Origin>) -> SignRequest {
    SignRequest {
        chain: blox_evm::caip::chain(chain),
        kind: kind.into(),
        payload,
        origin,
        expires_at: 0,
    }
}

fn tx_request(kind: &str, call: &TxCall, origin: Option<Origin>) -> SignRequest {
    let payload = json!({
        "to": call.to.map(|a| a.to_checksum(None)),
        "value": format!("{:#x}", call.value),
        "data": blox_evm::to_hex(&call.data),
    });
    request(call.chain, kind, payload, origin)
}

fn hash(s: &str) -> Result<B256> {
    s.parse().map_err(|_| Error::BadResponse("tx_hash".into()))
}

fn bytes(s: &str) -> Result<Vec<u8>> {
    blox_evm::hex_bytes(s).map_err(|_| Error::BadResponse("raw".into()))
}

fn unexpected(resp: SignResponse) -> Error {
    Error::BadResponse(format!("unexpected response {resp:?}"))
}
