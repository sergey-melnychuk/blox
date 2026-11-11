//! Where a requester keeps its connection between runs (BLOX.md §9.6).

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use blox_proto::b64;
use blox_proto::connection::{Connection, Keys};
use blox_proto::ident::SigningKey;
use blox_proto::keys::KeyPair;
use blox_proto::token::{Party, Token};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::{Error, Result};

/// A stored connection: the token, this side's secrets and the account.
#[derive(Clone, Serialize, Deserialize)]
pub struct StoredConnection {
    pub relay: String,
    pub label: String,
    /// Checksummed EVM address.
    pub account: String,
    /// Countersigned token (`Blox-Token` encoding).
    pub token: String,
    sig_secret: String,
    kem_secret: String,
}

impl Drop for StoredConnection {
    fn drop(&mut self) {
        self.sig_secret.zeroize();
        self.kem_secret.zeroize();
    }
}

impl std::fmt::Debug for StoredConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoredConnection")
            .field("relay", &self.relay)
            .field("label", &self.label)
            .field("account", &self.account)
            .finish_non_exhaustive()
    }
}

impl StoredConnection {
    pub fn new(conn: &Connection, keys: &Keys, label: &str, account: &str) -> Self {
        Self {
            relay: conn.relay().to_owned(),
            label: label.to_owned(),
            account: account.to_owned(),
            token: conn.token().to_header(),
            sig_secret: b64::encode(*keys.sig.to_bytes()),
            kem_secret: b64::encode(*keys.kem.to_secret_bytes()),
        }
    }

    /// Rebuilds the live connection and its signing key.
    pub fn open(&self) -> Result<(Connection, SigningKey)> {
        let token = Token::from_header(&self.token)?;
        let mut sig = b64::decode_array::<32>(&self.sig_secret)?;
        let mut kem = b64::decode_array::<32>(&self.kem_secret)?;
        let sk = SigningKey::from_bytes(&sig);
        let kp = KeyPair::from_secret_bytes(&kem);
        sig.zeroize();
        kem.zeroize();
        let conn = Connection::new(Party::Requester, token, kp?)?;
        if conn.my_inbox() != sk.public() {
            return Err(Error::Proto(blox_proto::Error::Malformed("stored keys")));
        }
        Ok((conn, sk))
    }

    pub fn expires_at(&self) -> Option<u64> {
        Token::from_header(&self.token)
            .ok()
            .map(|t| t.body.expires_at)
    }
}

pub trait ConnectionStore: Send + Sync {
    fn load(&self) -> Result<Option<StoredConnection>>;
    fn save(&self, conn: &StoredConnection) -> Result<()>;
    fn clear(&self) -> Result<()>;
}

/// Keeps the connection in memory. Clones share it (like tabs sharing a browser's storage).
#[derive(Clone, Default)]
pub struct MemoryStore(Arc<Mutex<Option<StoredConnection>>>);

impl ConnectionStore for MemoryStore {
    fn load(&self) -> Result<Option<StoredConnection>> {
        Ok(self.0.lock().unwrap().clone())
    }
    fn save(&self, conn: &StoredConnection) -> Result<()> {
        *self.0.lock().unwrap() = Some(conn.clone());
        Ok(())
    }
    fn clear(&self) -> Result<()> {
        *self.0.lock().unwrap() = None;
        Ok(())
    }
}

/// Keeps the connection in a JSON file readable by the owner only.
pub struct FileStore(PathBuf);

impl FileStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self(path.into())
    }
}

impl ConnectionStore for FileStore {
    fn load(&self) -> Result<Option<StoredConnection>> {
        match std::fs::read(&self.0) {
            Ok(bytes) => Ok(Some(serde_json::from_slice(&bytes).map_err(|e| {
                Error::Store(std::io::Error::new(std::io::ErrorKind::InvalidData, e))
            })?)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(Error::Store(e)),
        }
    }

    fn save(&self, conn: &StoredConnection) -> Result<()> {
        use std::io::Write as _;
        let mut json = serde_json::to_vec_pretty(conn).expect("serializes");
        let tmp = self.0.with_extension("tmp");
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
        let res = opts
            .open(&tmp)
            .and_then(|mut f| f.write_all(&json).and_then(|_| f.sync_all()))
            .and_then(|_| std::fs::rename(&tmp, &self.0));
        json.zeroize();
        res.map_err(Error::Store)
    }

    fn clear(&self) -> Result<()> {
        match std::fs::remove_file(&self.0) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(Error::Store(e)),
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use blox_proto::connection::{ConnectAttempt, accept_offer};

    const ACCOUNT: &str = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";

    fn connected() -> (Connection, Keys) {
        let attempt = ConnectAttempt::new("https://relay.example.com", "Example", None).unwrap();
        let acc = accept_offer(
            attempt.offer(),
            &Keys::generate(),
            ACCOUNT,
            1000,
            90_000,
            |_| Ok("0x00".into()),
        )
        .unwrap();
        let cand = attempt.open_bind(&acc.bind, 1000).unwrap();
        let (conn, _) = attempt.accept(cand, 1000).unwrap();
        (conn, attempt.keys().clone())
    }

    #[test]
    fn stored_connection_roundtrip_and_debug_hides_secrets() {
        let (conn, keys) = connected();
        let stored = StoredConnection::new(&conn, &keys, "Example", ACCOUNT);
        let (again, sig) = stored.open().unwrap();
        assert_eq!(again.id(), conn.id());
        assert_eq!(sig.public(), keys.sig.public());
        assert_eq!(stored.expires_at(), Some(90_000));
        let dbg = format!("{stored:?}");
        assert!(!dbg.contains(&stored.sig_secret) && !dbg.contains(&stored.token));
    }

    #[test]
    fn file_store_is_private_and_clears() {
        let (conn, keys) = connected();
        let stored = StoredConnection::new(&conn, &keys, "Example", ACCOUNT);
        let path = std::env::temp_dir().join(format!("blox-store-{}.json", std::process::id()));
        let fs = FileStore::new(&path);
        assert!(fs.load().unwrap().is_none());
        fs.save(&stored).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        assert_eq!(fs.load().unwrap().unwrap().token, stored.token);
        fs.clear().unwrap();
        fs.clear().unwrap();
        assert!(fs.load().unwrap().is_none());
    }
}
