//! The bytes the relay stores and forwards (BLOX.md §4.5).
//!
//! ```text
//! 0      1   version = 0x01
//! 1      1   type    = 0x01 bind | 0x02 message
//! 2      32  spk     sender's X25519 key
//! 34     32  enc
//! 66     ..  ct      (includes 16-byte tag)
//! ```
//!
//! `bind` is sealed with HPKE `mode_auth_psk` (the PSK from the QR code); every later
//! message with `mode_auth`. The AAD binds each envelope to its recipient's inbox.

use hpke::{
    Deserializable, OpModeR, OpModeS, PskBundle, Serializable, aead::AesGcm256, kdf::HkdfSha256,
    rand_core::CryptoRng,
};

use crate::ident::InboxId;
use crate::keys::{Kem, KeyPair, Psk, PublicKey};
use crate::{Error, Result, VERSION, pad};

const PSK_ID: &[u8] = b"blox/v1/bind";
const AAD_PREFIX: &[u8] = b"blox/v1";
const TAG_LEN: usize = 16;
pub const HEADER_LEN: usize = 2 + 32 + 32;
/// The shortest envelope the relay accepts.
pub const MIN_LEN: usize = HEADER_LEN + TAG_LEN;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Kind {
    Bind = 0x01,
    Message = 0x02,
}

impl Kind {
    fn from_byte(b: u8) -> Result<Self> {
        match b {
            0x01 => Ok(Kind::Bind),
            0x02 => Ok(Kind::Message),
            _ => Err(Error::Malformed("envelope type")),
        }
    }

    fn info(self) -> &'static [u8] {
        match self {
            Kind::Bind => b"blox/v1/bind",
            Kind::Message => b"blox/v1/msg",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Envelope {
    pub kind: Kind,
    /// The sender's X25519 key; the receiver finds the connection by it.
    pub spk: PublicKey,
    pub enc: [u8; 32],
    pub ct: Vec<u8>,
}

/// Validates only what the relay may look at: version, type and minimum length.
pub fn check_header(bytes: &[u8]) -> Result<Kind> {
    if bytes.len() < 2 {
        return Err(Error::Malformed("envelope too short"));
    }
    if bytes[0] != VERSION {
        return Err(Error::Version(bytes[0]));
    }
    let kind = Kind::from_byte(bytes[1])?;
    if bytes.len() < MIN_LEN {
        return Err(Error::Malformed("envelope too short"));
    }
    Ok(kind)
}

impl Envelope {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN + self.ct.len());
        out.push(VERSION);
        out.push(self.kind as u8);
        out.extend_from_slice(&self.spk.0);
        out.extend_from_slice(&self.enc);
        out.extend_from_slice(&self.ct);
        out
    }

    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let kind = check_header(bytes)?;
        Ok(Envelope {
            kind,
            spk: PublicKey(bytes[2..34].try_into().unwrap()),
            enc: bytes[34..66].try_into().unwrap(),
            ct: bytes[66..].to_vec(),
        })
    }
}

fn aad(recipient: &InboxId) -> Vec<u8> {
    [AAD_PREFIX, recipient.as_bytes()].concat()
}

/// Seals `bind` from the keystore (`sender` = k) to the requester (`recipient_pk` = s).
pub fn seal_bind(
    sender: &KeyPair,
    recipient_pk: PublicKey,
    psk: &Psk,
    recipient_inbox: &InboxId,
    plaintext: &[u8],
) -> Result<Envelope> {
    seal_with_rng(
        Kind::Bind,
        sender,
        recipient_pk,
        Some(psk),
        recipient_inbox,
        plaintext,
        &mut OsRng,
    )
}

/// Seals a message between the two parties of a connection.
pub fn seal_message(
    sender: &KeyPair,
    recipient_pk: PublicKey,
    recipient_inbox: &InboxId,
    plaintext: &[u8],
) -> Result<Envelope> {
    seal_with_rng(
        Kind::Message,
        sender,
        recipient_pk,
        None,
        recipient_inbox,
        plaintext,
        &mut OsRng,
    )
}

pub(crate) fn seal_with_rng(
    kind: Kind,
    sender: &KeyPair,
    recipient_pk: PublicKey,
    psk: Option<&Psk>,
    recipient_inbox: &InboxId,
    plaintext: &[u8],
    rng: &mut impl CryptoRng,
) -> Result<Envelope> {
    let padded = pad::pad(plaintext)?;
    let keypair = (sender.sk.clone(), sender.pk.clone());
    let mode = match (kind, psk) {
        (Kind::Bind, Some(psk)) => OpModeS::<Kem>::AuthPsk(
            keypair,
            PskBundle::new(&psk.0, PSK_ID).map_err(|_| Error::Crypto)?,
        ),
        (Kind::Message, None) => OpModeS::<Kem>::Auth(keypair),
        _ => return Err(Error::Malformed("bind needs the PSK, messages don't")),
    };
    let (enc, ct) = hpke::single_shot_seal_with_rng::<AesGcm256, HkdfSha256, Kem>(
        &mode,
        &recipient_pk.to_hpke()?,
        kind.info(),
        &padded,
        &aad(recipient_inbox),
        rng,
    )
    .map_err(|_| Error::Crypto)?;
    Ok(Envelope {
        kind,
        spk: sender.public(),
        enc: enc.to_bytes().into(),
        ct,
    })
}

/// Opens a `bind` with the PSK, authenticating the sender key in `env.spk`. The caller
/// checks that `spk` is the token's keystore key (§5.3).
pub fn open_bind(
    env: &Envelope,
    recipient: &KeyPair,
    psk: &Psk,
    recipient_inbox: &InboxId,
) -> Result<Vec<u8>> {
    if env.kind != Kind::Bind {
        return Err(Error::Malformed("expected bind"));
    }
    let bundle = PskBundle::new(&psk.0, PSK_ID).map_err(|_| Error::Crypto)?;
    open(
        env,
        recipient,
        OpModeR::<Kem>::AuthPsk(env.spk.to_hpke()?, bundle),
        recipient_inbox,
    )
}

/// Opens a message from `sender_pk`, the connection's peer.
pub fn open_message(
    env: &Envelope,
    recipient: &KeyPair,
    sender_pk: PublicKey,
    recipient_inbox: &InboxId,
) -> Result<Vec<u8>> {
    if env.kind != Kind::Message {
        return Err(Error::Malformed("expected message"));
    }
    if env.spk != sender_pk {
        return Err(Error::Crypto);
    }
    open(
        env,
        recipient,
        OpModeR::<Kem>::Auth(sender_pk.to_hpke()?),
        recipient_inbox,
    )
}

fn open(
    env: &Envelope,
    recipient: &KeyPair,
    mode: OpModeR<Kem>,
    recipient_inbox: &InboxId,
) -> Result<Vec<u8>> {
    let enc = <Kem as hpke::Kem>::EncappedKey::from_bytes(&env.enc).map_err(|_| Error::Crypto)?;
    let padded = hpke::single_shot_open::<AesGcm256, HkdfSha256, Kem>(
        &mode,
        &recipient.sk,
        &enc,
        env.kind.info(),
        &env.ct,
        &aad(recipient_inbox),
    )
    .map_err(|_| Error::Crypto)?;
    pad::unpad(padded)
}

/// OS randomness adapter for hpke's `rand_core` traits.
struct OsRng;

impl hpke::rand_core::TryRng for OsRng {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> std::result::Result<u32, Self::Error> {
        let mut b = [0u8; 4];
        self.try_fill_bytes(&mut b)?;
        Ok(u32::from_le_bytes(b))
    }

    fn try_next_u64(&mut self) -> std::result::Result<u64, Self::Error> {
        let mut b = [0u8; 8];
        self.try_fill_bytes(&mut b)?;
        Ok(u64::from_le_bytes(b))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> std::result::Result<(), Self::Error> {
        getrandom::fill(dst).expect("OS RNG");
        Ok(())
    }
}

impl hpke::rand_core::TryCryptoRng for OsRng {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ident::SigningKey;

    struct Party {
        kp: KeyPair,
        inbox: InboxId,
    }

    fn party() -> Party {
        Party {
            kp: KeyPair::generate(),
            inbox: SigningKey::generate().public(),
        }
    }

    #[test]
    fn bind_and_message_roundtrip() {
        let (s, k, psk) = (party(), party(), Psk::generate());
        let bind = seal_bind(&k.kp, s.kp.public(), &psk, &s.inbox, b"hi").unwrap();
        let bind = Envelope::parse(&bind.to_bytes()).unwrap();
        assert_eq!(bind.spk, k.kp.public());
        assert_eq!(open_bind(&bind, &s.kp, &psk, &s.inbox).unwrap(), b"hi");

        let msg = seal_message(&s.kp, k.kp.public(), &k.inbox, b"req").unwrap();
        let msg = Envelope::parse(&msg.to_bytes()).unwrap();
        assert_eq!(msg.spk, s.kp.public());
        assert_eq!(
            open_message(&msg, &k.kp, s.kp.public(), &k.inbox).unwrap(),
            b"req"
        );
    }

    #[test]
    fn every_flipped_byte_is_rejected() {
        let (s, k) = (party(), party());
        let bytes = seal_message(&s.kp, k.kp.public(), &k.inbox, b"x")
            .unwrap()
            .to_bytes();
        for i in 0..bytes.len() {
            let mut t = bytes.clone();
            t[i] ^= 0x01;
            let ok = Envelope::parse(&t)
                .and_then(|e| open_message(&e, &k.kp, s.kp.public(), &k.inbox))
                .is_ok();
            assert!(!ok, "flip at byte {i} accepted");
        }
    }

    #[test]
    fn wrong_psk_sender_inbox_or_kind_is_rejected() {
        let (s, k, psk) = (party(), party(), Psk::generate());
        let bind = seal_bind(&k.kp, s.kp.public(), &psk, &s.inbox, b"x").unwrap();
        assert!(open_bind(&bind, &s.kp, &Psk::generate(), &s.inbox).is_err());
        assert!(open_bind(&bind, &s.kp, &psk, &party().inbox).is_err());
        assert!(open_message(&bind, &s.kp, k.kp.public(), &s.inbox).is_err());

        let msg = seal_message(&s.kp, k.kp.public(), &k.inbox, b"x").unwrap();
        assert!(open_message(&msg, &k.kp, party().kp.public(), &k.inbox).is_err());
        assert!(open_message(&msg, &k.kp, s.kp.public(), &party().inbox).is_err());
        // A message sealed by another key but claiming the peer's spk.
        let mut forged = seal_message(&party().kp, k.kp.public(), &k.inbox, b"x").unwrap();
        forged.spk = s.kp.public();
        assert!(open_message(&forged, &k.kp, s.kp.public(), &k.inbox).is_err());
    }

    #[test]
    fn header_checks() {
        assert!(check_header(&[]).is_err());
        assert!(matches!(check_header(&[2, 2]), Err(Error::Version(2))));
        assert!(check_header(&[1, 9, 0, 0]).is_err());
        assert!(check_header(&[&[1u8, 2][..], &[0; 79]].concat()).is_err());
        assert!(check_header(&[&[1u8, 2][..], &[0; 80]].concat()).is_ok());
        assert!(check_header(&[&[1u8, 1][..], &[0; 80]].concat()).is_ok());
    }
}
