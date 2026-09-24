//! The bytes the relay stores and forwards (§4.3).
//!
//! ```text
//! 0      1   version = 0x01
//! 1      1   type    = 0x01 hello | 0x02 message
//! 2      32  spk     (hello only)
//! ..     32  enc
//! ..     ..  ct      (includes 16-byte tag)
//! ```

use hpke::{
    Deserializable, OpModeR, OpModeS, PskBundle, Serializable, aead::AesGcm256, kdf::HkdfSha256,
    rand_core::CryptoRng,
};

use crate::keys::{Kem, KeyPair, Psk, PublicKey};
use crate::mailbox::MailboxId;
use crate::{Error, Result, VERSION, pad};

const PSK_ID: &[u8] = b"blox/v1/session";
const AAD_PREFIX: &[u8] = b"blox/v1";
const TAG_LEN: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Kind {
    Hello = 0x01,
    Message = 0x02,
}

impl Kind {
    fn from_byte(b: u8) -> Result<Self> {
        match b {
            0x01 => Ok(Kind::Hello),
            0x02 => Ok(Kind::Message),
            _ => Err(Error::Malformed("envelope type")),
        }
    }

    fn info(self) -> &'static [u8] {
        match self {
            Kind::Hello => b"blox/v1/hello",
            Kind::Message => b"blox/v1/msg",
        }
    }

    fn header_len(self) -> usize {
        match self {
            Kind::Hello => 2 + 32 + 32,
            Kind::Message => 2 + 32,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Envelope {
    pub kind: Kind,
    /// Sender public key; present only for [`Kind::Hello`].
    pub spk: Option<PublicKey>,
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
    if bytes.len() < kind.header_len() + TAG_LEN {
        return Err(Error::Malformed("envelope too short"));
    }
    Ok(kind)
}

impl Envelope {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.kind.header_len() + self.ct.len());
        out.push(VERSION);
        out.push(self.kind as u8);
        if let Some(spk) = self.spk {
            out.extend_from_slice(&spk.0);
        }
        out.extend_from_slice(&self.enc);
        out.extend_from_slice(&self.ct);
        out
    }

    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let kind = check_header(bytes)?;
        let mut rest = &bytes[2..];
        let spk = if kind == Kind::Hello {
            let (k, r) = rest.split_at(32);
            rest = r;
            Some(PublicKey(k.try_into().unwrap()))
        } else {
            None
        };
        let (enc, ct) = rest.split_at(32);
        Ok(Envelope {
            kind,
            spk,
            enc: enc.try_into().unwrap(),
            ct: ct.to_vec(),
        })
    }
}

fn aad(recipient: &MailboxId) -> Vec<u8> {
    [AAD_PREFIX, recipient.as_bytes()].concat()
}

/// Pads and seals `plaintext` from `sender` to `recipient_pk`, bound to the recipient's mailbox.
pub fn seal(
    kind: Kind,
    sender: &KeyPair,
    recipient_pk: PublicKey,
    psk: &Psk,
    recipient_mailbox: &MailboxId,
    plaintext: &[u8],
) -> Result<Envelope> {
    seal_with_rng(
        kind,
        sender,
        recipient_pk,
        psk,
        recipient_mailbox,
        plaintext,
        &mut OsRng,
    )
}

pub(crate) fn seal_with_rng(
    kind: Kind,
    sender: &KeyPair,
    recipient_pk: PublicKey,
    psk: &Psk,
    recipient_mailbox: &MailboxId,
    plaintext: &[u8],
    rng: &mut impl CryptoRng,
) -> Result<Envelope> {
    let padded = pad::pad(plaintext)?;
    let bundle = PskBundle::new(&psk.0, PSK_ID).map_err(|_| Error::Crypto)?;
    let mode = OpModeS::<Kem>::AuthPsk((sender.sk.clone(), sender.pk.clone()), bundle);
    let (enc, ct) = hpke::single_shot_seal_with_rng::<AesGcm256, HkdfSha256, Kem>(
        &mode,
        &recipient_pk.to_hpke()?,
        kind.info(),
        &padded,
        &aad(recipient_mailbox),
        rng,
    )
    .map_err(|_| Error::Crypto)?;
    Ok(Envelope {
        kind,
        spk: (kind == Kind::Hello).then(|| sender.public()),
        enc: enc.to_bytes().into(),
        ct,
    })
}

/// Opens an envelope addressed to `recipient_mailbox`, authenticating `sender_pk`.
///
/// For a hello, pass `env.spk` as the sender key; the adapter decides separately
/// whether it accepts that key (first join only, §5.3).
pub fn open(
    env: &Envelope,
    recipient: &KeyPair,
    sender_pk: PublicKey,
    psk: &Psk,
    recipient_mailbox: &MailboxId,
) -> Result<Vec<u8>> {
    let bundle = PskBundle::new(&psk.0, PSK_ID).map_err(|_| Error::Crypto)?;
    let mode = OpModeR::<Kem>::AuthPsk(sender_pk.to_hpke()?, bundle);
    let enc = <Kem as hpke::Kem>::EncappedKey::from_bytes(&env.enc).map_err(|_| Error::Crypto)?;
    let padded = hpke::single_shot_open::<AesGcm256, HkdfSha256, Kem>(
        &mode,
        &recipient.sk,
        &enc,
        env.kind.info(),
        &env.ct,
        &aad(recipient_mailbox),
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
    use crate::mailbox::ReadSecret;

    struct Party {
        kp: KeyPair,
        mb: MailboxId,
    }

    fn party() -> Party {
        Party {
            kp: KeyPair::generate(),
            mb: ReadSecret::generate().mailbox_id(),
        }
    }

    #[test]
    fn hello_and_message_roundtrip() {
        let (a, k, psk) = (party(), party(), Psk::generate());

        let hello = seal(Kind::Hello, &k.kp, a.kp.public(), &psk, &a.mb, b"hi").unwrap();
        let hello = Envelope::parse(&hello.to_bytes()).unwrap();
        assert_eq!(hello.spk, Some(k.kp.public()));
        let pt = open(&hello, &a.kp, hello.spk.unwrap(), &psk, &a.mb).unwrap();
        assert_eq!(pt, b"hi");

        let msg = seal(Kind::Message, &a.kp, k.kp.public(), &psk, &k.mb, b"req").unwrap();
        let msg = Envelope::parse(&msg.to_bytes()).unwrap();
        assert_eq!(msg.spk, None);
        assert_eq!(
            open(&msg, &k.kp, a.kp.public(), &psk, &k.mb).unwrap(),
            b"req"
        );
    }

    #[test]
    fn every_flipped_byte_is_rejected() {
        let (a, k, psk) = (party(), party(), Psk::generate());
        let bytes = seal(Kind::Message, &a.kp, k.kp.public(), &psk, &k.mb, b"x")
            .unwrap()
            .to_bytes();
        for i in 0..bytes.len() {
            let mut t = bytes.clone();
            t[i] ^= 0x01;
            let ok = Envelope::parse(&t)
                .and_then(|e| open(&e, &k.kp, a.kp.public(), &psk, &k.mb))
                .is_ok();
            assert!(!ok, "flip at byte {i} accepted");
        }
    }

    #[test]
    fn wrong_psk_sender_or_mailbox_is_rejected() {
        let (a, k, psk) = (party(), party(), Psk::generate());
        let env = seal(Kind::Message, &a.kp, k.kp.public(), &psk, &k.mb, b"x").unwrap();
        assert!(open(&env, &k.kp, a.kp.public(), &Psk::generate(), &k.mb).is_err());
        assert!(open(&env, &k.kp, party().kp.public(), &psk, &k.mb).is_err());
        assert!(open(&env, &k.kp, a.kp.public(), &psk, &party().mb).is_err());
    }

    #[test]
    fn header_checks() {
        assert!(check_header(&[]).is_err());
        assert!(matches!(check_header(&[2, 2]), Err(Error::Version(2))));
        assert!(check_header(&[1, 9, 0, 0]).is_err());
        assert!(check_header(&[1, 2]).is_err());
        assert!(check_header(&[&[1u8, 2][..], &[0; 48]].concat()).is_ok());
        assert!(check_header(&[&[1u8, 1][..], &[0; 48]].concat()).is_err());
    }
}
