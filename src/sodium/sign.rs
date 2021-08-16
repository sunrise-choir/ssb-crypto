use crate::utils::as_array_32;
use crate::{Keypair, PublicKey, SecretKey, Signature};
use sodiumoxide::crypto::sign;

impl From<&Keypair> for sign::SecretKey {
    fn from(k: &Keypair) -> Self {
        let mut buf = [0; 64];
        buf[..32].copy_from_slice(&k.secret.0);
        buf[32..].copy_from_slice(&k.public.0);
        Self(buf)
    }
}

pub fn generate_keypair() -> Keypair {
    let (p, s) = sign::gen_keypair();

    Keypair {
        public: PublicKey(p.0),
        secret: SecretKey(as_array_32(&s.0[..32])),
    }
}

pub fn keypair_from_seed(seed: &[u8]) -> Option<Keypair> {
    if seed.len() != 32 {
        return None;
    }

    let mut buf = [0; 32];
    buf.copy_from_slice(seed);
    let seed = sign::Seed(buf);
    let (p, s) = sign::keypair_from_seed(&seed);
    Some(Keypair {
        public: PublicKey(p.0),
        secret: SecretKey(as_array_32(&s.0[..32])),
    })
}

pub fn sign(k: &Keypair, b: &[u8]) -> Signature {
    let s = sign::sign_detached(b, &k.into());
    Signature(s.to_bytes())
}

pub fn verify(k: &PublicKey, sig: &Signature, b: &[u8]) -> bool {
    sign::verify_detached(&sign::Signature::new(sig.0), b, &sign::PublicKey(k.0))
}
