use crate::{Keypair, PublicKey, SecretKey, Signature};
use ed25519_dalek as dalek;

impl Into<dalek::Keypair> for &Keypair {
    fn into(self) -> dalek::Keypair {
        dalek::Keypair {
            secret: dalek::SecretKey::from_bytes(&self.secret.0).unwrap(),
            public: dalek::PublicKey::from_bytes(&self.public.0).unwrap(),
        }
    }
}

impl Into<Keypair> for dalek::Keypair {
    fn into(self) -> Keypair {
        Keypair {
            secret: SecretKey(self.secret.to_bytes()),
            public: PublicKey(self.public.to_bytes()),
        }
    }
}

pub fn generate_keypair() -> Keypair {
    let mut rng = rand::rngs::OsRng {};
    dalek::Keypair::generate(&mut rng).into()
}

pub fn keypair_from_seed(seed: &[u8]) -> Option<Keypair> {
    let s = dalek::SecretKey::from_bytes(&seed).ok()?;
    let p = dalek::PublicKey::from(&s);

    Some(Keypair {
        public: PublicKey(p.to_bytes()),
        secret: SecretKey(s.to_bytes()),
    })
}

pub fn sign(k: &Keypair, b: &[u8]) -> Signature {
    let kp: dalek::Keypair = k.into();
    Signature(kp.sign(b).to_bytes())
}

pub fn verify(k: &PublicKey, s: &Signature, b: &[u8]) -> bool {
    if let Ok(sig) = dalek::Signature::from_bytes(&s.0) {
        let pk = dalek::PublicKey::from_bytes(&k.0).unwrap();
        pk.verify(b, &sig).is_ok()
    } else {
        false
    }
}
