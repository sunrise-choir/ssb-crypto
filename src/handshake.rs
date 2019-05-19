
use libsodium_sys::{crypto_sign_ed25519_pk_to_curve25519, crypto_sign_ed25519_sk_to_curve25519};
use sodiumoxide::crypto::scalarmult::{self, scalarmult, Scalar};
pub use scalarmult::{GroupElement as SharedSecret};

use crate::*;

use sodiumoxide::crypto::box_;
pub use box_::{
    PublicKey as EphPublicKey,
    SecretKey as EphSecretKey,
};

pub struct HandshakeKeys {
    pub read_key: secretbox::Key,
    pub read_noncegen: NonceGen,

    pub write_key: secretbox::Key,
    pub write_noncegen: NonceGen,
}

pub fn generate_ephemeral_keypair() -> (EphPublicKey, EphSecretKey) {
    box_::gen_keypair()
}

pub fn derive_shared_secret(
    our_sec: &EphSecretKey,
    their_pub: &EphPublicKey,
) -> Option<SharedSecret> {
    // Benchmarks suggest that these "copies" get optimized away.
    let n = Scalar::from_slice(&our_sec[..])?;
    let p = SharedSecret::from_slice(&their_pub[..])?;
    scalarmult(&n, &p).ok()
}

pub fn derive_shared_secret_pk(sk: &EphSecretKey, pk: &PublicKey)
                               -> Option<SharedSecret> {
    pk_to_curve(&pk)
        .and_then(|c| derive_shared_secret(&sk, &c))
}

pub fn derive_shared_secret_sk(sk: &SecretKey, pk: &EphPublicKey)
                               -> Option<SharedSecret> {
    sk_to_curve(&sk)
        .and_then(|c| derive_shared_secret(&c, &pk))
}

fn pk_to_curve(k: &PublicKey) -> Option<EphPublicKey> {
    let mut buf = [0; size_of::<EphPublicKey>()];

    let ok = unsafe { crypto_sign_ed25519_pk_to_curve25519(buf.as_mut_ptr(), k.0.as_ptr()) == 0 };

    if ok {
        EphPublicKey::from_slice(&buf)
    } else {
        None
    }
}

fn sk_to_curve(k: &SecretKey) -> Option<EphSecretKey> {
    let mut buf = [0; size_of::<EphSecretKey>()];

    let ok = unsafe { crypto_sign_ed25519_sk_to_curve25519(buf.as_mut_ptr(), k.0.as_ptr()) == 0 };

    if ok {
        EphSecretKey::from_slice(&buf)
    } else {
        None
    }
}
