use crate::{ephemeral::*, PublicKey, SecretKey};

use libsodium_sys::{crypto_sign_ed25519_pk_to_curve25519, crypto_sign_ed25519_sk_to_curve25519};
use sodiumoxide::crypto::scalarmult::{scalarmult, GroupElement, Scalar};

// pub use box_::{PublicKey as EphPublicKey, SecretKey as EphSecretKey};
use sodiumoxide::crypto::box_;

pub fn generate_ephemeral_keypair() -> (EphPublicKey, EphSecretKey) {
    let (pk, sk) = box_::gen_keypair();
    (EphPublicKey(pk.0), EphSecretKey(sk.0))
}

pub fn derive_shared_secret(
    our_sec: &EphSecretKey,
    their_pub: &EphPublicKey,
) -> Option<SharedSecret> {
    let n = Scalar(our_sec.0);
    let p = GroupElement(their_pub.0);
    scalarmult(&n, &p).ok().map(|s| SharedSecret(s.0))
}

pub fn derive_shared_secret_pk(sk: &EphSecretKey, pk: &PublicKey) -> Option<SharedSecret> {
    pk_to_curve(&pk).and_then(|c| derive_shared_secret(&sk, &c))
}

pub fn derive_shared_secret_sk(sk: &SecretKey, pk: &EphPublicKey) -> Option<SharedSecret> {
    sk_to_curve(&sk).and_then(|c| derive_shared_secret(&c, &pk))
}

fn pk_to_curve(k: &PublicKey) -> Option<EphPublicKey> {
    let mut buf = [0; EphPublicKey::SIZE];

    let ok = unsafe { crypto_sign_ed25519_pk_to_curve25519(buf.as_mut_ptr(), k.0.as_ptr()) == 0 };

    if ok {
        Some(EphPublicKey(buf))
    } else {
        None
    }
}

pub fn sk_to_curve(k: &SecretKey) -> Option<EphSecretKey> {
    let mut buf = [0; EphSecretKey::SIZE];

    let ok = unsafe { crypto_sign_ed25519_sk_to_curve25519(buf.as_mut_ptr(), k.0.as_ptr()) == 0 };

    if ok {
        Some(EphSecretKey(buf))
    } else {
        None
    }
}
