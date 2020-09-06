use crate::utils::as_array_32;
use crate::{ephemeral::*, PublicKey, SecretKey};

use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::{edwards::CompressedEdwardsY, montgomery::MontgomeryPoint};
use ed25519_dalek as dalek;
use rand::{CryptoRng, RngCore};
use x25519_dalek as x25519;

#[cfg(feature = "getrandom")]
pub fn generate_ephemeral_keypair() -> (EphPublicKey, EphSecretKey) {
    generate_ephemeral_keypair_with_rng(&mut rand::rngs::OsRng {})
}

pub fn generate_ephemeral_keypair_with_rng<R>(r: &mut R) -> (EphPublicKey, EphSecretKey)
where
    R: CryptoRng + RngCore,
{
    let s = x25519::StaticSecret::new(r);
    let p = x25519::PublicKey::from(&s);

    (EphPublicKey(*p.as_bytes()), EphSecretKey(s.to_bytes()))
}

// pub struct EphemeralSecret(pub(crate) Scalar);
// pub struct PublicKey(pub(crate) MontgomeryPoint);
// pub struct SharedSecret(pub(crate) MontgomeryPoint);

pub fn derive_shared_secret(sk: &EphSecretKey, pk: &EphPublicKey) -> Option<SharedSecret> {
    let s = x25519::StaticSecret::from(sk.0);
    let p = x25519::PublicKey::from(pk.0);

    Some(SharedSecret(*s.diffie_hellman(&p).as_bytes()))
}

pub fn derive_shared_secret_pk(sk: &EphSecretKey, pk: &PublicKey) -> Option<SharedSecret> {
    let e = CompressedEdwardsY(pk.0).decompress()?;
    if e.is_small_order() {
        return None;
    }
    let m = e.to_montgomery();
    let s = Scalar::from_bits(sk.0);
    Some(SharedSecret((s * m).to_bytes()))
}

pub fn derive_shared_secret_sk(sk: &SecretKey, pk: &EphPublicKey) -> Option<SharedSecret> {
    let exp = dalek::ExpandedSecretKey::from(&dalek::SecretKey::from_bytes(&sk.0).unwrap());
    let s = Scalar::from_bits(as_array_32(&exp.to_bytes()[..32]));
    let m = MontgomeryPoint(pk.0);
    Some(SharedSecret((s * m).to_bytes()))
}
