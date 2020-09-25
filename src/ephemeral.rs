//! Ephemeral (curve25519) keys and operations for deriving shared secrets via
//! [Elliptic-curve Diffie–Hellman](https://en.wikipedia.org/wiki/Elliptic-curve_Diffie–Hellman)
use core::mem::size_of;
use zerocopy::{AsBytes, FromBytes};
use zeroize::Zeroize;

// pub use box_::{PublicKey as EphPublicKey, SecretKey as EphSecretKey};

#[cfg(all(feature = "dalek", not(feature = "force_sodium")))]
use crate::dalek::ephemeral as eph;
#[cfg(all(
    feature = "sodium",
    any(feature = "force_sodium", not(feature = "dalek"))
))]
use crate::sodium::ephemeral as eph;

#[cfg(any(feature = "sodium", feature = "dalek"))]
pub use eph::{
    derive_shared_secret, derive_shared_secret_pk, derive_shared_secret_sk, sk_to_curve,
};

#[cfg(any(feature = "sodium", all(feature = "dalek", feature = "getrandom")))]
pub use eph::generate_ephemeral_keypair;

#[cfg(feature = "dalek")]
pub use crate::dalek::ephemeral::generate_ephemeral_keypair_with_rng;

/// The secret half of an ephemeral key pair; used for deriving a short-term shared secret for
/// secure communication.
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct EphSecretKey(pub [u8; 32]);
impl EphSecretKey {
    /// The size of an EphSecretKey, in bytes (32).
    pub const SIZE: usize = size_of::<Self>();
}

/// The public half of an ephemeral key pair.
#[derive(Copy, Clone, AsBytes, FromBytes)]
#[repr(C)]
pub struct EphPublicKey(pub [u8; 32]);
impl EphPublicKey {
    /// The size of an EphPublicKey, in bytes (32).
    pub const SIZE: usize = size_of::<Self>();

    /// Deserialize from a byte slice.
    ///
    /// The slice must have length 32.
    pub fn from_slice(s: &[u8]) -> Option<Self> {
        if s.len() == Self::SIZE {
            let mut out = Self([0; Self::SIZE]);
            out.0.copy_from_slice(s);
            Some(out)
        } else {
            None
        }
    }
}

/// A secret that's shared by two participants in a secure communication,
/// derived from their respective key pairs.
#[derive(AsBytes, Clone, Zeroize)]
#[repr(C)]
#[zeroize(drop)]
pub struct SharedSecret(pub [u8; 32]);
