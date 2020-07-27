use core::mem::size_of;
use zerocopy::{AsBytes, FromBytes};
use zeroize::Zeroize;

#[cfg(all(feature = "dalek", not(feature = "force_sodium")))]
use crate::dalek::auth;
#[cfg(all(
    feature = "sodium",
    any(feature = "force_sodium", not(feature = "dalek"))
))]
use crate::sodium::auth;

/// The network key, or network identifier, used during the secret handshake to prove
/// that both parties are participating in the same ssb network.
///
/// The main ssb network uses a publicly-known key, which is
/// available as `NetworkKey::SSB_MAIN_NET`.
///
/// This is an [HMAC](https://en.wikipedia.org/wiki/HMAC) key;
/// specifically HMAC-SHA-512-256.
#[derive(AsBytes, Clone, Debug, PartialEq, Zeroize)]
#[repr(C)]
#[zeroize(drop)]
pub struct NetworkKey(pub [u8; 32]); // auth::hmacsha512256::Key
impl NetworkKey {
    /// The size of a NetworkKey, in bytes (32).
    pub const SIZE: usize = size_of::<Self>();

    /// The NetworkKey for the primary ssb network.
    pub const SSB_MAIN_NET: NetworkKey = NetworkKey([
        0xd4, 0xa1, 0xcb, 0x88, 0xa6, 0x6f, 0x02, 0xf8, 0xdb, 0x63, 0x5c, 0xe2, 0x64, 0x41, 0xcc,
        0x5d, 0xac, 0x1b, 0x08, 0x42, 0x0c, 0xea, 0xac, 0x23, 0x08, 0x39, 0xb7, 0x55, 0x84, 0x5a,
        0x9f, 0xfb,
    ]);

    /// Deserialize from a slice of bytes.
    /// Returns `None` if the slice length isn't 32.
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

#[cfg(any(feature = "sodium", feature = "dalek"))]
impl NetworkKey {
    /// Generate an authentication code for the given byte slice.
    ///
    /// # Examples
    /// ```
    /// use ssb_crypto::{NetworkKey, ephemeral::*};
    /// let (pk, sk) = generate_ephemeral_keypair();
    /// let netkey = NetworkKey::SSB_MAIN_NET;
    /// let auth = netkey.authenticate(&pk.0);
    /// assert!(netkey.verify(&auth, &pk.0));
    /// ```
    pub fn authenticate(&self, b: &[u8]) -> NetworkAuth {
        auth::authenticate(self, b)
    }

    /// Verify that an authentication code was generated
    /// by this key, given the same byte slice.
    pub fn verify(&self, auth: &NetworkAuth, b: &[u8]) -> bool {
        auth::verify(self, auth, b)
    }

    /// Generate a random network key.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use ssb_crypto::NetworkKey;
    /// let key = NetworkKey::generate();
    /// assert_ne!(key, NetworkKey::SSB_MAIN_NET);
    /// ```
    pub fn generate() -> NetworkKey {
        auth::generate_key()
    }
}

// auth::hmacsha512256::Tag
/// An authentication code, produced by [`NetworkKey::authenticate`]
/// and verified by [`NetworkKey::verify`].
///
/// [`NetworkKey::authenticate`]: ./struct.NetworkKey.html#method.authenticate
/// [`NetworkKey::verify`]: ./struct.NetworkKey.html#method.verify
#[derive(AsBytes, FromBytes)]
#[repr(C)]
pub struct NetworkAuth(pub [u8; 32]);
impl NetworkAuth {
    /// The size in bytes of a NetworkAuth (32).
    pub const SIZE: usize = size_of::<Self>();
}
