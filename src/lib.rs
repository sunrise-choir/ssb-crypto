use core::mem::size_of;

extern crate sodiumoxide;

use sodiumoxide::crypto::{auth, sign};

pub use sign::{PublicKey, SecretKey, Signature, sign_detached, verify_detached};
pub use sodiumoxide::crypto::secretbox;
pub use auth::{Tag as AuthTag};

pub mod hash;
pub mod handshake;

pub fn generate_longterm_keypair() -> (PublicKey, SecretKey) {
    sign::gen_keypair()
}

/// 32-byte network key, known by client and server. Usually `NetworkKey::SSB_MAIN_NET`
#[derive(Clone)]
pub struct NetworkKey(auth::Key);
impl NetworkKey {
    pub const SSB_MAIN_NET: NetworkKey = NetworkKey(auth::Key([
        0xd4, 0xa1, 0xcb, 0x88, 0xa6, 0x6f, 0x02, 0xf8, 0xdb, 0x63, 0x5c, 0xe2, 0x64, 0x41, 0xcc,
        0x5d, 0xac, 0x1b, 0x08, 0x42, 0x0c, 0xea, 0xac, 0x23, 0x08, 0x39, 0xb7, 0x55, 0x84, 0x5a,
        0x9f, 0xfb,
    ]));

    pub fn as_slice(&self) -> &[u8] {
        &self.0[..]
    }
    pub fn from_slice(b: &[u8]) -> Option<NetworkKey> {
        Some(NetworkKey(auth::Key::from_slice(b)?))
    }

    pub fn authenticate(&self, data: &[u8]) -> AuthTag {
        auth::authenticate(data, &self.0)
    }

    pub fn verify(&self, tag: &AuthTag, data: &[u8]) -> bool {
        auth::verify(tag, data, &self.0)
    }

    pub const fn size() -> usize {
        size_of::<auth::Key>()
    }
}

pub struct NonceGen {
    next_nonce: secretbox::Nonce,
}

impl NonceGen {
    pub fn new(pk: &handshake::EphPublicKey, net_id: &NetworkKey) -> NonceGen {
        let hmac = auth::authenticate(&pk[..], &net_id.0);
        const N: usize = size_of::<secretbox::Nonce>();
        NonceGen {
            next_nonce: secretbox::Nonce::from_slice(&hmac[..N]).unwrap(),
        }
    }

    /// #Examples
    /// ```rust
    /// use shs_core::NonceGen;
    /// use sodiumoxide::crypto::secretbox::Nonce;
    ///
    /// let nonce_bytes = [0, 0, 0, 0, 0, 0, 0, 0,
    ///                    0, 0, 0, 0, 0, 0, 0, 0,
    ///                    0, 0, 0, 0, 0, 0, 255, 255];
    /// let mut gen = NonceGen::with_starting_nonce(Nonce::from_slice(&nonce_bytes).unwrap());
    /// let n1 = gen.next();
    /// assert_eq!(&n1[..], &nonce_bytes);
    /// let n2 = gen.next();
    /// assert_eq!(&n2[..], [0, 0, 0, 0, 0, 0, 0, 0,
    ///                      0, 0, 0, 0, 0, 0, 0, 0,
    ///                      0, 0, 0, 0, 0, 1, 0, 0]);
    /// ```
    pub fn with_starting_nonce(nonce: secretbox::Nonce) -> NonceGen {
        NonceGen {
            next_nonce: nonce
        }
    }

    pub fn next(&mut self) -> secretbox::Nonce {
        let n = self.next_nonce.clone();

        // Increment the nonce as a big-endian u24
        for byte in self.next_nonce.0.iter_mut().rev() {
            *byte = byte.wrapping_add(1);
            if *byte != 0 {
                break;
            }
        }
        n
    }
}
