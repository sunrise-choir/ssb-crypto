use core::mem::size_of;
use std::sync::Once;

extern crate sodiumoxide;
use sodiumoxide::crypto::{auth, sign};

pub use sign::{PublicKey, SecretKey, Signature, sign_detached, verify_detached};
pub use sodiumoxide::crypto::secretbox;
pub use auth::{Tag as AuthTag};

pub mod hash;
pub mod handshake;
pub mod utils;

static INIT: Once = Once::new();
pub fn init() {
    INIT.call_once(|| {
        sodiumoxide::init().expect("Failed to initialize libsodium.");
    });
}

pub fn generate_longterm_keypair() -> (PublicKey, SecretKey) {
    sign::gen_keypair()
}

/// 32-byte network key, known by client and server. Usually `NetworkKey::SSB_MAIN_NET`
#[derive(Clone, Debug, PartialEq)]
pub struct NetworkKey(auth::Key);
impl NetworkKey {
    pub const SSB_MAIN_NET: NetworkKey = NetworkKey(auth::Key([
        0xd4, 0xa1, 0xcb, 0x88, 0xa6, 0x6f, 0x02, 0xf8, 0xdb, 0x63, 0x5c, 0xe2, 0x64, 0x41, 0xcc,
        0x5d, 0xac, 0x1b, 0x08, 0x42, 0x0c, 0xea, 0xac, 0x23, 0x08, 0x39, 0xb7, 0x55, 0x84, 0x5a,
        0x9f, 0xfb,
    ]));

    pub fn random() -> NetworkKey {
        let mut buf = [0u8; NetworkKey::size()];
        utils::randombytes_into(&mut buf);
        NetworkKey::from_slice(&buf).unwrap()
    }

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
    /// use ssb_crypto::NonceGen;
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


#[cfg(test)]
mod tests {
    use core::mem::size_of;
    use super::{
        generate_longterm_keypair,
        handshake::*,
        NetworkKey,
        PublicKey,
    };

    #[test]
    fn networkkey_random() {
        let a = NetworkKey::random();
        let b = NetworkKey::random();

        assert_ne!(a, b);
        assert_ne!(a, NetworkKey::from_slice(&[0u8; NetworkKey::size()]).unwrap());
    }

    #[test]
    fn shared_secret_with_zero() {
        let (c_eph_pk, _) = generate_ephemeral_keypair();
        let (c_pk, _) = generate_longterm_keypair();

        let (_, s_eph_sk) = generate_ephemeral_keypair();
        let (_, s_sk) = generate_longterm_keypair();


        assert!(derive_shared_secret(&s_eph_sk, &c_eph_pk).is_some());
        let zero_eph_pk = EphPublicKey::from_slice(&[0; size_of::<EphPublicKey>()]).unwrap();
        assert!(derive_shared_secret(&s_eph_sk, &zero_eph_pk).is_none());

        assert!(derive_shared_secret_pk(&s_eph_sk, &c_pk).is_some());
        let zero_pk = PublicKey::from_slice(&[0; size_of::<PublicKey>()]).unwrap();
        assert!(derive_shared_secret_pk(&s_eph_sk, &zero_pk).is_none());

        assert!(derive_shared_secret_sk(&s_sk, &c_eph_pk).is_some());
        assert!(derive_shared_secret_sk(&s_sk, &zero_eph_pk).is_none());
    }
}
