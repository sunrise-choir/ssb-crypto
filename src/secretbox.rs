//! Secret (encrypted) "boxes" of data. (libsodium's secretbox, aka xsalsa20poly1305)
use core::mem::size_of;
use zerocopy::{AsBytes, FromBytes};
use zeroize::Zeroize;

#[cfg(all(feature = "dalek", not(feature = "force_sodium")))]
use crate::dalek::secretbox as sb;
#[cfg(all(
    feature = "sodium",
    any(feature = "force_sodium", not(feature = "dalek"))
))]
use crate::sodium::secretbox as sb;

/// A key used to seal and open an encrypted box.
///
/// The underlying memory is zeroed on drop.
#[derive(AsBytes, FromBytes, Clone, Zeroize)]
#[repr(C)]
#[zeroize(drop)]
pub struct Key(pub [u8; 32]);
impl Key {
    /// The size of a key, in bytes (32).
    pub const SIZE: usize = size_of::<Self>();

    /// Deserialize a key from a byte slice.
    ///
    /// Returns `None` if the slice length is not 32.
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
impl Key {
    /// Generate a new random key.
    pub fn generate() -> Key {
        sb::generate_key()
    }

    /// Encrypt a message in place, returning the authentication code.
    pub fn seal(&self, msg: &mut [u8], n: &Nonce) -> Hmac {
        sb::seal(self, msg, n)
    }

    /// Decrypt an encrypted message in place.
    #[must_use]
    pub fn open(&self, c: &mut [u8], hmac: &Hmac, n: &Nonce) -> bool {
        sb::open(self, c, hmac, n)
    }

    /// Decrypt an encrypted message with attached authentication code,
    /// writing the decrypted message into the provided buffer.
    ///
    /// If the decryption fails, `out` will contain a copy of the encrypted message.
    ///
    /// # Panics
    ///
    /// Panics if the output buffer length isn't big enough to hold the plaintext message.
    /// The output buffer length should be at least `input.len() - Hmac::SIZE`.
    #[must_use]
    pub fn open_attached_into(&self, input: &[u8], n: &Nonce, mut out: &mut [u8]) -> bool {
        let (h, c) = input.split_at(Hmac::SIZE);
        let hmac = Hmac::from_slice(h).unwrap();
        out.copy_from_slice(c);
        self.open(&mut out, &hmac, n)
    }

    /// Encrypt a message, writing the resulting [`Hmac`] and ciphertext into the
    /// given output buffer. The output buffer size must be at least `msg.len() + Hmac::SIZE`.
    ///
    /// [`Hmac`]: ./struct.Hmac.html
    pub fn seal_attached_into(&self, msg: &[u8], nonce: &Nonce, out: &mut [u8]) {
        assert!(out.len() >= msg.len() + Hmac::SIZE);

        let (h, mut c) = out.split_at_mut(Hmac::SIZE);
        c.copy_from_slice(msg);
        let hmac = self.seal(&mut c, nonce);
        h.copy_from_slice(hmac.as_bytes());
    }
}

/// A single-use value used during encryption.
/// Each encrypted/sealed box must have its own nonce.
#[derive(AsBytes, FromBytes, Copy, Clone)]
#[repr(C)]
pub struct Nonce(pub [u8; 24]);
impl Nonce {
    /// The size of a nonce, in bytes (24).
    pub const SIZE: usize = size_of::<Self>();

    /// A nonce, filled with zeros. This is used during the ssb handshake,
    /// and probably shouldn't be used otherwise.
    pub fn zero() -> Nonce {
        Nonce([0; 24])
    }

    /// Generate a new, random nonce.
    #[cfg(any(feature = "sodium", feature = "dalek"))]
    pub fn generate() -> Nonce {
        sb::generate_nonce()
    }

    /// Deserialize a nonce from a byte slice.
    ///
    /// Returns `None` if the byte slice length isn't 24.
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

/// The authentication code for an encrypted secret box.
#[derive(Copy, Clone, AsBytes, FromBytes)]
#[repr(C)]
pub struct Hmac(pub [u8; 16]);
impl Hmac {
    /// The size of an Hmac, in bytes (24).
    pub const SIZE: usize = size_of::<Self>();

    /// Deserialize an Hmac from a byte slice.
    ///
    /// Returns `None` if the byte slice length isn't 16.
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
