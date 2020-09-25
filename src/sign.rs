use crate::utils::as_array_32;
use core::fmt;
use core::mem::size_of;
#[cfg(feature = "dalek")]
use rand::{CryptoRng, RngCore};
use zerocopy::{AsBytes, FromBytes};
use zeroize::Zeroize;

#[cfg(all(feature = "dalek", not(feature = "force_sodium")))]
use crate::dalek::sign;
#[cfg(all(
    feature = "sodium",
    any(feature = "force_sodium", not(feature = "dalek"))
))]
use crate::sodium::sign;

/// A public/secret long-term key pair.
///
/// This is an [Ed25519](https://en.wikipedia.org/wiki/EdDSA) key pair.
#[derive(Clone, Debug, AsBytes, FromBytes)]
#[repr(C)]
pub struct Keypair {
    /// The secret half of the key pair. Keep private.
    pub secret: SecretKey,

    /// The public half of the key pair. Feel free to share.
    pub public: PublicKey,
}

impl Keypair {
    /// Size of a key pair, in bytes (== 64).
    pub const SIZE: usize = size_of::<Self>();

    /// Deserialize a keypair from a byte slice.
    ///
    /// The slice length must be 64; where the first 32 bytes
    /// are the secret key, and the second 32 bytes are the public key
    /// (libsodium's standard layout).
    pub fn from_slice(s: &[u8]) -> Option<Self> {
        if s.len() == Self::SIZE {
            Some(Keypair {
                secret: SecretKey(as_array_32(&s[..32])),
                public: PublicKey(as_array_32(&s[32..])),
            })
        } else {
            None
        }
    }

    /// Deserialize from the bas64 representation. Ignores optional .ed25519 suffix.
    ///
    /// # Example
    /// ```rust
    /// let s = "R6DKoOCt1Cj/IB2/ocvj2Eyp8AgmFdoJ9hH2TO4Tl8Yfapd5Lmw4pSpoY0WBEnqpHjz6UB4/QL2Wr0hWVAyi1w==.ed25519";
    /// if let Some(keypair) = ssb_crypto::Keypair::from_base64(s) {
    ///   // let auth = keypair.sign("hello".to_bytes());
    ///   // ...
    /// } else {
    ///     panic!()
    /// }
    /// ```
    #[cfg(feature = "b64")]
    pub fn from_base64(s: &str) -> Option<Self> {
        let mut buf = [0; 64];
        if crate::b64::decode(s, &mut buf, Some(".ed25519")) {
            Self::from_slice(&buf)
        } else {
            None
        }
    }

    /// Does not include ".ed25519" suffix or a sigil prefix.
    ///
    /// # Example
    /// ```rust
    /// let s = "R6DKoOCt1Cj/IB2/ocvj2Eyp8AgmFdoJ9hH2TO4Tl8Yfapd5Lmw4pSpoY0WBEnqpHjz6UB4/QL2Wr0hWVAyi1w==";
    /// let kp = ssb_crypto::Keypair::from_base64(s).unwrap();
    /// assert_eq!(kp.as_base64(), s);
    /// ```
    #[cfg(feature = "alloc")]
    pub fn as_base64(&self) -> alloc::string::String {
        let mut buf = [0; 64];
        let (s, p) = buf.split_at_mut(32);
        s.copy_from_slice(&self.secret.0);
        p.copy_from_slice(&self.public.0);
        base64::encode_config(&buf[..], base64::STANDARD)
    }

    /// Generate a new random keypair.
    #[cfg(any(feature = "sodium", all(feature = "dalek", feature = "getrandom")))]
    pub fn generate() -> Keypair {
        sign::generate_keypair()
    }

    /// Create a keypair from the given seed bytes. Slice length must be 32.
    #[cfg(any(feature = "sodium", feature = "dalek"))]
    pub fn from_seed(seed: &[u8]) -> Option<Keypair> {
        sign::keypair_from_seed(seed)
    }

    /// Generate a new random keypair using the given cryptographically-secure
    /// random number generator.
    #[cfg(feature = "dalek")]
    pub fn generate_with_rng<R>(r: &mut R) -> Keypair
    where
        R: CryptoRng + RngCore,
    {
        crate::dalek::sign::generate_keypair_with_rng(r)
    }

    /// Generate a signature for a given byte slice.
    #[cfg(any(feature = "sodium", feature = "dalek"))]
    pub fn sign(&self, b: &[u8]) -> Signature {
        sign::sign(&self, b)
    }
}

/// The secret half of a [`Keypair`].
///
/// Note that a libsodium "secret key" is actually a pair of secret and public keys,
/// in the same buffer. This is only the secret half, which isn't much use on its own.
/// For signing, and deserializing a libsodium secretkey encoded in base64
/// (as in the ~/.ssb/secret file), see [`Keypair`].
///
/// The underlying memory is zeroed on drop.
///
/// [`Keypair`]: ./struct.Keypair.html
#[derive(Clone, Debug, AsBytes, FromBytes, Zeroize)]
#[zeroize(drop)]
#[repr(C)]
pub struct SecretKey(pub [u8; 32]);
impl SecretKey {
    /// Size of a secret key, in bytes (32).
    pub const SIZE: usize = size_of::<Self>();
}

/// The public half of a [`Keypair`].
///
/// [`Keypair`]: ./struct.Keypair.html
#[derive(AsBytes, FromBytes, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[repr(C)]
pub struct PublicKey(pub [u8; 32]);
impl PublicKey {
    /// Size of a public key, in bytes (== 32).
    pub const SIZE: usize = size_of::<Self>();

    /// Deserialize a public key from a byte slice. The slice length must be 32.
    pub fn from_slice(s: &[u8]) -> Option<Self> {
        if s.len() == Self::SIZE {
            let mut out = Self([0; Self::SIZE]);
            out.0.copy_from_slice(s);
            Some(out)
        } else {
            None
        }
    }

    /// Deserialize from the base-64 representation. Ignores optional leading '@' sigil and '.ed25519' suffix.
    ///
    /// # Example
    /// ```rust
    /// use ssb_crypto::PublicKey;
    /// let author = "@H2qXeS5sOKUqaGNFgRJ6qR48+lAeP0C9lq9IVlQMotc=.ed25519";
    /// let pk = PublicKey::from_base64(author).unwrap();
    /// ```
    #[cfg(feature = "b64")]
    pub fn from_base64(mut s: &str) -> Option<Self> {
        if s.starts_with('@') {
            s = &s[1..];
        }
        let mut buf = [0; Self::SIZE];
        if crate::b64::decode(s, &mut buf, Some(".ed25519")) {
            Some(Self(buf))
        } else {
            None
        }
    }

    /// Does not include ".ed25519" suffix or a prefix sigil.
    ///
    /// # Example
    /// ```rust
    /// let s = "H2qXeS5sOKUqaGNFgRJ6qR48+lAeP0C9lq9IVlQMotc=";
    /// let pk = ssb_crypto::PublicKey::from_base64(s).unwrap();
    /// assert_eq!(pk.as_base64(), s);
    /// ```
    #[cfg(feature = "alloc")]
    pub fn as_base64(&self) -> alloc::string::String {
        base64::encode_config(&self.0, base64::STANDARD)
    }

    /// Verify that a signature was generated by this key's secret half for the given
    /// bytes.
    #[cfg(any(feature = "sodium", feature = "dalek"))]
    pub fn verify(&self, sig: &Signature, b: &[u8]) -> bool {
        sign::verify(self, sig, b)
    }
}

/// A cryptographic signature of some content, generated by [`Keypair::sign`]
/// and verified by [`PublicKey::verify`].
///
/// [`Keypair::sign`]: ./struct.Keypair.html#method.sign
/// [`PublicKey::verify`]: ./struct.PublicKey.html#method.verify
#[derive(AsBytes, FromBytes, Copy, Clone)]
#[repr(C)]
pub struct Signature(pub [u8; 64]);
impl Signature {
    /// Size of a signature, in bytes (== 64).
    pub const SIZE: usize = size_of::<Self>();

    /// Deserialize a signature from a byte slice. The slice length must be 64.
    pub fn from_slice(s: &[u8]) -> Option<Self> {
        if s.len() == Self::SIZE {
            let mut out = Self([0; Self::SIZE]);
            out.0.copy_from_slice(s);
            Some(out)
        } else {
            None
        }
    }

    /// Deserialize a signature from a base-64 encoded string. Ignores optional .sig.ed25519 suffix.
    ///
    /// # Example
    /// ```rust
    /// use ssb_crypto::Signature;
    /// let s = "QTsCZ+INzDENs1dAdej14Lsp1v2UCXUtRZBv4HlDGo6WZn29ZYM5lZtxnyNC53LxX0ucY1x8NlC1A1RjY7FHBA==.sig.ed25519";
    /// let sig = Signature::from_base64(s).unwrap();
    /// ```
    #[cfg(feature = "b64")]
    pub fn from_base64(s: &str) -> Option<Self> {
        let mut buf = [0; Self::SIZE];
        if crate::b64::decode(s, &mut buf, Some(".sig.ed25519")) {
            Some(Self(buf))
        } else {
            None
        }
    }

    /// Does not include ".sig.ed25519" suffix or a prefix sigil.
    ///
    /// # Example
    /// ```rust
    /// use ssb_crypto::Signature;
    /// let s = "QTsCZ+INzDENs1dAdej14Lsp1v2UCXUtRZBv4HlDGo6WZn29ZYM5lZtxnyNC53LxX0ucY1x8NlC1A1RjY7FHBA==";
    /// let sig = Signature::from_base64(s).unwrap();
    /// assert_eq!(sig.as_base64(), s);
    /// ```
    #[cfg(feature = "alloc")]
    pub fn as_base64(&self) -> alloc::string::String {
        base64::encode_config(&self.0[..], base64::STANDARD)
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Signature({:?})", &self.0[..])
    }
}
impl Eq for Signature {}
impl PartialEq for Signature {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_ref().eq(other.0.as_ref())
    }
}
