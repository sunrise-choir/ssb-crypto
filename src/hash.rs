use core::mem::size_of;
use zerocopy::{AsBytes, FromBytes};

/// A sha256 hash digest. The standard hash in the scuttleverse.
#[derive(AsBytes, FromBytes, PartialEq, Debug)]
#[repr(C)]
pub struct Hash(pub [u8; 32]);
impl Hash {
    /// The size in bytes of the Hash type ( == 32).
    pub const SIZE: usize = size_of::<Self>();

    /// Deserialize from byte representation.
    /// Returns `None` if the slice length isn't 32.
    /// Note that this doesn't hash the provided byte slice,
    /// use the [`hash`] function for that.
    pub fn from_slice(s: &[u8]) -> Option<Self> {
        if s.len() == Self::SIZE {
            let mut out = Self([0; Self::SIZE]);
            out.0.copy_from_slice(s);
            Some(out)
        } else {
            None
        }
    }

    /// Deserialize from base-64 string representation.
    /// Ignores optional leading '%' or '&' sigil and '.sha256' suffix.
    ///
    /// # Example
    /// ```rust
    /// let s = "%4hUgS4j0TwKdsZzOV/tfqiPtqoLw2qYg/Wl9Xy8FPEU=.sha256";
    /// let h = ssb_crypto::Hash::from_base64(s).unwrap();
    /// ```
    #[cfg(feature = "b64")]
    pub fn from_base64(mut s: &str) -> Option<Self> {
        let mut buf = [0; Self::SIZE];
        if s.starts_with('%') || s.starts_with('&') {
            s = &s[1..];
        }
        if crate::b64::decode(s, &mut buf, Some(".sha256")) {
            Some(Self(buf))
        } else {
            None
        }
    }
}

#[cfg(all(feature = "dalek", not(feature = "force_sodium")))]
pub use crate::dalek::hash::hash;
#[cfg(all(
    feature = "sodium",
    any(feature = "force_sodium", not(feature = "dalek"))
))]
pub use crate::sodium::hash::hash;
