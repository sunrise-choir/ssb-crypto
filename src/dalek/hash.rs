use crate::hash::Hash;
use sha2::Digest;
use sha2::Sha256;

/// Generate a sha256 hash digest from the given byte slice.
pub fn hash(b: &[u8]) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update(b);
    Hash::from_slice(hasher.finalize().as_ref()).unwrap()
}
