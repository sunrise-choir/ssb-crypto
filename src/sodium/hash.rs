use crate::hash::Hash;
use sodiumoxide::crypto::hash::sha256;

pub fn hash(b: &[u8]) -> Hash {
    let d = sha256::hash(b);
    Hash(d.0)
}
