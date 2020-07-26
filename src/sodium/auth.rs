use crate::{NetworkAuth, NetworkKey};
use sodiumoxide::crypto::auth;

pub fn authenticate(k: &NetworkKey, m: &[u8]) -> NetworkAuth {
    let a = auth::authenticate(m, &auth::Key(k.0));
    NetworkAuth(a.0)
}

pub fn verify(k: &NetworkKey, a: &NetworkAuth, m: &[u8]) -> bool {
    auth::verify(&auth::Tag(a.0), m, &auth::Key(k.0))
}

pub fn generate_key() -> NetworkKey {
    let k = auth::gen_key();
    NetworkKey(k.0)
}
