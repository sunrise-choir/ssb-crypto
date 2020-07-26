use crate::secretbox::*;
use sodiumoxide::crypto::secretbox as sb;

#[must_use]
pub fn open(k: &Key, c: &mut [u8], hmac: &Hmac, n: &Nonce) -> bool {
    sb::open_detached(c, &sb::Tag(hmac.0), &sb::Nonce(n.0), &sb::Key(k.0)).is_ok()
}

// encrypted in place
pub fn seal(k: &Key, m: &mut [u8], n: &Nonce) -> Hmac {
    let t = sb::seal_detached(m, &sb::Nonce(n.0), &sb::Key(k.0));
    Hmac(t.0)
}

pub fn generate_nonce() -> Nonce {
    let n = sb::gen_nonce();
    Nonce(n.0)
}

pub fn generate_key() -> Key {
    let k = sb::gen_key();
    Key(k.0)
}
