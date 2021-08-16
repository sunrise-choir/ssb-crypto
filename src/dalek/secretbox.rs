use crate::secretbox::*;

use xs::aead::{generic_array::GenericArray, AeadInPlace, NewAead};
use xs::XSalsa20Poly1305;
use xsalsa20poly1305 as xs;

#[must_use]
pub fn open(k: &Key, mut c: &mut [u8], hmac: &Hmac, n: &Nonce) -> bool {
    let key = GenericArray::from_slice(&k.0);
    let nonce = GenericArray::from_slice(&n.0);
    let tag = GenericArray::from_slice(&hmac.0);
    let cipher = XSalsa20Poly1305::new(key);

    cipher
        .decrypt_in_place_detached(nonce, &[], &mut c, tag)
        .is_ok()
}

// encrypted in place
pub fn seal(k: &Key, mut m: &mut [u8], n: &Nonce) -> Hmac {
    let key = GenericArray::from_slice(&k.0);
    let nonce = GenericArray::from_slice(&n.0);
    let cipher = XSalsa20Poly1305::new(key);

    // This only fails if the second param (associated data) isn't empty,
    // so the unwrap here is fine.
    let h = cipher
        .encrypt_in_place_detached(nonce, &[], &mut m)
        .unwrap();
    Hmac(*h.as_ref())
}
