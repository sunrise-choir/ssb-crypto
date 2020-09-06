use crate::utils::as_array_32;
use crate::{NetworkAuth, NetworkKey};

use hmac::{Hmac, Mac, NewMac};
use sha2::Sha512;
use subtle::ConstantTimeEq;

// Note that libsodium's HMAC-SHA-512-256 is Hmac<Sha512>,
// with the output truncated to 256 bits, which is not the same as
// Hmac<Sha512Trunc256>.
pub fn authenticate(k: &NetworkKey, m: &[u8]) -> NetworkAuth {
    let mut mac = Hmac::<Sha512>::new_varkey(&k.0).unwrap(); // infallible
    mac.update(m);
    NetworkAuth(as_array_32(&mac.finalize().into_bytes()[..32]))
}

pub fn verify(k: &NetworkKey, a: &NetworkAuth, m: &[u8]) -> bool {
    let mut mac = Hmac::<Sha512>::new_varkey(&k.0).unwrap(); // infallible
    mac.update(m);
    let choice = mac.finalize().into_bytes()[..32].ct_eq(&a.0);
    choice.unwrap_u8() == 1
}
