//! crypto util(s). Just `memzero` for now.
use core::convert::TryInto;
use zeroize::Zeroize;

/// Securely zero-out a slice of memory.
pub fn memzero(b: &mut [u8]) {
    b.zeroize()
}

pub(crate) fn as_array_32(b: &[u8]) -> [u8; 32] {
    b.try_into().unwrap()
}
