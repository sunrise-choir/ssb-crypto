use rand::{rngs::OsRng, RngCore};

pub fn random_bytes(mut b: &mut [u8]) {
    let mut rng = OsRng {};
    rng.fill_bytes(&mut b);
}
