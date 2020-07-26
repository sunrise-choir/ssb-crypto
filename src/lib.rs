//! This crate provides the cryptographic functionality needed to implement
//! the Secure Scuttlebutt networking protocols and content signing and encryption.
//!
//! There are two implementations of the crypto operations available; one that uses
//! [libsodium] C library (via the [sodiumoxide] crate), and a pure-rust implementation
//! that uses [dalek] and [RustCrypto] crates (which is the default). You can select which
//! implementation to use via Cargo.toml feature flags (see below).
//!
//! # Features
//!
//! If you only need the struct definitions and basic operations,
//! disable default features, and (optionally) enable b64.
//!
//! ```toml
//! [dependencies.ssb-crypto]
//! version = "0.2"
//! default_features = false
//! features = ["b64"]
//! ```
//!
//! ### `dalek`
//! On by default. Use the dalek/RustCrypto implementation of the crypto operations.
//! The crypto functionality is exposed via convenient methods, eg [`Keypair::sign`] and
//! [`PublicKey::verify`]. If neither `dalek` nor `sodium` features are enabled,
//! these methods won't be available.
//!
//! ### `b64`
//! On by default. Enable `from_base64` functions for [`Keypair`], [`PublicKey`], [`Signature`], and [`Hash`].
//!
//! ### `sodium`
//! Use the libsodium/sodiumoxide implementation of the crypto operations.
//! If the `sodium` and `dalek` features are both enabled, struct methods (eg. [`Keypair::sign`])
//! will use the dalek implementation. Note that this can happen if multiple dependencies
//! use ssb-crypto, some preferring `sodium`, and others preferring `dalek`.
//! To force the methods to use the sodium implementation, enable the `force_sodium` feature.
//!
//! ```toml
//! [dependencies.ssb-crypto]
//! version = "0.2"
//! default_features = false
//! features = ["sodium", "b64"]
//! ```
//!
//! ### `sodium_module`
//! Enable the `sodium` module, which contains standalone functions
//! for all the crypto operations, implemented using libsodium/sodiumoxide.
//! This is mostly useful for testing; eg. `cargo test --features sodium_module`
//! will test the dalek and sodium implementations for compatibility.
//! Note that the sodium and dalek modules are hidden from the docs; you'll have
//! to look at the code if you want to use them directly.
//!
//! [libsodium]: https://libsodium.gitbook.io
//! [sodiumoxide]: https://crates.io/crates/sodiumoxide
//! [RustCrypto]: https://github.com/RustCrypto/
//! [dalek]: https://dalek.rs
//! [`Keypair::sign`]: ./struct.Keypair.html#method.sign
//! [`PublicKey::verify`]: ./struct.PublicKey.html#method.verify
#![no_std]
#![warn(missing_docs)]

#[cfg(test)]
#[macro_use]
extern crate std;
extern crate zerocopy;
extern crate zeroize;

#[cfg(feature = "b64")]
mod b64;

#[cfg(feature = "dalek_module")]
#[doc(hidden)]
pub mod dalek;
#[cfg(feature = "sodium_module")]
#[doc(hidden)]
pub mod sodium;

mod hash;
pub use hash::*;

mod auth;
pub use auth::*;

mod sign;
pub use sign::*;

pub mod ephemeral;
pub mod secretbox;
pub mod utils;

#[cfg(test)]
mod tests {
    use crate::{ephemeral::*, Keypair, PublicKey};

    #[test]
    fn shared_secret_with_zero() {
        let (c_eph_pk, _) = generate_ephemeral_keypair();
        let c_keys = Keypair::generate();

        let (_, s_eph_sk) = generate_ephemeral_keypair();
        let s_keys = Keypair::generate();

        assert!(derive_shared_secret(&s_eph_sk, &c_eph_pk).is_some());
        // let zero_eph_pk = EphPublicKey([0; EphPublicKey::SIZE]);
        // assert!(derive_shared_secret(&s_eph_sk, &zero_eph_pk).is_none());

        assert!(derive_shared_secret_pk(&s_eph_sk, &c_keys.public).is_some());
        let zero_pk = PublicKey([0; PublicKey::SIZE]);
        assert!(derive_shared_secret_pk(&s_eph_sk, &zero_pk).is_none());

        assert!(derive_shared_secret_sk(&s_keys.secret, &c_eph_pk).is_some());
        // assert!(derive_shared_secret_sk(&s_keys.secret, &zero_eph_pk).is_none());
    }
}

#[cfg(all(
    test,
    any(feature = "sodium", feature = "dalek"),
    all(feature = "dalek_module", feature = "sodium_module")
))]
mod dalek_vs_sodium {
    #[cfg(feature = "sodium")]
    use crate::dalek as other;
    #[cfg(feature = "dalek")]
    use crate::sodium as other;

    use crate::dalek;
    use crate::sodium;
    use crate::Keypair;

    #[test]
    fn auth() {
        use crate::{ephemeral::*, NetworkKey};

        let (pk, _sk) = generate_ephemeral_keypair();
        let netkey = NetworkKey::SSB_MAIN_NET;
        let auth = netkey.authenticate(&pk.0);
        let auth2 = other::auth::authenticate(&netkey, &pk.0);
        assert_eq!(auth.0, auth2.0);

        assert!(netkey.verify(&auth, &pk.0));
        assert!(other::auth::verify(&netkey, &auth, &pk.0));
    }

    #[test]
    fn auth_test_vecs() {
        use crate::NetworkKey;
        use hmac::{Hmac, Mac, NewMac};
        use sha2::Sha512;

        let key = NetworkKey([
            74, 101, 102, 101, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0,
        ]);
        let c = [
            0x77, 0x68, 0x61, 0x74, 0x20, 0x64, 0x6f, 0x20, 0x79, 0x61, 0x20, 0x77, 0x61, 0x6e,
            0x74, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x6e, 0x6f, 0x74, 0x68, 0x69, 0x6e, 0x67, 0x3f,
        ];

        let a_expected = [
            0x16, 0x4b, 0x7a, 0x7b, 0xfc, 0xf8, 0x19, 0xe2, 0xe3, 0x95, 0xfb, 0xe7, 0x3b, 0x56,
            0xe0, 0xa3, 0x87, 0xbd, 0x64, 0x22, 0x2e, 0x83, 0x1f, 0xd6, 0x10, 0x27, 0x0c, 0xd7,
            0xea, 0x25, 0x05, 0x54,
        ];
        let a1 = sodium::auth::authenticate(&key, &c);
        assert_eq!(a1.0, a_expected);

        let mut mac = Hmac::<Sha512>::new_varkey(&key.0).unwrap();
        mac.update(&c);
        assert_eq!(mac.finalize().into_bytes().as_ref()[..32], a_expected);

        let a2 = dalek::auth::authenticate(&key, &c);
        assert_eq!(a2.0, a_expected);
    }
    #[test]
    fn hash() {
        let m = "hello this is a message".as_bytes();
        assert_eq!(crate::hash::hash(m), other::hash::hash(m));
    }

    #[test]
    fn sign() {
        let m = "hello this is a message".as_bytes();
        let kp = Keypair::generate();
        let sig1 = kp.sign(m);
        let sig2 = other::sign::sign(&kp, m);

        assert_eq!(sig1, sig2);
        assert!(kp.public.verify(&sig1, m));
        assert!(other::sign::verify(&kp.public, &sig1, m));
    }

    #[test]
    fn sign_test_vecs() {
        use hex::decode;

        let vecs = [("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
		     "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
		     "",
		     "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
		    ("833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42",
		     "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
		     "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
		     "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b58909351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704")];

        for (sk, pk, msg, sig) in &vecs {
            let sk = decode(sk).unwrap();
            let pk = decode(pk).unwrap();
            let msg = decode(msg).unwrap();
            let sig = decode(sig).unwrap();

            let s_k = sodium::sign::keypair_from_seed(&sk).unwrap();
            let d_k = dalek::sign::keypair_from_seed(&sk).unwrap();

            assert_eq!(s_k.public, d_k.public);
            assert_eq!(&s_k.public.0, &pk[..]);
            assert_eq!(s_k.secret.0, d_k.secret.0);

            let sig1 = s_k.sign(&msg);
            let sig2 = d_k.sign(&msg);
            dbg!(sig1);
            dbg!(sig2);
            assert_eq!(sig1, sig2);
            assert_eq!(&sig[..], &sig1.0[..]);
            assert!(s_k.public.verify(&sig1, &msg));
            assert!(d_k.public.verify(&sig1, &msg));
        }
    }

    #[test]
    fn ephemeral() {
        use dalek::ephemeral as dal;
        use sodium::ephemeral as sod;
        use x25519_dalek as x25519;

        let (xp, xs) = sod::generate_ephemeral_keypair();
        let (yp, ys) = sod::generate_ephemeral_keypair();

        let xs2 = x25519::StaticSecret::from(xs.0);
        let xp2 = x25519::PublicKey::from(&xs2);
        assert_eq!(&xp.0, xp2.as_bytes());

        let ys2 = x25519::StaticSecret::from(ys.0);
        let yp2 = x25519::PublicKey::from(&ys2);
        let yp3 = x25519::PublicKey::from(yp.0);
        assert_eq!(&yp.0, yp2.as_bytes());
        assert_eq!(&yp.0, yp3.as_bytes());

        let dh = xs2.diffie_hellman(&yp2);
        let sod_secret = sod::derive_shared_secret(&xs, &yp).unwrap();
        let dal_secret = dal::derive_shared_secret(&xs, &yp).unwrap();
        assert_eq!(&sod_secret.0, dh.as_bytes());
        assert_eq!(&dal_secret.0, dh.as_bytes());

        let dh = ys2.diffie_hellman(&xp2);
        let sod_secret = sod::derive_shared_secret(&ys, &xp).unwrap();
        let dal_secret = dal::derive_shared_secret(&ys, &xp).unwrap();
        assert_eq!(&sod_secret.0, dh.as_bytes());
        assert_eq!(&dal_secret.0, dh.as_bytes());
    }
}
