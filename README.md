# ssb-crypto

This currently just re-exports the parts of the `sodiumoxide` crate that
are needed by SSB, and defines a couple custom structs.

Some of the exposed types (eg. PublicKey, SecretKey) should ultimately
be wrapped in a higher-level abstraction, like `ssb-multiformats`.
