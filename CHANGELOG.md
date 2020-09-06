# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2020-09-02
### Added
- Dalek/RustCrypto implementation of crypto operations, in addition to sodiumoxide
- from_base64 functions for `Keypair`, `PublicKey`, `Signature`, and `Hash`
- cargo feature flags to control functionality (dalek vs sodium, base64 decoding)
- no_std support

### Changed
- Revamped API
- Crypto operations now default to the new Dalek/RustCrypto implementation
