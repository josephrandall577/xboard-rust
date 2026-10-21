# Vendored source

Direct source: https://github.com/josephrandall577/snell-in-rust

Aligned to `55002dca55eea45b2774e19e0d8d05d1c590398c` (v1.1.2).

The Rust implementation originates from SagerNet/sing-snell (Go). This tree
retains local fixes for non-UTF-8 host bytes and scoped IPv6 addresses, their
tests, and the corresponding example resolver and documentation changes.

The v6 multi-PSK service is a local extension for XBoard: default-mode salt-block
fingerprints select a credential, and AEAD verification establishes identity.
Existing single-PSK and client-ID library services remain available for interop.
