# Interop with the Go reference

This module pins the Go implementation this crate was ported from
(`github.com/sagernet/sing-snell` at `bc5a12ac736f`).

* `suite/` is the original Go test suite. Its official-server tests start the server from
  `SNELL_SERVER_BIN` instead of the official binaries in Docker, so they exercise the Go clients
  against the Rust server:

  ```sh
  cargo build --release --example snell-server
  SNELL_SERVER_BIN=$PWD/../target/release/examples/snell-server go test ./...
  ```

  `tls_server_test.go` adds TLS obfuscation coverage that the original suite only had in loopback.

* `snell-server/` is a server built on the Go implementation with the same command line as the
  Rust example, used to run the Rust clients in `tests/official.rs` against Go:

  ```sh
  go build -o go-snell-server ./snell-server
  SNELL_SERVER_BIN=$PWD/go-snell-server cargo test --test official
  ```

* `testdata/generators/` holds the Go tests that produced `tests/fixtures`. They use unexported
  identifiers, so copy each `snellvN_*_test.go` into the `snellvN` package of a checkout of the
  pinned revision and run, for example:

  ```sh
  VECTORS_OUT=/path/to/tests/fixtures/v6_vectors.txt go test -run TestDumpVectors ./snellv6/
  VECTORS_OUT=/path/to/tests/fixtures/v6_wire_shape.txt go test -run TestDumpWireShape ./snellv6/
  ```
