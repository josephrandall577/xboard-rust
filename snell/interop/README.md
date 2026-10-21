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

* `suite/multi_psk_test.go` exercises the XBoard node with independent Go v6
  clients on a single port, including empty client IDs, a forged client ID,
  TCP/UDP payloads and exact per-PSK traffic reports to a local mock panel.
  From this directory, after building the root node:

  ```sh
  XBOARD_SNELL_BIN=$PWD/../../target/debug/xboard-snell go test ./suite -run TestV6MultiPskNode
  ```

  CI sets this alongside `SNELL_SERVER_BIN`; without it the node test is skipped.
