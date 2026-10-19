# sing-snell

[Surge snell](https://kb.nssurge.com/surge-knowledge-base/release-notes/snell) implemented in Rust.

This is a Rust port of the Go library `sing-snell`, built on tokio.

## Features

* All complete features except the v5 QUIC proxy:
  * v4 client (also used for v5 servers) with HTTP / TLS obfuscation, UDP and connection reuse;
  * v5 server (accepts v4 and v5 clients) with obfuscation, UDP, connection reuse,
    salt replay detection and multi-user keys;
  * v6 client and server in `default` (shaped), `unshaped` and `unsafe-raw` modes, with UDP,
    connection reuse and multi-user keys.
* Behavior as consistent with the official implementation as possible: the record shaping,
  padding, payload growth, reply and close semantics of the Go implementation are kept,
  including its quirks.
* Zero-copy write paths (`write_buffer`, `write_vectorised`, packet batches) with buffer
  headroom, mirroring sing's extended connection interfaces.

## Usage

```toml
[dependencies]
sing-snell = { git = "https://github.com/SagerNet/sing-snell" }
```

The crate is imported as `snell`.

### Client

```rust
use std::sync::Arc;

use snell::{Conn, Context, Socksaddr, SystemDialer, v6};

let client = v6::Client::new(v6::ClientOptions {
    psk: b"your-pre-shared-key".to_vec(),
    mode: v6::Mode::Default,
    reuse: true,
    dialer: Some(Arc::new(SystemDialer)),
    server: Socksaddr::parse("203.0.113.1:6160"),
    ..Default::default()
})?;
let conn = client.dial_context(&Context::new(), Socksaddr::parse("example.com:443")).await?;
conn.write(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n").await?;
```

Without a dialer, wrap an existing connection with `dial_conn`, `dial_early_conn` or
`dial_packet_conn`. Use `snell::ConnStream` to plug a connection into tokio's
`AsyncRead` / `AsyncWrite` helpers such as `copy_bidirectional`.

### Server

```rust
use std::sync::Arc;

use snell::{Context, Socksaddr, TcpConn, v5};

let service = v5::Service::new(v5::ServiceOptions {
    psk: b"your-pre-shared-key".to_vec(),
    obfs_mode: snell::ObfsMode::None,
    handler: Arc::new(MyHandler), // implements snell::Handler
})?;
let (stream, source) = listener.accept().await?;
let conn = Arc::new(TcpConn::new(stream)?);
if let Err(err) = service.new_connection(Context::new(), conn, Socksaddr::from(source), None).await {
    let _ = snell::Conn::close(err.conn.as_ref()).await;
}
```

`examples/snell-server.rs` is a complete server that reads the official configuration format:

```sh
cargo run --release --example snell-server -- -c snell.conf
```

## Connections

[`Conn`](src/net.rs) is the counterpart of Go's `net.Conn`: every method takes `&self`, so a
connection can be read, written and closed from different tasks, and deadlines and close
interrupt pending operations. `TcpConn` provides it for tokio TCP streams (with Go's
`TCP_NODELAY` and keep-alive defaults); implement the trait to run snell over other transports.

## Tests

```sh
make test               # unit, loopback and fixture tests
make test_official      # against the official snell-server binaries (needs Docker)
make interop            # against the Go reference implementation (needs Go)
```

* `tests/loopback.rs` runs Rust clients against Rust servers.
* `tests/official.rs` is a port of the Go suite's official server tests. It runs the server from
  `SNELL_SERVER_BIN`, or the official binaries in Docker, and skips otherwise.
* `interop/` pins the Go reference implementation: `interop/suite` is the original Go client suite
  running against the Rust server, and `interop/snell-server` is a Go server for `tests/official.rs`.
* TLS obfuscation follows the Go reference, which targets the Surge 6.4.4 client. The official
  snell-server v4.1.1 and v5.0.1 reject it from the Go reference client and from this port alike
  ("Decryption failed"; HTTP obfuscation works), so that test runs only against the Go and Rust
  servers.
* `tests/fixtures` holds vectors exported from the Go reference (v6 profile derivation, salt block
  shuffling, padding generation and mixing, and record-by-record wire shapes for v4, v5 and v6),
  which the unit tests compare byte for byte. The generators are in `interop/testdata/generators`.

## Why

Surge believes that being closed-source and not proliferated can keep this protocol
covert, but this is already impossible in 2026. Considering that snell still has
advantages that other random-traffic protocols do not possess, such as multiplexing
support with complete TCP semantics and traffic-characteristic diversity, we made this
instead of reinventing the wheel.
