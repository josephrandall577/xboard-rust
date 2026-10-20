# snell-xboard-node

An Xboard-compatible Snell v6 landing server built on the vendored
[`snell`](snell/) crate (the Rust port of sing-snell).

The node speaks the Snell v6 wire protocol (per-user keys, `default`,
`unshaped` and `unsafe-raw` modes) and implements the Xboard node backend
contract: user sync, traffic accounting, device limits, speed limits,
quota enforcement, alive-IP reporting and node status/metrics.

## Features

- **Snell v6**, including per-user keys: the Xboard user `uuid` is the Snell
  user key, so one listener serves every user with independent credentials.
- **Traffic accounting** per user and direction, reported to the panel as
  `{uid: [upload, download]}` deltas and persisted locally.
- **Device limits** by distinct source IP, with a configurable TTL.
- **Speed limits** (Mbps) enforced with a shared per-user token bucket, so
  all connections of one user share the same budget.
- **Quotas**: users at or above `transfer_enable` are refused.
- **Expiry and enable/disable** flags, identical to the panel's fields.
- **Xboard panel integration**: V2 (`/api/v2/server/*`, handshake + merged
  report) and legacy V1 (`/api/v1/server/UniProxy/*`), polling plus optional
  WebSocket push (`sync.users`).
- **Local admin API** and SQLite persistence, so the node works standalone
  and the data plane never depends on the panel being up.

## Download binaries

Publish a GitHub Release to start the **Release binaries** workflow. It builds
from that Release's tag and attaches the archives and a combined `SHA256SUMS`
file to the same Release after all six platforms finish successfully. Draft
Releases do not start builds; publishing a regular Release or a prerelease does.
A Git tag push alone does not publish binaries.

| Platform | Architecture | Target / asset suffix |
| --- | --- | --- |
| Linux | x86_64 | `x86_64-unknown-linux-musl.tar.gz` |
| Linux | ARM64 | `aarch64-unknown-linux-musl.tar.gz` |
| macOS | Intel | `x86_64-apple-darwin.tar.gz` |
| macOS | Apple Silicon | `aarch64-apple-darwin.tar.gz` |
| Windows | x86_64 | `x86_64-pc-windows-msvc.zip` |
| Windows | ARM64 | `aarch64-pc-windows-msvc.zip` |

Assets are named `snell-xboard-node-<release-tag>-<target>.<archive-type>`.
Each archive contains the executable, `config.example.toml`, this README and
the license. Linux binaries use static musl and bundled SQLite; Windows
binaries statically link the MSVC runtime. macOS binaries are unsigned.

Download the matching archive from [Releases](https://github.com/josephrandall577/xboard-snell/releases),
extract it, copy `config.example.toml` to `config.toml`, and edit the panel
settings and server PSK. On Linux/macOS:

```sh
sha256sum --check --ignore-missing SHA256SUMS
# macOS: shasum -a 256 --check --ignore-missing SHA256SUMS
./snell-xboard-node --check -c config.toml
./snell-xboard-node -c config.toml
```

On Windows, run `Get-FileHash <archive.zip> -Algorithm SHA256` and compare it
with `SHA256SUMS`, then run `.\snell-xboard-node.exe -c config.toml` in PowerShell.

Maintainers can use **Actions → Release binaries → Run workflow** to verify
the same build and packaging steps without publishing a Release. Manual runs
provide Actions artifacts and do not attach files to a Release. CI separately
runs node/library tests on Linux, macOS and Windows, plus bidirectional Go
interoperability on Linux.

## Build

```sh
cargo build --release
```

## Run

```sh
cp config.example.toml config.toml
# edit psk / panel settings
./target/release/snell-xboard-node -c config.toml
```

`--check` validates the configuration and exits.

## Xboard setup

1. Add a node in Xboard. The backend only needs a token and node id.
2. Start the node with the matching `[panel]` block.
3. Point each user's Snell client at `listen` with the server `psk` and the
   user's `uuid` as the Snell user key.

With `api_version = 2` the node calls `POST /api/v2/server/handshake`,
`GET /api/v2/server/config`, `GET /api/v2/server/user` and
`POST /api/v2/server/report`. With `api_version = 1` it uses the legacy
`/api/v1/server/UniProxy/{config,user,push,alive,status}` endpoints.

## Standalone setup

Leave out the `[panel]` table, declare users under `[[node.users]]` or create
them through the admin API. Traffic counters live in the SQLite file from
`[storage]`.

## Admin API

`[admin].listen` (default `127.0.0.1:6161`). If `[admin].token` is set, send
`Authorization: Bearer <token>`.

| Method | Path | Description |
| --- | --- | --- |
| GET | `/health` | Liveness |
| GET | `/api/v1/stats` | Uptime, connections, device/quota reject counters, aggregate traffic, per-user online counts |
| GET | `/api/v1/users` | Users with live usage, remaining quota, devices, block state |
| GET | `/api/v1/users/{id}` | One user |
| POST | `/api/v1/users` | Create a user (same fields as `[[node.users]]`) |
| PUT | `/api/v1/users/{id}` | Update a user |
| DELETE | `/api/v1/users/{id}` | Delete a user |
| POST | `/api/v1/users/{id}/traffic` | Reset a user's traffic counters |
| POST | `/api/v1/traffic/reset` | Reset all traffic counters |
| PUT | `/api/v1/users/{id}/block` | Block a user at the authorization gate |
| PUT | `/api/v1/users/{id}/unblock` | Unblock a user |

User writes are applied to the live listener immediately; connections that
already exist keep running.

## Semantics

- **Upload** is bytes read from the client toward the destination,
  **download** is bytes written back to the client.
- **Device count** is the number of distinct source IPs seen within
  `limits.device_ttl` seconds.
- **Speed limit** is per user, in Mbps, shared by all of the user's
  connections.
- A failed panel report leaves the traffic pending; the next report retries
  it, so bytes are not lost during panel outages.

## Layout

| File | Purpose |
| --- | --- |
| `src/server.rs` | Snell v6 listener and user map |
| `src/relay.rs` | TCP/UDP relay, authorization gate, metering |
| `src/accounting.rs` | Per-user counters, devices, token buckets |
| `src/store.rs` | SQLite persistence |
| `src/panel.rs` | Xboard V1/V2 client |
| `src/ws.rs` | Panel WebSocket push |
| `src/admin.rs` | Admin API |
| `src/node.rs` | Startup, sync and report loops, shutdown |

## Tests

```sh
cargo test             # unit, end-to-end v6 and panel contract tests
cargo clippy --all-targets -- -D warnings
```

`tests/e2e.rs` drives a real Snell v6 client through the node and checks
per-user metering, rejection of unknown/expired/over-quota users, device
limits and persistence. `tests/panel.rs` pins the panel request and response
shapes against a mock Xboard.

## Limitations

- UDP is relayed per association socket; source-port-preserving or
  per-destination socket pools are not implemented.
- The panel `sync.user.delta` WebSocket event is intentionally left to the
  poll loop; only full `sync.users` pushes apply immediately.
- Route rules, custom outbounds and certificates from the panel's node config
  are not consumed: a Snell node has no kernel-side routing to program.
