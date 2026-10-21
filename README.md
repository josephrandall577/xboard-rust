# xboard-snell

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
- **Panel-only operation**: all users come from Xboard; a read-only local API
  exposes health, statistics and synchronized users. SQLite caches panel users
  and pending traffic, so existing users can keep connecting during panel outages.
- **Linux deployment**: one-command installation of verified amd64/arm64 releases,
  with a dedicated systemd service account, automatic restart and boot startup.

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

Assets are named `xboard-snell-<release-tag>-<target>.<archive-type>`.
Newly built archives contain the executable, both single-node and multi-node TOML
examples, the installer, the systemd unit, this README and the license. Existing
v1.1.1 and v1.1.0 archives predate the installer and systemd packaging; the public
site supplies their installer and service unit as verified companion files. Those
binaries also predate the panel-only changes in this checkout.
Windows binaries statically link the MSVC runtime. macOS binaries are unsigned.

Download the matching archive from the public [download site](https://assets.nowhere.best/),
extract it, copy `config.example.toml` to `config.toml`, and edit the panel
settings and server PSK. On Linux/macOS:

```sh
sha256sum --check --ignore-missing SHA256SUMS
# macOS: shasum -a 256 --check --ignore-missing SHA256SUMS
./xboard-snell --check -c config.toml
./xboard-snell -c config.toml
```

On Windows, run `Get-FileHash <archive.zip> -Algorithm SHA256` and compare it
with `SHA256SUMS`, then run `.\xboard-snell.exe -c config.toml` in PowerShell.

Maintainers can use **Actions → Release binaries → Run workflow** to verify
the same build and packaging steps without publishing a Release. Manual runs
provide Actions artifacts and do not attach files to a Release. CI separately
runs node/library tests on Linux, macOS and Windows, plus bidirectional Go
interoperability on Linux.

## One-command Linux deployment

Requires Linux with systemd, root access, and an amd64 or arm64 CPU. Install
`curl`, `tar`, `coreutils` (for `sha256sum`), `useradd` and `getent` if
missing. On Debian/Ubuntu these are provided by `curl tar coreutils passwd libc-bin`.

~~~sh
curl -fsSL https://assets.nowhere.best/install.sh -o install.sh
sudo bash install.sh
~~~

On first install, enter the panel URL, node token and node ID when prompted.
The script generates a random server PSK, downloads the latest stable binary
for this CPU from the public download site, verifies the archive and companion
systemd unit against `SHA256SUMS`, validates the configuration, and starts the
service with boot startup enabled. No GitHub login or token is needed on the
node. To choose a release, add `--version <tag>`. A mirror can be selected with
`--download-url https://your-download-site.example.com`.

For unattended deployment, pass panel credentials through the environment:

~~~sh
sudo env PANEL_URL=https://panel.example.com PANEL_TOKEN='your-panel-token' NODE_ID=1 \
  bash install.sh --listen 0.0.0.0:6160
~~~

Set `SNELL_PSK` to use an existing server PSK. `--api-version 1` selects the
legacy panel API. Run `bash install.sh --help` for all options. The generated
configuration disables the local admin API; enable it with a token if needed.
Read the server PSK from `[node].psk` in the installed config and configure the
matching Snell client server address and port. Allow that listening TCP port in
the host/provider firewall.

| Item | Location |
| --- | --- |
| Executable | `/usr/local/bin/xboard-snell` |
| Configuration (root and service group only) | `/etc/xboard-snell/config.toml` |
| SQLite databases and service working directory | `/var/lib/xboard-snell/` |
| systemd unit | `/etc/systemd/system/xboard-snell.service` |
| Logs | `journalctl -u xboard-snell` |

~~~sh
sudo systemctl status xboard-snell --no-pager
sudo journalctl -u xboard-snell -f
# After editing /etc/xboard-snell/config.toml:
sudo systemctl restart xboard-snell
# Stop and disable boot startup:
sudo systemctl disable --now xboard-snell
~~~

Run the installer again to upgrade. It preserves the installed configuration and
SQLite files, validates the new binary against the existing config, then replaces
the executable and restarts the service. Panel settings passed on later runs do
not overwrite an existing config. The installer does not install Rust or build
on the server.

For multi-node deployment or an existing configuration, prepare a panel TOML
locally and use `sudo bash install.sh --config /path/to/config.toml` on first
install. Relative storage paths resolve under `/var/lib/xboard-snell`; absolute
storage paths must also be under this directory for the supplied service's write
permissions. Multi-node listening IPs must already be assigned to the host.

## Public download site on Cloudflare Pages

The private source repository builds releases in GitHub Actions. Only the
verified binary archives, install script, service unit, public release notes and
version metadata are copied into the download site. The site builder checks
all six platforms and archive SHA256 values before writing its output, and
rejects assets over Cloudflare Pages' 25 MiB single-file limit. Source files and
GitHub credentials are not included in the site. A binary can still contain
embedded build paths or other compiler metadata.

| Public endpoint | Purpose |
| --- | --- |
| `https://assets.nowhere.best/` | Download page |
| `https://assets.nowhere.best/install.sh` | Linux installer |
| `https://assets.nowhere.best/version.json` | Latest stable version and all platform URLs, SHA256 values and sizes |
| `https://assets.nowhere.best/latest.txt` | Stable release tag used by the dependency-light installer |
| `/xboard-snell/releases/<tag>/version.json` | Version details for a retained release |
| `/xboard-snell/releases/<tag>/SHA256SUMS` | Archive, service and installer checksums |

The manifest uses `schemaVersion: 1`. Top-level `url`, `sha256` and `size`
refer to Linux x64. `linux`, `macos` and `win` each provide `version`,
`x64` and `arm64`. Every architecture entry has `url`, `sha256` and
`size` (bytes). `installer` and `service` describe the companion files;
`notes` contains the release notes, `stable` repeats the selected stable
release, and `versions` lists retained version manifests. The site currently
publishes stable releases only, so the latest and stable version are identical.
Checksums detect corruption; no signing key or signature is claimed.

The default retention is five stable releases. Older download URLs stop working
when those releases leave the retained set. Publishing a stable Release triggers
the site workflow after all binaries are attached. The workflow summary includes
public installer, metadata and all six platform download links. A missing
Cloudflare credential fails publication with an explicit configuration error.
Prereleases and ordinary source pushes do not update the public stable download. Maintainers can also run
**Actions → Publish download site → Run workflow** with a specific stable tag.

Initial setup in the private GitHub repository:

1. Create a Direct Upload Pages project with production branch `main` and
   associate the public domain. This deployment uses `nowhere-assets`.
2. Set repository Actions variables `CLOUDFLARE_PAGES_PROJECT` and
   `CLOUDFLARE_ACCOUNT_ID` to the actual project and account. Optionally set
   `PUBLIC_DOWNLOAD_URL`; its default is `https://assets.nowhere.best`.
3. Add Actions secret `CLOUDFLARE_API_TOKEN` with the Cloudflare permission
   **Account → Cloudflare Pages → Edit**, restricted to the publishing account.
4. Commit/push these workflows, then run **Publish download site**. Cloudflare
   MCP authentication is separate from Wrangler/CI authentication; the MCP
   connection does not automatically create this GitHub secret.

To build locally using an authenticated GitHub CLI and publish with an
authenticated Wrangler CLI:

~~~sh
python3 scripts/build_download_site.py --repository josephrandall577/xboard-snell --output public
npx wrangler@4.151.3 pages deploy public --project-name nowhere-assets --branch main
~~~

The `public` output directory must not already exist. The Pages project uses
Direct Upload rather than letting Cloudflare build the private source checkout.
See [Cloudflare Direct Upload](https://developers.cloudflare.com/pages/get-started/direct-upload/)
and [CI credentials](https://developers.cloudflare.com/pages/how-to/use-direct-upload-with-continuous-integration/).

## Manual systemd installation

The release archive includes `systemd/xboard-snell.service`. To install without
the download script, extract the matching verified release and run these commands
from its directory (create the service account only if it does not exist):

~~~sh
sudo useradd --system --user-group --home-dir /var/lib/xboard-snell --no-create-home --shell /usr/sbin/nologin xboard-snell
sudo install -d -m 0750 -o root -g xboard-snell /etc/xboard-snell
sudo install -d -m 0750 -o xboard-snell -g xboard-snell /var/lib/xboard-snell
sudo install -m 0755 xboard-snell /usr/local/bin/xboard-snell
sudo install -m 0640 -o root -g xboard-snell config.example.toml /etc/xboard-snell/config.toml
# Edit PSK and panel settings before enabling the service:
sudoedit /etc/xboard-snell/config.toml
sudo install -m 0644 systemd/xboard-snell.service /etc/systemd/system/xboard-snell.service
sudo systemctl daemon-reload
sudo systemctl enable --now xboard-snell
~~~

The service runs as `xboard-snell`, persists state across restarts, writes logs
to journald and restarts after failures. It can listen on privileged ports without
running as root. SIGTERM initiates the node's normal shutdown and final traffic
persistence/reporting; the unit allows up to 300 seconds for this. The admin API
health endpoint, if enabled, reports process liveness rather than panel readiness.

## Multiple panel nodes

One process can run several independent panel-backed nodes. Define each node in
[[nodes]] with a unique name and a distinct, specific local IP address (not a
wildcard). IPv4-mapped IPv6 listen addresses are rejected; use native IPv4
or IPv6 addresses. Each node also needs its own listening port, PSK, panel node ID and
unique management API listen address. TCP and UDP destination sockets bind to
the same local IP as the corresponding Snell listener. If the requested
address family or local bind is unavailable, the connection fails rather than
leaving through another node's IP. Users, traffic accounting, SQLite files,
rate limits, device limits, panel credentials and management tokens are
independent per node. Shared quota and log settings remain at the top level.

Start from config.multi-node.example.toml; do not combine [[nodes]] with the
legacy [node] / [panel] configuration. Distinct IPs must already be assigned
to this host. Management API endpoints are configured per node. Overlapping
management and Snell endpoints are rejected, and an occupied management port
fails startup. When upgrading
an installation whose config omits [storage], an existing snell-xboard-node.db
is reused if xboard-snell.db does not yet exist; explicit storage paths are
left unchanged.

## Build

```sh
cargo build --release
```

## Run

```sh
cp config.example.toml config.toml
# edit psk / panel settings
./target/release/xboard-snell -c config.toml
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

## Upgrading from standalone mode

Standalone operation has been removed. Single-node configurations require a
valid `[panel]` block; every `[[nodes]]` entry requires its own panel settings.
Remove all `[[node.users]]` tables: these now fail validation rather than being
silently ignored. User creation, updates, removal, blocking and quota changes
must be performed in Xboard. The local API no longer accepts write requests.
Existing SQLite traffic and pending reports are preserved; cached users are
replaced by the next successful full panel sync. On a fresh database no clients
can authenticate until the first successful panel user sync.

## Admin API

`[admin].listen` (default `127.0.0.1:6161`). If `[admin].token` is set, send
`Authorization: Bearer <token>`.

| Method | Path | Description |
| --- | --- | --- |
| GET | `/health` | Liveness |
| GET | `/api/v1/stats` | Uptime, connections, device/quota reject counters, aggregate traffic, per-user online counts |
| GET | `/api/v1/users` | Users with live usage, remaining quota, devices, block state |
| GET | `/api/v1/users/{id}` | One user |
The API is read-only. Manage users and traffic allowances in Xboard; updates
arrive through polling or supported WebSocket pushes. User sync runs immediately
after the startup handshake, then at the configured pull interval.

## Semantics

- **Upload** is bytes read from the client toward the destination,
  **download** is bytes written back to the client.
- **Device count** is the number of distinct source IPs seen within
  `limits.device_ttl` seconds.
- **Speed limit** is per user, in Mbps, shared by all of the user's
  connections.
- Local traffic totals and pending panel reports are saved together in SQLite.
  Failed reports remain queued across restarts; the next report retries them.
  Shutdown stops TCP/UDP relays before persisting and reporting the final bytes.
- Reports use at-least-once delivery. If the panel accepts a report but its
  response is lost, retrying can count those bytes twice; the panel API has no
  idempotency key to resolve that ambiguity.

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
# Linux/macOS installer smoke tests (isolated; no system services are changed):
cargo build --locked
python3 scripts/test_install.py
python3 scripts/test_download_site.py
```

`tests/e2e.rs` drives a real Snell v6 client through the node and checks
per-user metering, rejection of unknown/expired/over-quota users, device
limits and persistence. `tests/panel.rs` pins the panel request and response
shapes against a mock Xboard. Installer tests cover verified downloads, both Linux
CPU architectures, generated config, upgrade data preservation and failure paths.
Linux CI also runs ShellCheck and validates the systemd unit.

## Limitations

- UDP is relayed per association socket; source-port-preserving or
  per-destination socket pools are not implemented.
- The panel `sync.user.delta` WebSocket event is intentionally left to the
  poll loop; only full `sync.users` pushes apply immediately.
- Route rules, custom outbounds and certificates from the panel's node config
  are not consumed: a Snell node has no kernel-side routing to program.
