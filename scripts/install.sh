#!/usr/bin/env bash
# Install a verified public download and configure its systemd service.
set -euo pipefail

DEFAULT_DOWNLOAD_URL="https://assets.nowhere.best"
DOWNLOAD_URL="${XBOARD_SNELL_DOWNLOAD_URL:-$DEFAULT_DOWNLOAD_URL}"
VERSION="${XBOARD_SNELL_VERSION:-latest}"
PANEL_URL="${PANEL_URL:-}"
PANEL_TOKEN="${PANEL_TOKEN:-}"
NODE_ID="${NODE_ID:-}"
SNELL_PSK="${SNELL_PSK:-}"
SNELL_LISTEN="${SNELL_LISTEN:-0.0.0.0:6160}"
API_VERSION="${API_VERSION:-2}"
CONFIG_FILE=/etc/xboard-snell/config.toml
BINARY_FILE=/usr/local/bin/xboard-snell
SERVICE_FILE=/etc/systemd/system/xboard-snell.service
STATE_DIR=/var/lib/xboard-snell
TEMP_DIR=

usage() {
    cat <<'EOF'
Usage: sudo bash install.sh [options]

Install the latest stable release on Linux amd64/arm64 with systemd.
On first install, missing panel settings are prompted via /dev/tty.
An existing config and database are preserved when upgrading.

  --version TAG        Release tag (default: latest stable)
  --download-url URL   Public download site (also XBOARD_SNELL_DOWNLOAD_URL)
  --panel-url URL      Xboard URL (also PANEL_URL)
  --panel-token TOKEN  Panel token (prefer PANEL_TOKEN environment variable)
  --node-id ID         Panel node ID (also NODE_ID)
  --psk KEY            Server PSK; generated if omitted (also SNELL_PSK)
  --listen IP:PORT     Snell listener (also SNELL_LISTEN; default 0.0.0.0:6160)
  --api-version 1|2    Panel API version (also API_VERSION; default 2)
  --config PATH       Copy this existing panel TOML on first install
  -h, --help          Show this help

Dependencies: bash, curl, tar, coreutils (sha256sum), systemd, useradd, getent.
EOF
}

fail() { printf 'Error: %s\n' "$*" >&2; exit 1; }
log() { printf '%s\n' "$*"; }
cleanup() { if [[ -n "$TEMP_DIR" ]]; then rm -rf -- "$TEMP_DIR"; fi; }

prompt() {
    local variable=$1 label=$2 secret=${3:-false} value
    [[ -n "${!variable}" ]] && return
    [[ -r /dev/tty && -w /dev/tty ]] || fail "Missing $variable; pass an option or environment variable."
    printf '%s: ' "$label" >/dev/tty
    if [[ "$secret" == true ]]; then
        IFS= read -rs value </dev/tty || fail "Cannot read $variable"
        printf '\n' >/dev/tty
    else
        IFS= read -r value </dev/tty || fail "Cannot read $variable"
    fi
    printf -v "$variable" '%s' "$value"
}

# Quote literal strings for TOML, including tokens containing quotes/backslashes.
toml_string() {
    local value=$1
    [[ ! "$value" =~ [[:cntrl:]] ]] || fail 'Configuration values must not contain control characters'
    value=${value//\\/\\\\}
    value=${value//\"/\\\"}
    printf '"%s"' "$value"
}

fetch() {
    curl --fail --show-error --silent --location --retry 3 \
        --connect-timeout 15 --max-time 300 --proto '=https' --proto-redir '=https' "$@"
}

main() {
    local config_source= option target archive_name archive_root base expected filename
    while (($#)); do
        option=$1
        case "$option" in
            -h|--help) usage; return ;;
            --version|--download-url|--panel-url|--panel-token|--node-id|--psk|--listen|--api-version|--config)
                (($# >= 2)) && [[ -n "$2" ]] || fail "$option requires a value"
                case "$option" in
                    --version) VERSION=$2 ;;
                    --download-url) DOWNLOAD_URL=$2 ;;
                    --panel-url) PANEL_URL=$2 ;;
                    --panel-token) PANEL_TOKEN=$2 ;;
                    --node-id) NODE_ID=$2 ;;
                    --psk) SNELL_PSK=$2 ;;
                    --listen) SNELL_LISTEN=$2 ;;
                    --api-version) API_VERSION=$2 ;;
                    --config) config_source=$2 ;;
                esac
                shift 2 ;;
            *) fail "Unknown option: $option (see --help)" ;;
        esac
    done
    [[ "$(uname -s)" == Linux ]] || fail 'Only Linux with systemd is supported'
    [[ "$(id -u)" == 0 ]] || fail 'Run this installer as root (sudo bash install.sh)'
    local command_name
    for command_name in curl tar sha256sum systemctl useradd getent install od awk mktemp; do
        command -v "$command_name" >/dev/null || fail "Missing dependency: $command_name"
    done
    systemctl show-environment >/dev/null || fail 'systemd must be running as the system service manager'
    case "$(uname -m)" in
        x86_64|amd64) target=x86_64-unknown-linux-musl ;;
        aarch64|arm64) target=aarch64-unknown-linux-musl ;;
        *) fail "Unsupported architecture: $(uname -m)" ;;
    esac
    DOWNLOAD_URL="${DOWNLOAD_URL%/}"
    [[ "$DOWNLOAD_URL" =~ ^https://[A-Za-z0-9][A-Za-z0-9.-]*(:[0-9]+)?(/[A-Za-z0-9._~/-]*)?$ ]] || fail 'Download URL must be an HTTPS URL without credentials, query or fragment'
    if [[ -n "$config_source" ]]; then
        [[ -f "$config_source" ]] || fail "Configuration file not found: $config_source"
        [[ ! -e "$CONFIG_FILE" ]] || fail '--config is only accepted on first install; edit the installed config to update it'
    fi
    umask 077
    TEMP_DIR=$(mktemp -d)
    trap cleanup EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    if [[ "$VERSION" == latest ]]; then
        fetch --output "$TEMP_DIR/latest.txt" "$DOWNLOAD_URL/latest.txt"
        VERSION=$(<"$TEMP_DIR/latest.txt")
    fi
    [[ "$VERSION" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ && "$VERSION" != latest ]] || fail 'Cannot determine a valid release tag; use --version TAG'
    archive_root="xboard-snell-$VERSION-$target"
    archive_name="$archive_root.tar.gz"
    base="$DOWNLOAD_URL/xboard-snell/releases/$VERSION"
    log "Downloading $VERSION ($target)..."
    fetch --output "$TEMP_DIR/SHA256SUMS" "$base/SHA256SUMS"
    for filename in "$archive_name" xboard-snell.service; do
        fetch --output "$TEMP_DIR/$filename" "$base/$filename"
        expected=$(awk -v name="$filename" '$2 == name { print $1 }' "$TEMP_DIR/SHA256SUMS")
        [[ "$expected" =~ ^[a-fA-F0-9]{64}$ ]] || fail "Missing or ambiguous checksum for $filename"
        (cd "$TEMP_DIR" && printf '%s  %s\n' "$expected" "$filename" | sha256sum --check --status) || fail "Release checksum verification failed: $filename"
    done
    # Older releases do not bundle a unit; the site supplies a verified sidecar.
    tar -xzf "$TEMP_DIR/$archive_name" -C "$TEMP_DIR" --no-same-owner "$archive_root/xboard-snell"
    local candidate="$TEMP_DIR/$archive_root/xboard-snell"
    local unit="$TEMP_DIR/xboard-snell.service"
    [[ -f "$candidate" && ! -L "$candidate" && -f "$unit" && ! -L "$unit" ]] || fail 'Invalid release files'
    chmod 0755 "$candidate"

    local check_config="$TEMP_DIR/config.toml"
    if [[ -f "$CONFIG_FILE" ]]; then
        log "Preserving $CONFIG_FILE and existing databases."
        check_config=$CONFIG_FILE
    elif [[ -n "$config_source" ]]; then
        install -m 0600 "$config_source" "$check_config"
    else
        prompt PANEL_URL 'Panel URL (https://panel.example.com)'
        prompt PANEL_TOKEN 'Panel token' true
        prompt NODE_ID 'Panel node ID'
        [[ "$NODE_ID" =~ ^[1-9][0-9]*$ ]] || fail 'Node ID must be a positive integer'
        [[ "$API_VERSION" == 1 || "$API_VERSION" == 2 ]] || fail 'API version must be 1 or 2'
        [[ "$PANEL_URL" == https://* || "$PANEL_URL" == http://* ]] || fail 'Panel URL must use HTTP(S)'
        [[ -n "$PANEL_TOKEN" ]] || fail 'Panel token cannot be empty'
        if [[ -z "$SNELL_PSK" ]]; then
            SNELL_PSK=$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')
        fi
        # The generated admin API is disabled; enable the read-only API manually if needed.
        {
            printf '[node]\nlisten = '; toml_string "$SNELL_LISTEN"
            printf '\npsk = '; toml_string "$SNELL_PSK"
            printf '\nmode = "default"\n\n[panel]\nurl = '; toml_string "$PANEL_URL"
            printf '\ntoken = '; toml_string "$PANEL_TOKEN"
            printf '\nnode_id = %s\napi_version = %s\npull_interval = 60\npush_interval = 60\n' "$NODE_ID" "$API_VERSION"
            printf '\n[admin]\ndisabled = true\n\n[storage]\npath = "/var/lib/xboard-snell/xboard-snell.db"\n\n[log]\nlevel = "info"\n'
        } >"$check_config"
    fi
    # Validate before touching a running installation. Relative storage paths are
    # resolved in the same working directory as the service (including legacy DBs).
    if [[ -d "$STATE_DIR" ]]; then
        (cd "$STATE_DIR" && "$candidate" --check -c "$check_config")
    else
        "$candidate" --check -c "$check_config"
    fi

    if ! getent passwd xboard-snell >/dev/null; then
        local nologin=/usr/sbin/nologin
        [[ -x "$nologin" ]] || nologin=/sbin/nologin
        useradd --system --user-group --home-dir "$STATE_DIR" --no-create-home --shell "$nologin" xboard-snell
    fi
    install -d -m 0750 -o root -g xboard-snell "$(dirname "$CONFIG_FILE")"
    install -d -m 0750 -o xboard-snell -g xboard-snell "$STATE_DIR"
    install -d -m 0755 "$(dirname "$BINARY_FILE")" "$(dirname "$SERVICE_FILE")"
    if [[ ! -e "$CONFIG_FILE" ]]; then
        install -m 0640 -o root -g xboard-snell "$check_config" "$CONFIG_FILE"
    fi
    # Stage beside the executable and rename atomically, avoiding ETXTBSY on upgrade.
    install -m 0755 -o root -g root "$candidate" "$BINARY_FILE.new"
    mv -f -- "$BINARY_FILE.new" "$BINARY_FILE"
    install -m 0644 -o root -g root "$unit" "$SERVICE_FILE"
    systemctl daemon-reload
    systemctl enable xboard-snell.service
    systemctl restart xboard-snell.service
    # Allow immediate configuration/permission errors to surface before success.
    sleep 2
    systemctl is-active --quiet xboard-snell.service || fail 'Service failed to start; run journalctl -u xboard-snell -n 100 --no-pager'
    log "Installed $VERSION. Config: $CONFIG_FILE"
    log 'Service: systemctl status xboard-snell --no-pager'
    log 'Logs: journalctl -u xboard-snell -f'
    log 'Server PSK is stored in [node].psk in the config file.'
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
