.PHONY: fmt lint test test_official xboard_node_test xboard_node_lint interop interop_go_suite interop_rust_client

SNELL_SERVER_RUST = target/release/examples/snell-server
SNELL_SERVER_GO = target/interop/go-snell-server

XBOARD_NODE = xboard-node

fmt:
	cargo fmt
	cd $(XBOARD_NODE) && cargo fmt
	cd interop && gofmt -w .

lint: xboard_node_lint
	cargo fmt --check
	cargo clippy --all-targets -- -D warnings
	cd interop && go vet ./...

xboard_node_lint:
	cd $(XBOARD_NODE) && cargo fmt --check
	cd $(XBOARD_NODE) && cargo clippy --all-targets -- -D warnings

test: xboard_node_test
	cargo test

xboard_node_test:
	cd $(XBOARD_NODE) && cargo test

# Runs tests/official.rs against the official snell-server binaries in Docker.
test_official:
	cargo test --test official -- --test-threads=1

$(SNELL_SERVER_RUST):
	cargo build --release --example snell-server

$(SNELL_SERVER_GO):
	cd interop && go build -o ../$(SNELL_SERVER_GO) ./snell-server

# The original Go client suite against the Rust server.
interop_go_suite: $(SNELL_SERVER_RUST)
	cd interop && SNELL_SERVER_BIN=$(abspath $(SNELL_SERVER_RUST)) go test -count=1 -timeout 15m ./...

# The Rust client suite (tests/official.rs) against the Go reference server.
interop_rust_client: $(SNELL_SERVER_GO)
	SNELL_SERVER_BIN=$(abspath $(SNELL_SERVER_GO)) cargo test --test official

interop: interop_go_suite interop_rust_client
