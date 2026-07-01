.PHONY: build clean do-docs do-docs-ci do-lint do-lint-ci test test-feat test-all all help check release coverage coverage-check coverage-ci coverage-setup audit docs developer node-harness build-wasi test-wasi wit-sync

# TypeScript anchor interop harnesses (wrap @keetanetwork/anchor)
HARNESS_DIR := keetanetwork-anchor-client/node-harness
HARNESS_SOURCES := $(wildcard $(HARNESS_DIR)/src/*.ts) $(HARNESS_DIR)/tsconfig.json

# WASI bindings crate and its built components (wasmtime/host-language e2e tests)
WASI_CRATE := keetanetwork-anchor-client-wasi
WASI_P2_WASM := target/wasm32-wasip2/debug/keetanetwork_anchor_client_wasi.wasm
WASI_P1_WASM := target/wasm32-wasip1/debug/keetanetwork_anchor_client_wasi.wasm

# Project name
PROJ_NAME := anchor-rs

# Build configuration
release ?=

ifdef release
	release_flag := --release
	target := release
else
	release_flag :=
	target := debug
endif

# Default target
default: build

# Build everything
all: clean build test

# Just check compilation without building
check:
	cargo check

# Build the project
build:
	cargo build $(release_flag)

# Clean build artifacts
clean:
	cargo clean
	rm -rf target/
	rm -rf build/

# Generate documentation without dependencies and open it
do-docs:
	cargo doc --no-deps --document-private-items --all-features --open

# Generate documentation without opening it (for CI)
do-docs-ci:
	cargo doc --no-deps --document-private-items --all-features

# Lint code (Rust + the TypeScript harnesses, one command)
do-lint: do-docs-ci node-harness
	cd $(HARNESS_DIR) && npm run lint
	cargo clippy --fix --allow-staged --allow-dirty
	cargo fmt

# Lint code for CI (check only, no fixes)
do-lint-ci: node-harness
	cd $(HARNESS_DIR) && npm run lint
	cargo check --all-targets --all-features
	cargo fmt --all -- --check
	cargo clippy --all-targets --all-features -- -D warnings

# Feature matrix
test-feat:
	# Per-feature unit tests (std present so the harness runs).
	cargo test -p keetanetwork-anchor --lib --no-default-features --features std
	cargo test -p keetanetwork-anchor --lib --no-default-features --features std,serde
	cargo test -p keetanetwork-anchor --lib --no-default-features --features std,chrono
	cargo test -p keetanetwork-anchor --lib --no-default-features --features std,x509
	cargo test -p keetanetwork-anchor --lib --no-default-features --features std,signing
	cargo test -p keetanetwork-anchor --lib --no-default-features --features std,serde,chrono,x509,signing
	# no_std compile checks (test harness needs std, so check only).
	cargo check -p keetanetwork-anchor --no-default-features
	cargo check -p keetanetwork-anchor --no-default-features --features alloc
	cargo check -p keetanetwork-anchor --no-default-features --features alloc,serde
	cargo check -p keetanetwork-anchor --no-default-features --features alloc,chrono
	cargo check -p keetanetwork-anchor --no-default-features --features serde
	cargo check -p keetanetwork-anchor --no-default-features --features chrono
	cargo check -p keetanetwork-anchor --no-default-features --features x509
	cargo check -p keetanetwork-anchor --no-default-features --features signing
	# Client: pure decode/resolver/service path is no_std; transport is http/std.
	cargo check -p keetanetwork-anchor-client --no-default-features
	cargo check -p keetanetwork-anchor-client --no-default-features --features codec
	cargo check -p keetanetwork-anchor-client --no-default-features --features service
	cargo check -p keetanetwork-anchor-client --no-default-features --features kyc
	cargo check -p keetanetwork-anchor-client --no-default-features --features http
	cargo check -p keetanetwork-anchor-client --no-default-features --features kyc,http
	# Resilience: pure cores are no_std; backends/decorator ride the runtimes.
	cargo check -p keetanetwork-anchor-client --no-default-features --features resilience
	cargo check -p keetanetwork-anchor-client --features resilience
	# Cross-target: browser (WasmRuntime + fetch HTTP) and WASI (WasiRuntime).
	cargo check -p keetanetwork-anchor-client --target wasm32-unknown-unknown --no-default-features --features wasm,resilience
	cargo check -p keetanetwork-anchor-client --target wasm32-wasip1 --no-default-features --features resilience
	cargo check -p keetanetwork-anchor-client --target wasm32-wasip2 --no-default-features --features resilience
	# WASI P2 networked KYC surface: WasiTransport + service layer + resilience.
	cargo check -p keetanetwork-anchor-client --target wasm32-wasip2 --no-default-features --features kyc,wasi,resilience
	# Shared binding core (algorithm mapping + account construction).
	cargo test -p keetanetwork-anchor-bindings
	# WASI bindings crate: host compile, then each feature-gated ABI.
	cargo check -p keetanetwork-anchor-client-wasi
	cargo check -p keetanetwork-anchor-client-wasi --target wasm32-wasip2 --no-default-features --features p2
	cargo check -p keetanetwork-anchor-client-wasi --target wasm32-wasip1 --no-default-features --features p1

# Build the TypeScript harnesses (installs deps + compiles every entry).
$(HARNESS_DIR)/node_modules/.package-lock.json: $(HARNESS_DIR)/package-lock.json
	cd $(HARNESS_DIR) && npm ci

$(HARNESS_DIR)/dist/.built: $(HARNESS_DIR)/node_modules/.package-lock.json $(HARNESS_SOURCES)
	cd $(HARNESS_DIR) && npm run build
	touch $@

node-harness: $(HARNESS_DIR)/dist/.built

# Run tests with host system's default target, then prove the core still
# compiles with no default features (no_std path).
test: node-harness
	# Use a shell script to unset CARGO_BUILD_TARGET and run tests
	sh -c 'unset CARGO_BUILD_TARGET; cargo test --all-features --workspace'
	cargo build -p keetanetwork-anchor --no-default-features

ANCHOR_WIT_DEP := $(WASI_CRATE)/wit/deps/keeta-client/world.wit

# Vendor the node WASI crate's WIT into the anchor component's deps.
wit-sync:
	@command -v jq >/dev/null || { echo "wit-sync: jq is required to resolve the client WIT" >&2; exit 1; }
	@manifest=$$(cargo metadata --format-version 1 --filter-platform wasm32-wasip1 --features p1 --manifest-path $(WASI_CRATE)/Cargo.toml | jq -r '.packages[] | select(.name=="keetanetwork-client-wasi") | .manifest_path'); \
	if [ -z "$$manifest" ]; then echo "wit-sync: could not resolve keetanetwork-client-wasi via cargo metadata" >&2; exit 1; fi; \
	src="$$(dirname "$$manifest")/wit/world.wit"; \
	if [ ! -f "$$src" ]; then echo "wit-sync: client WIT not found at $$src" >&2; exit 1; fi; \
	mkdir -p $(dir $(ANCHOR_WIT_DEP)); \
	cp "$$src" $(ANCHOR_WIT_DEP)

# Build both WASI artifacts the host-tests drive
build-wasi: wit-sync
	cargo build -p $(WASI_CRATE) --target wasm32-wasip2 --features p2
	cargo build -p $(WASI_CRATE) --target wasm32-wasip1 --no-default-features --features p1

# Run every host-test against the live TS KYC anchor, proving signing parity
test-wasi: build-wasi node-harness
	WASI_P2_COMPONENT=$(CURDIR)/$(WASI_P2_WASM) \
	WASI_P1_MODULE=$(CURDIR)/$(WASI_P1_WASM) \
	KYC_HARNESS=$(CURDIR)/$(HARNESS_DIR)/dist/kyc.js \
	ASSET_HARNESS=$(CURDIR)/$(HARNESS_DIR)/dist/asset.js \
		cargo test --manifest-path $(WASI_CRATE)/host-tests/Cargo.toml -- --include-ignored

test-all: test test-feat test-wasi

# Set up coverage tools (internal helper target)
coverage-setup:
	# Install cargo-llvm-cov if not present (quiet)
	@cargo install cargo-llvm-cov --quiet || true
	# Install llvm-tools-preview component (force, no prompts)
	@rustup component add llvm-tools-preview 2>/dev/null || true

# Generate code coverage report
coverage: coverage-setup node-harness
	# Clean previous coverage data
	@cargo llvm-cov clean --workspace || true
	# Generate HTML coverage report
	cargo llvm-cov --all-features --workspace --html --ignore-filename-regex '.*generated.*'
	# Generate LCOV coverage report (reusing the same coverage data)
	cargo llvm-cov report --lcov --output-path coverage.lcov --ignore-filename-regex '.*generated.*'
	# Open HTML report in browser (macOS) if it exists
	@if [ -f target/llvm-cov/html/index.html ]; then \
		open target/llvm-cov/html/index.html; \
	else \
		echo "HTML report not found at target/llvm-cov/html/index.html"; \
		echo "Trying alternative location..."; \
		find target -name "index.html" -path "*/llvm-cov/*" 2>/dev/null | head -1 | xargs open || echo "No HTML report found"; \
	fi

# Check coverage percentage and fail if below threshold
coverage-check: coverage-setup node-harness
	# Generate coverage and check threshold
	@echo "Generating coverage report..."
	@cargo llvm-cov --all-features --workspace --summary-only --ignore-filename-regex '.*generated.*' > coverage_summary.txt 2>&1
	@COVERAGE=$$(grep "TOTAL" coverage_summary.txt | grep -oE '[0-9]+\.[0-9]+%' | tail -1 | sed 's/%//'); \
	THRESHOLD=90.0; \
	if [ -z "$$COVERAGE" ]; then \
		echo "Could not extract total coverage percentage"; \
		cat coverage_summary.txt; \
		rm -f coverage_summary.txt; \
		exit 1; \
	fi; \
	echo "Current coverage: $${COVERAGE}%"; \
	echo "Minimum threshold: $${THRESHOLD}%"; \
	if [ $$(echo "$${COVERAGE} < $${THRESHOLD}" | bc -l) -eq 1 ]; then \
		echo "Coverage $${COVERAGE}% is below threshold $${THRESHOLD}%"; \
		rm -f coverage_summary.txt; \
		exit 1; \
	else \
		echo "Coverage $${COVERAGE}% meets threshold $${THRESHOLD}%"; \
		rm -f coverage_summary.txt; \
	fi

# Generate coverage report for CI (LCOV format for SonarCloud)
coverage-ci: coverage-setup node-harness
	# Generate LCOV coverage report for CI/SonarCloud
	cargo llvm-cov --all-features --workspace --lcov --output-path coverage.lcov --ignore-filename-regex '.*generated.*'

# Run security audit
audit:
	cargo audit

# Generate and open documentation
docs:
	cargo doc --no-deps --document-private-items --all-features --open

# Developer setup - install Rust and set up development environment
developer:
	@echo "Setting up development environment..."
	@if command -v rustc > /dev/null 2>&1; then \
		echo "Rust is already installed (version: $$(rustc --version))"; \
	else \
		echo "Installing Rust via rustup (automated)..."; \
		if [ -f scripts/rustup-init.sh ]; then \
			chmod +x scripts/rustup-init.sh; \
			./scripts/rustup-init.sh -y --default-toolchain stable; \
			echo "Rust installed! Sourcing environment..."; \
			. "$$HOME/.cargo/env" 2>/dev/null || true; \
		else \
			echo "scripts/rustup-init.sh not found in project root."; \
			echo "   Please download it from: https://sh.rustup.rs/"; \
			exit 1; \
		fi; \
	fi
	@echo "Setting up development tools..."
	@if command -v rustc > /dev/null 2>&1; then \
		echo "Rust version: $$(rustc --version)"; \
		echo "Cargo version: $$(cargo --version)"; \
		echo "Installing development tools..."; \
		$(MAKE) coverage-setup; \
		cargo install cargo-audit --quiet || echo "cargo-audit installation failed or already installed"; \
		echo "Running initial build and test..."; \
		$(MAKE) check; \
		$(MAKE) test; \
		echo ""; \
		echo "Development environment setup complete!"; \
	else \
		echo "Rust installation completed but not available in current shell."; \
		echo "Please restart your shell or run:"; \
		echo "   source $$HOME/.cargo/env"; \
		echo "   make developer"; \
	fi
	$(MAKE) help

# Publish packages and create release
# Optionally restrict to specific crates: make release PKG="keetanetwork-anchor"
# Bypass the clean-tree check (and cargo publish dirty guard): make release DIRTY=1
# Skip the test suite (lints still run): make release SKIP_TESTS=1
release:
	@echo "Running release script..."
	@./scripts/release.sh $(filter-out $@,$(MAKECMDGOALS)) $(if $(DIRTY),--allow-dirty) $(if $(SKIP_TESTS),--skip-tests) $(PKG)

# Allow flags to be passed as fake targets
--%:
	@:

# Help information
help:
	@echo "Makefile"
	@echo "=================================="
	@echo "Developer commands:"
	@echo "  make                - Build in debug mode"
	@echo "  make help           - Show this help message"
	@echo "  make developer      - Set up development environment (install Rust, tools, etc.)"
	@echo "  make build          - Build in debug mode"
	@echo "  make build release=1 - Build in release mode"
	@echo "  make clean          - Clean build artifacts"
	@echo "  make check          - Check compilation without building"
	@echo "  make do-docs        - Generate and open documentation"
	@echo "  make do-lint        - Lint code with clippy and format (with fixes)"
	@echo "  make node-harness   - Install + build the TypeScript interop harnesses"
	@echo "  make test           - Run tests (builds node-harness; all crypto feature combinations)"
	@echo "  make test-feat      - Run crypto crate tests with specific features"
	@echo "  make test-all       - Run all tests including feature tests"
	@echo "  make wit-sync       - Vendor the node WASI crate's WIT (keeta:client) into the anchor component deps"
	@echo "  make build-wasi     - Build the WASI P2 component and P1 core module the host-tests drive"
	@echo "  make test-wasi      - Build the wasm artifacts and run the host e2e tests (wasmtime P2 + bound C# SDK over P1) against the live TS KYC anchor"
	@echo "  make audit          - Run security audit"
	@echo "  make docs           - Generate and open documentation"
	@echo "  make coverage       - Generate code coverage report (HTML + LCOV)"
	@echo "  make coverage-check - Check coverage percentage and fail if below threshold"
	@echo "  make all            - Clean, build, and test"
	@echo ""
	@echo "CI Commands:"
	@echo "  make do-lint-ci     - Lint code for CI (check only, no fixes)"
	@echo "  make do-docs-ci     - Generate documentation without opening it"
	@echo "  make coverage-ci    - Generate LCOV coverage report for CI/SonarCloud"
	@echo ""
	@echo "Release Commands:"
	@echo "  make release                       - Publish all packages to crates.io and create signed release tag"
	@echo "  make release PKG=\"crate-a crate-b\" - Publish only the named crates (skips workspace tag)"
	@echo "  make release DIRTY=1               - Allow publishing with a dirty working tree"
	@echo "  make release SKIP_TESTS=1          - Skip the test suite (lints still run)"
	@echo "  make release --dry-run             - Preview the release without publishing"
