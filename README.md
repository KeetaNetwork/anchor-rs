# anchor-rs

A Rust implementation of KeetaNet anchor.

## Development

### Quick Start

For first-time setup, simply run:

```bash
make developer
```

This will:

- Install Rust (if not already installed)
- Install development tools
- Run initial build and tests

### Building

```bash
# Debug build
make build

# Release build
make release

# Check compilation without building
make check
```

### Testing

```bash
# Test defaults with all features
make test

# Test all features individually from packages with features
make test-feat

# Test everything
make test-all
```

### Language bindings

#### C#

The C# SDK (`keetanetwork-anchor-client-wasi/bindings/csharp`) is a proof-of-concept binding kept in-tree. It is an in-process .NET host over the WASI Preview 1 core module (`target/wasm32-wasip1/...`): the resolver, request signing, resilience, and polling all run inside the one portable `.wasm`; the C# side only shims HTTP and timers and marshals JSON.

It is exercised by the Rust host-test `csharp_p1_kyc.rs`, which boots the live TypeScript anchor and drives the C# test harness (`KeetaNet.Anchor.Kyc.Harness`) end-to-end via the .NET CLI - exactly like the wasmtime P2 host-test, just through the bound SDK.

Local dependencies (macOS):

```bash
# .NET SDK (the Wasmtime native runtime ships inside the NuGet package)
brew install --cask dotnet-sdk

# The wasm targets the host-tests build
rustup target add wasm32-wasip1 wasm32-wasip2

# Node.js 20 drives the TypeScript signing-parity harness
brew install node@20
```

Run all WASI host e2e tests (the wasmtime P2 component and the bound C# SDK over P1) against the live TypeScript anchor:

```bash
make test-wasi
```

The C# test **skips** locally when the .NET SDK is absent so a Rust-only checkout still passes; CI sets `CI`, which forces the run, so the binding is always exercised there.

### Code Coverage

```bash
# Generate HTML coverage report (opens in browser)
make coverage
```

### Linting

```bash
# Format code and run clippy
make do-lint
```

### Documentation

```bash
# Generate documentation and open it
make do-docs
```

### Other Commands

```bash
# Clean build artifacts
make clean

# Show all available commands
make help
```

### CI Commands

```bash
# Generate LCOV coverage report for CI
make coverage-ci

# Format code and clippy without fixes
make do-lint-ci
```
