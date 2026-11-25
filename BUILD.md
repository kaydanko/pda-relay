# Build and test

## Requirements

- Rust toolchain 1.87 or newer (workspace `rust-version`; pinned checks use `cargo +1.87.0`).
- A supported Linux or macOS development host. The production reference target is Linux.
- Network access once to download the locked crates.

## Commands

From the repository root:

```sh
cargo build --manifest-path relay/Cargo.toml --locked --workspace
cargo fmt --manifest-path relay/Cargo.toml --all --check
cargo clippy --manifest-path relay/Cargo.toml --workspace --all-targets -- -D warnings
cargo test --manifest-path relay/Cargo.toml --locked --workspace
```

Run the development server:

```sh
cargo run --manifest-path relay/Cargo.toml --locked -p pda-relay
```

The protocol crate is deliberately `#![no_std]` and uses only `alloc` plus `minicbor`. `cargo check -p pda-relay-protocol` verifies its normal portable build. An eventual ESP-IDF implementation must pass the same golden vectors; this repository does not yet claim an ESP32 build or connection capacity.

## Test coverage

- stable CBOR golden encoding and round trips;
- rejection of indefinite arrays, trailing bytes, wrong ID sizes, and oversize frames/payloads;
- duplicate live-route rejection and generation-safe cleanup;
- two live clients forwarding opaque bytes and routing recipient ACK;
- offline-recipient error with no relay queue;
- binary-only application framing;
- isolated subprocess restart proving that packet bytes and routes are not persisted.

