# Delanocreds Wallet

This wallet is designed as a WebAssembly Component using Wasm Interface Types (WIT) for Delanocreds. This means it can be used anywhere wasmtime is supported, such as in Rust or in the Browser using [`jco`](https://www.npmjs.com/package/@bytecodealliance/jco).

This crate provides a Rust implementation of the [Wasm Interface Types (WIT)](https://component-model.bytecodealliance.org/design/wit.html) proposal.

# API Summary

See the [wit file](./wit/delanocreds.wit) for the full API.

- `issue` - Creates and issues a Root Credential. Self-issues the credential if no NymProof option is provided.
- `offer` - Turns a created credential into an Offer for someone else's Nym
- `accept` - Accepts an Offer and redeems it for the holder. Must have attributes that match the credential to successfully accept an offer.
- `prove` - Creates a proof for a given credential and attributes.
- `verify` - Verifies a proof for a given credential and attributes.

# Build

```bash
cargo component build
```

# Test

```bash
cargo component build
cargo test
```

Ensure that compatible [`cargo-component`](https://github.com/bytecodealliance/cargo-component) is installed with the current `wasmtime`:

```bash
cargo install cargo-component
```
