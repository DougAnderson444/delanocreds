# **Del**egatable **Ano**nymous **Cred**ential**s** (Delanocreds) Workspace

The Delegateable Anonymous Credentials (DAC) system. A system for issuing and verifying anonymous credentials that can be delegated to other parties.

![Delano](./dac-flow.svg)

This is a workspace broken down into:

| Crate | Status | Description |
| --- | --- | --- |
| [delanocreds](/crates/delanocreds/) | ✅ | The Rust core library for issuing and using anonymous credentials. |
| [delano-keys](/crates/delano-keys/) |  ✅ | A Rust library for generating, compacting, expanding, and using BLS12-381 verification keys (VKs). |
| [delano-wallet](/crates/delano-wallet/) |  ✅ | Wallet Component, uses Wasm Interface Types ([WIT](https://component-model.bytecodealliance.org/design/wit.html)) for [Wasm Component](https://github.com/WebAssembly/component-model) use from any [host system](https://github.com/bytecodealliance/wit-bindgen#host-runtimes-for-components) such as Go, JavaScript, Python or Rust.
| [delano-wit-ui](/crates/delano-wit-ui/) | 🚧 | A Work-In-Progress default implementation of the Delano UI using [`wurbo`](https://github.com/DougAnderson444/wurbo) and [Minijinja](https://docs.rs/minijinja/latest/minijinja/) HTML Templates.
| [examples](examples/) |  🚧 | A simple Rust demo that issues and verifies credentials |

## Run Demo Binary

See how fast it creates and verifies credentials.

```bash
cargo run --release
```

## Tests

Workspace and integration tests are located in `./tests` and can be run with:

```bash
cargo test --workspace
```

When writing [`delanocreds`](/crates/delanocreds), the [`bls12-381-plus` crate](https://github.com/mikelodder7/bls12_381_plus/pull/3) wasn't wasm32 compatible, so I forked it and added wasm32 support. The wasm32 tests were added to verify the changes compile to wasm, added in `./tests/wasm.rs` using `wasm-bindgen-test` and [wasm-bindgen-cli](https://rustwasm.github.io/wasm-bindgen/wasm-bindgen-test/usage.html#appendix-using-wasm-bindgen-test-without-wasm-pack). They can be run with this command:

```bash
cargo test --target wasm32-unknown-unknown
```

## Build Wasm

Because the workspace includes Wasm Interface Types (WIT), the build command must use `component build` instead of `build`. This is a wrapper around `cargo build` anyway, so it builds non-components too:

```bash
cargo component build --workspace --release
```

