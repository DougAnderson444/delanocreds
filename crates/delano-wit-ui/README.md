# Delanocreds User Interface

A default implementation of the Delano UI using [`wurbo`](https://github.com/DougAnderson444/wurbo).

Don't like the look of it? You will be able to fork the HTML templates and modify it to your liking.

# Usage

This crate is just the User Interface to interact with the [`delano-wit`](../delano-wit/) Application Binary Interface (ABI) and display the resulting data.

To use this crate, you will need to provide [`delano-wit`](../delano-wit/) (or your fork of it) as an import dependency when using `wasm-tools` to compose your app together.

A reference composed app is available here.

# Test

Tests in [`./tests/mod.rs`](./tests/mod.rs) can be run with:

```bash
cargo test
```

These tests use wasmtime to run the WIT component in Rust, and depend on the `.wit` dependencies in the [`wit`](../wit/deps/) folder, which have been copied over from their source folder. If the dependencies changes, then these copies also need to be updated for the tests to run as intended.

# Dev

Build the component with:

```bash
cargo component build 
```

Compile your Tailwindcss into `./style/output.css`:

```bash
npx tailwindcss -i ./style/input.css -o ./style/output.css --watch
```

then run the component using `rollup-plugin-wit-component`. See [Example](../../examples/svelte-wit-ui/src/lib/ui/UIOnly.svelte) for example usage. Unfortunately because of the way Vite handle wasm that compiles wasm, `vite dev` mode cannot be used and the code must be built every time.
