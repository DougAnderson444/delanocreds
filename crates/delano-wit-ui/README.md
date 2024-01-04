# Delanocreds User Interface

A default implementation of the Delano UI using [`wurbo`](https://github.com/DougAnderson444/wurbo).

Don't like the look of it? You will be able to fork the HTML templates and modify it to your liking.

# Usage

This crate is just the User Interface to interact with the [`delano-wit`](../delano-wit/) Application Binary Interface (ABI) and display the resulting data.

To use this crate, you will need to provide [`delano-wit`](../delano-wit/) (or your fork of it) as an import dependency when using `wasm-tools` to compose your app together.

A reference composed app is available here.

# Dev

Using `trunk-rs`:

```bash
trunk serve --open
```

Compile your Tailwindcss into `./style/output.css`:

```bash
npx tailwindcss -i ./style/input.css -o ./style/output.css --watch
```
