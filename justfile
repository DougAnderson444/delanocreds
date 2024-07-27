# compose the *.wasm files together
build:
  cargo component build --workspace --release

preview: build
  cd examples/svelte-wit-ui && npm run build && npm run preview -- --open

test:
  cargo test --workspace
