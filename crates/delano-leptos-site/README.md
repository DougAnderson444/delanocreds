## Developing

Build and watch for CSS changes:

```bash
tailwindcss -i ./input.css -o ./style/output.css --watch
```

Install trunk to client side render this bundle.

```
cargo install trunk
```

Then the site can be served with

```shell
trunk serve --open
```

The browser will automatically open [http://127.0.0.1:8080/](http://127.0.0.1:8080/)
