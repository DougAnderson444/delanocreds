# Example Apps using the WIT components.

There is a UI demo app in [`./src/lib/ui/UIOnly.svelte`] and a full wallet (composed `delano-wallet`, `delano-wit-ui`, and a [`seed-keeper`](https://github.com/DougAnderson444/seed-keeper)) in [`./src/lib/full/FullWallet.svelte`].

## Compose Full Wallet (WIP)

Compose the seed, delano and user interface components into a full wallet

```bash
just compose
```

## Developing

Once you've created a project and installed dependencies with `npm install` (or `pnpm install` or `yarn`), start the server:

```bash
npm run build

# or start the server and open the app in a new browser tab
npm run preview -- --open
```

## Building

To create a production version of your app:

```bash
npm run build
```

You can preview the production build with `npm run preview`.

> To deploy your app, you may need to install an [adapter](https://kit.svelte.dev/docs/adapters) for your target environment.
