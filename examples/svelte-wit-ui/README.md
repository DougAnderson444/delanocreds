# Example Apps using the WIT components.

There is a UI demo app in [`./src/lib/ui/UIOnly.svelte`] and a full wallet (composed `delano-wallet`, `delano-wit-ui`, and a [`seed-keeper`](https://github.com/DougAnderson444/seed-keeper)) in [`./src/lib/full/FullWallet.svelte`].

## Developing

Once you've created a project and installed dependencies with `npm install` (or `pnpm install` or `yarn`), build and start the server using [`just`](https://just.systems):

```bash
just preview
```

## Compose Full Wallet (WIP)

See the [`peerpiper-wallet`](https://github.com/PeerPiper/peerpiper/tree/master/crates/peerpiper-wallet) for an example of how to intgerate a `seed-keeper` with this component into a Full Wallet.
