<script>
	import { onMount, tick } from 'svelte';
	import * as wurbo from 'wurbo';

	// Import wasm component bytes as a url
	import wasmURL from '../../../../../target/wasm32-wasi/debug/delano_wit_ui.wasm?url';
	import * as importables from './importables.js';

	export let load;

	/**
	 * The rendered component as a string of HTML
	 * @type {string | null}
	 */
	let renderedHTML;
	/**
	 * The module that loads the WebAssembly component
	 *
	 * @type {{ render: (arg0: string) => string | null; listen: () => void; }}
	 */
	let mod;

	onMount(async () => {
		// ensure you are in the Browser environment to rollup your WIT Component
		// const { load } = await import('rollup-plugin-wit-component');

		let listener = new wurbo.Listener();

		// get your wasm bytes from your storage source
		let wasmBytes = await fetch(wasmURL).then((res) => res.arrayBuffer());

		// define the import handles you are giving to your component
		let all_importables = [
			{ 'delano:wit-ui/wurbo-in': importables.buildCodeString(listener.namespace) },
			{
				'delano:wallet/actions@0.1.0': importables.buildWalletActions()
			}
		];

		// load the import handles into the Wasm component and get the ES module returned
		mod = await load(wasmBytes, all_importables);

		// call `render` with your inputs for the component
		let data = {
			tag: 'all-content',
			val: {
				page: {
					name: 'Delanocreds Wallet app',
					version: '0.1.0',
					description: 'A wallet app for Delanocreds'
				}
			}
		};
		renderedHTML = mod.wurboOut.render(data);

		// lisen for events from the component
		listener.listen(mod);
	});

	// Once the HTML is rendered and the module is loaded, we can activate the event emitters
	$: if (renderedHTML && mod)
		(async () => {
			// wait for the DOM to reflect the updates first
			await tick();
			// once the DOM has our elements loaded, we can activate the event emitters
			mod.wurboOut.activate();
		})();
</script>

<svelte:head>
	<script src="https://cdn.tailwindcss.com"></script>
</svelte:head>
<div>
	<h1>Delano UI Only</h1>
	{#if renderedHTML}
		{@html renderedHTML}
	{/if}
</div>
