<script>
	import { onMount, tick } from 'svelte';
	import { Wurbo, wurboIn } from 'wurbo';
	// When we use $page.url.hash, responding to chnages in the hash becomes very easy.
	import { page } from '$app/stores';

	// Import wasm component bytes as a url
	import wasmURL from '../../../../../target/wasm32-wasi/release/delano_wit_ui.wasm?url';
	import { buildWalletActions } from './importables.js';

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
	let wurbo;

	onMount(async () => {
		// get your wasm bytes from your storage source
		let wasmBytes = await fetch(wasmURL).then((res) => res.arrayBuffer());

		// define the import handles you are giving to your component
		let all_importables = [
			{ 'delano:wit-ui/wurbo-in': wurboIn },
			{
				'delano:wallet/actions@0.1.0': buildWalletActions()
			}
		];

		// load the import handles into the Wasm component and get the ES module returned
		wurbo = new Wurbo({ arrayBuffer: wasmBytes, importables: all_importables });

		// get the string after the hash (slice 1)
		let api = null;
		try {
			api = $page.url.hash.slice(1);
		} catch (e) {
			console.warn(e);
		}

		// call `render` with your inputs for the component
		let data = {
			tag: 'all-content',
			val: {
				page: {
					name: 'Delanocreds Wallet app',
					version: '0.1.0',
					description: 'A wallet app for Delanocreds'
				},
				load: api
			}
		};
		renderedHTML = await wurbo.render(data);
	});

	// Once the HTML is rendered and the module is loaded, we can activate the event emitters
	$: if (renderedHTML && wurbo)
		(async () => {
			// wait for the DOM to reflect the updates first
			await tick();
			// once the DOM has our elements loaded, we can activate the event emitters
			wurbo.activate();
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
