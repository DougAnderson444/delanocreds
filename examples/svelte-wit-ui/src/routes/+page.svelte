<script>
	import { onMount } from 'svelte';
	import { examples } from '$lib';

	let load;

	onMount(async () => {
		// ensure you are in the Browser environment to rollup your WIT Component
		({ load } = await import('rollup-plugin-wit-component'));
	});
</script>

<div>
	<!-- For each Svelte file in examples, display it -->
	{#if load}
		{#each examples as example}
			<div class="border-2 border-dashed p-2 m-2">
				<svelte:component this={example} {load} />
			</div>
		{/each}
	{/if}
</div>
