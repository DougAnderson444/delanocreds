import { sveltekit } from '@sveltejs/kit/vite';
import { defineConfig } from 'vite';

export default defineConfig({
	plugins: [sveltekit()],
	server: { fs: { strict: false } },
	build: {
		minify: false
	},
	worker: {
		format: 'es'
	}
});
