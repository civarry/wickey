import { defineConfig } from 'vite';
import { svelte } from '@sveltejs/vite-plugin-svelte';
import tailwindcss from '@tailwindcss/vite';

const target = `http://127.0.0.1:${process.env.WICKEY_PORT || 7777}`;

// The backend rejects any Origin that is not its own loopback address, so the dev proxy drops it.
const proxy = {
  target,
  changeOrigin: true,
  configure: (p: { on: (ev: 'proxyReq', fn: (req: { removeHeader: (n: string) => void }) => void) => void }) => {
    p.on('proxyReq', (req) => req.removeHeader('origin'));
  },
};

export default defineConfig({
  root: import.meta.dirname,
  base: '/',
  plugins: [tailwindcss(), svelte()],
  build: { outDir: 'dist', emptyOutDir: true, assetsInlineLimit: 0 },
  server: { proxy: { '/api': proxy, '/p': proxy } },
});
