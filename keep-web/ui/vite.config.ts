import { defineConfig } from 'vite'
import { svelte } from '@sveltejs/vite-plugin-svelte'

// Relative base so assets resolve behind the StartOS reverse proxy.
export default defineConfig({
  plugins: [svelte()],
  base: './',
  build: { outDir: 'dist' },
  server: {
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:8080',
        ws: true,
      },
    },
  },
})
