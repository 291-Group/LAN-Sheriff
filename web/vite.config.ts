import { defineConfig } from 'vite'
import preact from '@preact/preset-vite'

export default defineConfig({
  plugins: [preact()],
  // Built straight into the Go embed directory so `make build` is one step.
  build: {
    outDir: '../internal/web/dist',
    emptyOutDir: true,
    target: 'es2020',
    reportCompressedSize: true,
  },
  server: {
    // Overridable so the dev server, and the CPU profiler that runs against
    // it, can be pointed at a purpose-seeded instance instead of whatever
    // happens to be on 2911. Profiling needs a known dataset, not a live one.
    proxy: {
      '/api': {
        target: process.env.LS_API || 'http://127.0.0.1:2911',
        ws: true,
      },
    },
  },
})
