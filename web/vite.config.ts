import { resolve } from 'node:path'
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig(({ command }) => ({
  base: command === 'build' ? '/cloudthreat-atlas/' : '/',
  publicDir: resolve(__dirname, '../demo'),
  plugins: [react()],
  build: {
    target: 'es2022',
    sourcemap: false,
    license: { fileName: 'THIRD_PARTY_LICENSES.md' },
  },
  test: {
    environment: 'jsdom',
    setupFiles: ['./src/test/setup.ts'],
    css: true,
    exclude: ['e2e/**', '**/node_modules/**', '**/dist/**'],
  },
}))
