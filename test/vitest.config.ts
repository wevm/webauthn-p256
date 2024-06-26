import { join } from 'node:path'
import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    coverage: {
      exclude: ['**/_cjs/**', '**/_esm/**', '**/_types/**', '**/playground/**'],
      include: ['**/src/**'],
      provider: 'v8',
      reporter: process.env.CI ? ['lcov'] : ['text', 'json', 'html'],
    },
    setupFiles: [join(import.meta.dirname, './setup.ts')],
  },
})
