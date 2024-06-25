import { join } from 'node:path'
import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    setupFiles: [join(import.meta.dirname, './setup.ts')],
  },
})
