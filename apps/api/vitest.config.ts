import { defineConfig } from 'vitest/config';
import path from 'path';

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    include: [
      'src/**/*.test.ts',
      'test/**/*.test.ts',
      'test/**/*.integration.ts',
      'test/**/*.security.ts',
      'test/**/*.db.ts',
      'test/**/*.ws.ts',
      'test/**/*.concurrent.ts',
      'test/**/*.perf.ts',
      'test/**/*.seed.ts',
    ],
    globalSetup: ['test/fixtures/global-setup.ts'],
    setupFiles: [],
    testTimeout: 15000,
    hookTimeout: 30000,
  },
  resolve: {
    alias: {
      '@meritum/shared': path.resolve(__dirname, '../../packages/shared/src'),
    },
  },
});
