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
    ],
    setupFiles: [],
  },
  resolve: {
    alias: {
      '@meritum/shared': path.resolve(__dirname, '../../packages/shared/src'),
    },
  },
});
