import { defineConfig } from 'vitest/config';

// Unit tests only. The Playwright accessibility gate lives in e2e/ and is run
// separately via `npm run test:a11y`, so it must never be collected by vitest.
export default defineConfig({
  test: {
    include: ['src/**/*.test.ts'],
    exclude: ['e2e/**', 'node_modules/**', 'dist/**'],
    environment: 'node',
  },
});
