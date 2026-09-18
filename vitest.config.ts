/// <reference types="vitest" />
import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'node',
    globals: false,
    setupFiles: ['./test/setup.ts'],
    include: ['test/**/*.test.ts'],
    testTimeout: 30_000,
    hookTimeout: 30_000,
    env: {
      VITE_API_BASE_URL: 'https://api.example.test',
      VITE_WS_BASE_URL: 'wss://ws.example.test',
    },
  },
});