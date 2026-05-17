import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// https://vite.dev/config/
export default defineConfig({
  plugins: [
    react(),
    tailwindcss(),
  ],
  // Vitest config — kept in this file so `npm test` picks it up without
  // a separate vitest.config. jsdom gives us window/document for RTL;
  // setupFiles wires @testing-library/jest-dom matchers.
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./src/test/setup.js'],
    // Wave 12: keep Playwright E2E specs out of Vitest — they import
    // @playwright/test which is incompatible with the jsdom runtime.
    exclude: ['e2e/**', 'node_modules/**', 'dist/**'],
  },
})
