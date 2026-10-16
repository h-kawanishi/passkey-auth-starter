import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    // E2E（test/e2e）は Playwright が担当する。Vitest が拾うと別ランナーの API で落ちるので除外する。
    include: ['test/unit/**/*.test.ts', 'test/integration/**/*.test.ts'],
    environment: 'node',
  },
});
