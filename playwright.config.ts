import { randomBytes } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { defineConfig, devices } from '@playwright/test';

// 開発用サーバー（既定 3000）と衝突しないよう、E2E 専用のポートを使う。
// 複数の作業ツリーで同時に E2E を走らせるときは E2E_PORT で変える（reuseExistingServer で他方のサーバーを拾わないため）。
const PORT = Number(process.env.E2E_PORT ?? 3123);
const ORIGIN = `http://localhost:${PORT}`;
// E2E のサーバーの DB は一時ディレクトリのファイルにする。テストから同じ DB を開き、
// 「本人確認から 5 分が過ぎた」状態を時刻の書き換えで作るため（5 分待たずに再認証の流れを試す）。
// 設定ファイルはテストの各ワーカーでも読み直されるので、最初に決めた値を環境変数で引き継ぐ
process.env.E2E_DATABASE_PATH ??= join(tmpdir(), `passkey-auth-starter-e2e-${PORT}-${Date.now()}.sqlite`);

export default defineConfig({
  testDir: 'test/e2e',
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? 'github' : 'list',
  use: {
    baseURL: ORIGIN,
    trace: 'retain-on-failure',
  },
  projects: [
    {
      // パスキーの E2E は Chrome DevTools Protocol の仮想認証器を使うため Chromium に限る。
      name: 'chromium',
      use: {
        ...devices['Desktop Chrome'],
        // CI では `playwright install` したブラウザを使う。手元に別のブラウザしかない環境向けの逃げ道。
        ...(process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE
          ? { launchOptions: { executablePath: process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE } }
          : {}),
      },
    },
  ],
  webServer: {
    command: 'npx tsx src/server.ts',
    url: `${ORIGIN}/healthz`,
    reuseExistingServer: !process.env.CI,
    env: {
      NODE_ENV: 'test',
      HOST: '127.0.0.1',
      PORT: String(PORT),
      RP_ID: 'localhost',
      RP_NAME: 'passkey-auth-starter (e2e)',
      ORIGIN,
      // テストのたびに使い捨ての秘密を作る。固定値をリポジトリに置かないため。
      SESSION_SECRET: randomBytes(32).toString('base64url'),
      DATABASE_PATH: process.env.E2E_DATABASE_PATH,
      LOG_LEVEL: 'warn',
    },
  },
});
