import { expect, test } from '@playwright/test';

// 最小の煙試験。ほかの E2E が落ちたとき、原因が「サーバーが起動しない」なのか「個別の機能」なのかを切り分けるために置く。
// パスキーの E2E（仮想認証器）は passkey.spec.ts、パスワードは password.spec.ts、再設定は reset.spec.ts にある。
test('トップ画面が開ける', async ({ page }) => {
  await page.goto('/');
  await expect(page).toHaveTitle('passkey-auth-starter');
  await expect(page.getByRole('heading', { level: 1 })).toHaveText('passkey-auth-starter');
});
