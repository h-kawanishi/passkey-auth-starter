import { expect, test } from '@playwright/test';

// セッション A では「サーバーが起動し、ブラウザで画面が開ける」ことだけを確かめる。
// パスキー登録 → ログインの E2E（仮想認証器）はセッション C で追加する。
test('トップ画面が開ける', async ({ page }) => {
  await page.goto('/');
  await expect(page).toHaveTitle('passkey-auth-starter');
  await expect(page.getByRole('heading', { level: 1 })).toHaveText('passkey-auth-starter');
});
