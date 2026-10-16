import { randomBytes } from 'node:crypto';
import { expect, test } from '@playwright/test';

// 画面からの「パスワードで登録 → ログアウト → ログイン」。
// 画面のスクリプト（app.js）が JSON で送り、Origin ヘッダ（S13）も含めて通ることを実ブラウザで確かめる。
test('パスワードで登録・ログアウト・ログインができる', async ({ page }) => {
  const email = `e2e-${randomBytes(4).toString('hex')}@example.com`;
  // テストの期待値に生値を書かないよう、毎回ランダムに作る
  const password = randomBytes(24).toString('base64url');

  await page.goto('/signup');
  await page.getByLabel('メールアドレス').fill(email);
  await page.getByLabel('パスワード（15 文字以上）').fill(password);
  await page.getByRole('button', { name: '登録する' }).click();

  await expect(page).toHaveURL(/\/account$/);
  await expect(page.locator('[data-me-email]')).toHaveText(email);

  await page.getByRole('button', { name: 'この端末でログアウト' }).click();
  await expect(page).toHaveURL(/\/$/);

  await page.goto('/login');
  await page.getByLabel('メールアドレス').fill(email);
  await page.getByLabel('パスワード').fill(randomBytes(24).toString('base64url'));
  await page.getByRole('button', { name: 'ログイン', exact: true }).click();
  await expect(page.getByRole('alert')).toHaveText('メールアドレスまたはパスワードが違います');

  await page.getByLabel('パスワード').fill(password);
  await page.getByRole('button', { name: 'ログイン', exact: true }).click();
  await expect(page).toHaveURL(/\/account$/);
  await expect(page.locator('[data-me-email]')).toHaveText(email);
});

test('短いパスワードは理由とともに拒否される（S2）', async ({ page }) => {
  await page.goto('/signup');
  await page.getByLabel('メールアドレス').fill(`e2e-${randomBytes(4).toString('hex')}@example.com`);
  const input = page.getByLabel('パスワード（15 文字以上）');
  await input.fill(randomBytes(7).toString('hex'));
  // ブラウザの minlength 検査を外して、サーバー側の検査と文言を確かめる
  // tsconfig に DOM の型を入れていないので、ブラウザ側で動く式は文字列で渡す
  await page.evaluate("document.querySelector('form').noValidate = true");
  await page.getByRole('button', { name: '登録する' }).click();
  await expect(page.getByRole('alert')).toContainText('15 文字以上');
});
