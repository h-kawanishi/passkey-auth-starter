import { randomBytes } from 'node:crypto';
import { expect, test } from '@playwright/test';

// パスワード忘れの画面。メールの中身は E2E からは読めない（開発用の Mailer は標準出力に書く）ので、
// トークンを使い切る流れは結合テスト（test/integration/reset.test.ts）で確かめ、ここでは画面の振る舞いを見る。

test('ログイン画面から再設定の画面へ進み、登録の有無が分からない同じ文言が出る', async ({ page }) => {
  await page.goto('/login');
  await page.getByRole('link', { name: 'パスワードを忘れた場合' }).click();
  await expect(page).toHaveURL(/\/reset$/);
  await page.getByLabel('メールアドレス').fill(`e2e-${randomBytes(4).toString('hex')}@example.com`);
  await page.getByRole('button', { name: '再設定のメールを送る' }).click();
  await expect(page.getByRole('status')).toContainText('登録されていれば');
});

test('再設定リンクのトークンはアドレス欄から消え、無効なトークンは理由とともに断られる（S10）', async ({ page }) => {
  // 形は正しいが発行していないトークン
  const bogus = randomBytes(32).toString('base64url');
  await page.goto(`/reset/new#token=${bogus}`);
  // 画面を開いたら、トークンは URL（アドレス欄と履歴）から消えている
  await expect(page).toHaveURL(/\/reset\/new$/);
  await page.getByLabel('新しいパスワード（15 文字以上）').fill(randomBytes(24).toString('base64url'));
  await page.getByRole('button', { name: 'パスワードを設定する' }).click();
  await expect(page.getByRole('alert')).toContainText('このリンクは使えません');
});
