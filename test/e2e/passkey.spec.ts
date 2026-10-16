import { expect, test, type CDPSession, type Page } from '@playwright/test';

// Chrome DevTools Protocol の WebAuthn 仮想認証器で、本物のブラウザの navigator.credentials を動かす。
// 指紋センサーや PIN の代わりを CDP が務めるので、CI でも人の操作なしにパスキーを試せる。
async function addVirtualAuthenticator(
  page: Page,
  transport: 'internal' | 'usb' = 'internal',
): Promise<{ cdp: CDPSession; authenticatorId: string }> {
  const cdp = await page.context().newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2',
      // internal = 端末内蔵（プラットフォーム認証器）、usb = 持ち歩くセキュリティキー
      transport,
      hasResidentKey: true, // S5: Discoverable Credential を保存できる
      hasUserVerification: true,
      isUserVerified: true, // 指紋や PIN の確認に成功した扱い
      automaticPresenceSimulation: true, // 「タッチした」扱いを自動で返す
    },
  });
  return { cdp, authenticatorId };
}

test('パスキーで登録 → ログアウト → パスキーでログインできる', async ({ page }) => {
  const { cdp, authenticatorId } = await addVirtualAuthenticator(page);
  // 並列実行や再実行でメールが重ならないよう、毎回違う値にする
  const email = `e2e-${Date.now()}-${Math.floor(Math.random() * 1e6)}@example.com`;

  await page.goto('/signup');
  await page.getByLabel('メールアドレス').fill(email);
  await page.getByRole('button', { name: 'パスキーで登録' }).click();

  await expect(page).toHaveURL(/\/account$/);
  await expect(page.locator('#account-email')).toHaveText(email);
  await expect(page.locator('#passkey-list li')).toHaveCount(1);

  // 認証器の中に Discoverable Credential が 1 つできている（S5）
  const { credentials } = await cdp.send('WebAuthn.getCredentials', { authenticatorId });
  expect(credentials).toHaveLength(1);
  expect(credentials[0]?.isResidentCredential).toBe(true);

  // ログイン画面は開いた時点で条件付き UI の待ち受けを始める。仮想認証器が勝手に応じてログインして
  // しまわないよう、「タッチした」扱いをいったん止めて、ログアウトできたことを先に確かめる
  await cdp.send('WebAuthn.setAutomaticPresenceSimulation', { authenticatorId, enabled: false });
  await page.getByRole('button', { name: 'ログアウト' }).click();
  await expect(page).toHaveURL(/\/login$/);
  // ログアウト後はアカウント設定に入れない
  await page.goto('/account');
  await expect(page).toHaveURL(/\/login$/);

  // メールアドレスを打たずに、パスキーだけでログインする（Discoverable Credential）
  await cdp.send('WebAuthn.setAutomaticPresenceSimulation', { authenticatorId, enabled: true });
  await page.getByRole('button', { name: 'パスキーでログイン' }).click();
  await expect(page).toHaveURL(/\/account$/);
  await expect(page.locator('#account-email')).toHaveText(email);
  await expect(page.locator('#passkey-list li')).toContainText('最終利用');
});

test('アカウント設定でパスキーを追加・名前変更できる', async ({ page }) => {
  await addVirtualAuthenticator(page);
  const email = `e2e-add-${Date.now()}-${Math.floor(Math.random() * 1e6)}@example.com`;
  await page.goto('/signup');
  await page.getByLabel('メールアドレス').fill(email);
  await page.getByRole('button', { name: 'パスキーで登録' }).click();
  await expect(page).toHaveURL(/\/account$/);

  // 2 本目は別の認証器（セキュリティキー）として足す。同じ認証器は excludeCredentials で弾かれ、
  // 仮想の内蔵認証器は 1 つしか作れないため
  await addVirtualAuthenticator(page, 'usb');
  await page.getByLabel('名前').fill('仕事用ノートPC');
  await page.getByRole('button', { name: 'パスキーを追加' }).click();
  await expect(page.locator('#passkey-list li')).toHaveCount(2);
  await expect(page.locator('#passkey-list')).toContainText('仕事用ノートPC');

  page.once('dialog', (d) => void d.accept('私用スマホ'));
  await page.locator('#passkey-list li').first().getByRole('button', { name: '名前を変える' }).click();
  await expect(page.locator('#passkey-list li').first().locator('.passkey-name')).toHaveText('私用スマホ');
});

test('条件付き UI: ログイン画面を開くだけで、自動入力のパスキーからログインできる', async ({ page }) => {
  await addVirtualAuthenticator(page);
  const email = `e2e-autofill-${Date.now()}-${Math.floor(Math.random() * 1e6)}@example.com`;
  await page.goto('/signup');
  await page.getByLabel('メールアドレス').fill(email);
  await page.getByRole('button', { name: 'パスキーで登録' }).click();
  await expect(page).toHaveURL(/\/account$/);
  await page.context().clearCookies(); // ログアウトと同じ状態にする

  // 仮想認証器は自動入力の候補選択を「選んだ」扱いで返す。ボタンを押さずにログインが完了する
  await page.goto('/login');
  await expect(page).toHaveURL(/\/account$/);
  await expect(page.locator('#account-email')).toHaveText(email);
});
