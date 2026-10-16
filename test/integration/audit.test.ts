// S12: 監査ログの網羅と、ログ・監査ログ・DB に秘密の生値が出ないことを、すべての流れを通して確かめる。
import { PassThrough } from 'node:stream';
import { describe, expect, it } from 'vitest';
import type { FastifyInstance, LightMyRequestResponse } from 'fastify';
import type {
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
} from '@simplewebauthn/server';
import { AUDIT_EVENTS } from '../../src/auth/audit.js';
import { LOCKOUT_THRESHOLD } from '../../src/auth/lockout.js';
import type { Db } from '../../src/db/connection.js';
import { ORIGIN, makeApp, post, randomPassword, signup, uniqueEmail } from '../helpers/app.js';
import { CaptureMailer, tokenFromMail } from '../helpers/mailer.js';
import { TestBrowser } from '../helpers/passkey-client.js';
import { SoftAuthenticator } from '../helpers/soft-authenticator.js';

/** DB の全テーブル・全列。BLOB は UTF-8・16 進・base64url のどれで探しても見つかるようにする */
function dumpDatabase(db: Db): string {
  const tables = db.prepare("SELECT name FROM sqlite_master WHERE type = 'table'").pluck().all() as string[];
  return tables
    .flatMap((t) => db.prepare(`SELECT * FROM "${t}"`).all() as Record<string, unknown>[])
    .flatMap((row) => Object.values(row))
    .map((v) =>
      Buffer.isBuffer(v) ? [v.toString('utf8'), v.toString('hex'), v.toString('base64url')].join('|') : String(v),
    )
    .join('\n');
}

/** すべての流れを一通り行い、その途中で出てきた秘密の生値を集めて返す */
async function walkEveryFlow(app: FastifyInstance, mailer: CaptureMailer): Promise<Set<string>> {
  const secrets = new Set<string>();
  const keepCookies = (res: LightMyRequestResponse) => res.cookies.forEach((c) => c.value && secrets.add(c.value));
  const keepBrowser = (b: TestBrowser) => b.cookies.forEach((v) => v && secrets.add(v));

  // ---- パスワード: 登録・失敗・成功・変更（失敗と成功）・ログアウト・全端末ログアウト
  const alice = await signup(app);
  secrets.add(alice.password).add(alice.cookie.split('=')[1]!);
  const wrong = randomPassword();
  secrets.add(wrong);
  await post(app, '/login', { email: alice.email, password: wrong }); // login.failure
  const login = await post(app, '/login', { email: alice.email, password: alice.password }); // login.success
  keepCookies(login);
  const cookie = `sid=${login.cookies.find((c) => c.name === 'sid')!.value}`;
  await post(app, '/account/password', { currentPassword: wrong, newPassword: randomPassword() }, { cookie });
  const newPassword = randomPassword();
  secrets.add(newPassword);
  const changed = await post(app, '/account/password', { currentPassword: alice.password, newPassword }, { cookie });
  keepCookies(changed);
  const changedCookie = `sid=${changed.cookies.find((c) => c.name === 'sid')!.value}`;
  await post(app, '/logout', {}, { cookie: changedCookie }); // logout
  const again = await post(app, '/login', { email: alice.email, password: newPassword });
  keepCookies(again);
  await post(app, '/logout/all', {}, { cookie: `sid=${again.cookies.find((c) => c.name === 'sid')!.value}` });

  // ---- パスワード: ロック（account.locked → login.locked）
  const bob = await signup(app);
  secrets.add(bob.password).add(bob.cookie.split('=')[1]!);
  for (let i = 0; i < LOCKOUT_THRESHOLD; i++) {
    const p = randomPassword();
    secrets.add(p);
    await post(app, '/login', { email: bob.email, password: p });
  }
  await post(app, '/login', { email: bob.email, password: bob.password }); // login.locked

  // ---- パスキー: 登録・登録失敗・追加・名前変更・削除・ログイン成功と失敗
  const carolAuth = new SoftAuthenticator(ORIGIN);
  const carol = new TestBrowser(app, ORIGIN);
  await carol.signup(carolAuth, uniqueEmail()); // signup + passkey.register
  keepBrowser(carol);
  const opt = await carol.request('POST', '/passkeys/register/options', {});
  keepBrowser(carol); // 引換券（pk_ceremony）
  const options = opt.json<PublicKeyCredentialCreationOptionsJSON>();
  // 偽サイト（別オリジン）で作られた応答は登録できない → passkey.register.failure
  const evil = new SoftAuthenticator('https://evil.example').register(options);
  await carol.request('POST', '/passkeys/register/verify', { response: evil });
  const second = await carol.request('POST', '/passkeys/register/options', {});
  await carol.request('POST', '/passkeys/register/verify', {
    response: new SoftAuthenticator(ORIGIN).register(second.json<PublicKeyCredentialCreationOptionsJSON>()),
    deviceName: '予備',
  });
  const list = (await carol.request('GET', '/passkeys')).json<{ passkeys: { id: number }[] }>();
  const spare = list.passkeys.at(-1)!.id;
  await carol.request('PATCH', `/passkeys/${spare}`, { deviceName: '予備のキー' }); // passkey.rename
  await carol.request('DELETE', `/passkeys/${spare}`); // passkey.delete
  await carol.request('POST', '/logout', {});
  await carol.login(carolAuth); // passkey.login.success
  keepBrowser(carol);
  const forger = new SoftAuthenticator(ORIGIN);
  const attacker = new TestBrowser(app, ORIGIN, '203.0.113.9');
  await attacker.login(forger, { claimCredentialId: carolAuth.credentialId }); // passkey.login.failure

  // ---- 再認証（パスキーの追加の前の本人確認）: パスワードの失敗と成功、パスキーでの成功
  const erin = await signup(app);
  secrets.add(erin.password).add(erin.cookie.split('=')[1]!);
  const erinWrong = randomPassword();
  secrets.add(erinWrong);
  await post(app, '/account/reauth', { password: erinWrong }, { cookie: erin.cookie }); // reauth.failure
  await post(app, '/account/reauth', { password: erin.password }, { cookie: erin.cookie }); // reauth
  const reauthOpt = await carol.request('POST', '/passkeys/reauth/options', {});
  keepBrowser(carol);
  carolAuth.counter += 1;
  await carol.request('POST', '/passkeys/reauth/verify', {
    response: carolAuth.authenticate(reauthOpt.json<PublicKeyCredentialRequestOptionsJSON>()),
  }); // reauth（method: passkey）

  // ---- パスワード再設定: 依頼・失敗・完了
  await post(app, '/reset', { email: alice.email }); // password.reset.request
  const token = tokenFromMail(await mailer.waitFor(1));
  secrets.add(token);
  await post(app, '/reset/confirm', { token: token.replace(/^./, (c) => (c === 'A' ? 'B' : 'A')), password: randomPassword() });
  const resetPassword = randomPassword();
  secrets.add(resetPassword);
  await post(app, '/reset/confirm', { token, password: resetPassword }); // password.reset.complete

  return secrets;
}

// すべての流れを通すので Argon2id の計算（わざと遅い, S1）が十数回入る。並列で走ると既定の 5 秒を超えることがある
const WALK_TIMEOUT_MS = 30_000;

describe('S12: 監査ログ', () => {
  it('定義したすべてのイベントが、実際の操作で記録される', async () => {
    const mailer = new CaptureMailer();
    const app = await makeApp({ mailer, passkeyRateLimit: { max: 1000, timeWindowMs: 60_000 } });
    try {
      await walkEveryFlow(app, mailer);
      const recorded = new Set(app.db.prepare('SELECT DISTINCT event FROM audit_log').pluck().all() as string[]);
      // 定義にあるのに記録されないイベント（記録漏れ）も、定義に無いイベント（綴りの揺れ）も無い
      expect([...recorded].sort()).toEqual([...AUDIT_EVENTS].sort());
      // どの行にも時刻と IP がある（後から「いつ・どこから」を追えるように）
      const missing = app.db.prepare('SELECT COUNT(*) FROM audit_log WHERE at IS NULL OR ip IS NULL').pluck().get();
      expect(missing).toBe(0);
    } finally {
      await app.close();
    }
  }, WALK_TIMEOUT_MS);

  it('アプリのログ（trace まで）・監査ログ・DB のどこにも、パスワード・セッション ID・引換券・再設定トークンの生値が無い', async () => {
    const stream = new PassThrough();
    const chunks: string[] = [];
    stream.on('data', (c: Buffer) => chunks.push(c.toString('utf8')));
    const mailer = new CaptureMailer();
    const app = await makeApp({ mailer, logStream: stream, passkeyRateLimit: { max: 1000, timeWindowMs: 60_000 } });
    // 既定の LOG_LEVEL（test では silent）だと何も出ないので、最も詳しい trace にして調べる
    app.log.level = 'trace';
    try {
      const secrets = await walkEveryFlow(app, mailer);
      expect(secrets.size).toBeGreaterThan(10);
      const logs = chunks.join('');
      expect(logs).toContain('/reset/confirm'); // ログが実際に出ていることの確認
      const audit = (app.db.prepare('SELECT event, detail FROM audit_log').all() as object[])
        .map((r) => JSON.stringify(r))
        .join('\n');
      const dump = dumpDatabase(app.db);
      for (const secret of secrets) {
        expect(logs).not.toContain(secret);
        expect(audit).not.toContain(secret);
        expect(dump).not.toContain(secret);
      }
    } finally {
      await app.close();
    }
  }, WALK_TIMEOUT_MS);
});
