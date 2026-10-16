// パスキーのルートへの妨害・偽装と、本番設定の Cookie を確かめる結合テスト。
// passkey-login.test.ts が「正しく使えること」を見るのに対し、こちらは「悪用されにくいこと」を見る。
import { afterEach, describe, expect, it } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { loadConfig, type Config } from '../../src/config.js';
import { openDatabase, type Db } from '../../src/db/connection.js';
import { buildApp } from '../../src/server.js';
import { TestBrowser } from '../helpers/passkey-client.js';
import { CaptureMailer } from '../helpers/mailer.js';
import { SoftAuthenticator } from '../helpers/soft-authenticator.js';

const testConfig = loadConfig({ NODE_ENV: 'test', PORT: '3999', DATABASE_PATH: ':memory:' });

let db: Db;
let app: FastifyInstance;

async function start(config: Config): Promise<void> {
  db = openDatabase(':memory:');
  // 本番設定では Mailer を渡さないと起動できない（server.ts の chooseMailer）
  app = buildApp(config, { db, mailer: new CaptureMailer() });
  await app.ready();
}

afterEach(async () => {
  await app.close();
  db.close();
});

describe('S8: 開始の要求を大量に送っても、他の利用者のログインは妨げられない', () => {
  it('1 つの IP からの大量の要求は 429 で止まり、被害者の途中のログインはそのまま完了できる', async () => {
    await start(testConfig);
    const auth = new SoftAuthenticator(testConfig.origin);
    const victim = new TestBrowser(app, testConfig.origin, '198.51.100.7');
    await victim.signup(auth, 'victim@example.com');

    const opt = await victim.request('POST', '/passkeys/login/options', {});
    // Origin は文字列の照合なので、ブラウザ以外の道具なら付けられる。攻撃者は正しい Origin を名乗る
    const attacker = new TestBrowser(app, testConfig.origin, '203.0.113.9');
    const codes = new Map<number, number>();
    for (let i = 0; i < 2_000; i++) {
      const { statusCode } = await attacker.request('POST', '/passkeys/login/options', {});
      codes.set(statusCode, (codes.get(statusCode) ?? 0) + 1);
    }
    expect(codes.get(429)).toBeGreaterThan(1_900);

    auth.counter += 1;
    const response = auth.authenticate(opt.json());
    expect((await victim.request('POST', '/passkeys/login/verify', { response })).statusCode).toBe(200);
  });

  it('多数の IP から置き場を埋めても、被害者のチャレンジは押し出されない（新しい要求が 503 になる）', async () => {
    await start(testConfig);
    const auth = new SoftAuthenticator(testConfig.origin);
    const victim = new TestBrowser(app, testConfig.origin, '198.51.100.7');
    await victim.signup(auth, 'victim@example.com');
    const opt = await victim.request('POST', '/passkeys/login/options', {});

    // 1 つの IP が持てる未使用のチャレンジは 20 個。600 か所 × 20 = 12,000 で全体の上限（10,000）を超える
    let unavailable = 0;
    for (let n = 0; n < 600; n++) {
      const bot = new TestBrowser(app, testConfig.origin, `10.0.${Math.floor(n / 250)}.${n % 250}`);
      for (let i = 0; i < 20; i++) {
        if ((await bot.request('POST', '/passkeys/login/options', {})).statusCode === 503) unavailable += 1;
      }
    }
    expect(unavailable).toBeGreaterThan(0);

    auth.counter += 1;
    const response = auth.authenticate(opt.json());
    expect((await victim.request('POST', '/passkeys/login/verify', { response })).statusCode).toBe(200);
  }, 60_000);
});

describe('S6: 巻き戻りの記録は、署名が本物のときだけ', () => {
  it('秘密鍵を持たない第三者が被害者の credential ID で巻き戻ったカウンタを送っても counter_rollback にならない', async () => {
    await start(testConfig);
    const victimAuth = new SoftAuthenticator(testConfig.origin);
    const victim = new TestBrowser(app, testConfig.origin);
    await victim.signup(victimAuth, 'victim@example.com');
    await victim.request('POST', '/logout', {});
    expect((await victim.login(victimAuth)).statusCode).toBe(200); // 保存カウンタが 1 になる

    const attacker = new TestBrowser(app, testConfig.origin, '203.0.113.9');
    const forger = new SoftAuthenticator(testConfig.origin);
    forger.counter = -1; // login() が +1 して 0 になる
    const res = await attacker.login(forger, { claimCredentialId: victimAuth.credentialId });
    expect(res.statusCode).toBe(401);

    const last = db.prepare('SELECT event, detail FROM audit_log ORDER BY id DESC LIMIT 1').get() as {
      event: string;
      detail: string;
    };
    expect(last.event).toBe('passkey.login.failure');
    expect(JSON.parse(last.detail)).toMatchObject({ kind: 'bad_signature' });
  });
});

describe('S7: 本番設定のセッション Cookie', () => {
  it('__Host-sid で、Secure・HttpOnly・SameSite=Lax・Path=/ を持ち、Domain を持たない', async () => {
    const config = loadConfig({
      NODE_ENV: 'production',
      PORT: '3999',
      ORIGIN: 'https://example.com',
      RP_ID: 'example.com',
      SESSION_SECRET: 'x'.repeat(32), // テスト専用の値。本物の秘密ではない
      DATABASE_PATH: ':memory:',
      LOG_LEVEL: 'silent',
    });
    await start(config);
    const browser = new TestBrowser(app, config.origin);
    const res = await browser.signup(new SoftAuthenticator(config.origin), 'a@example.com');
    expect(res.statusCode).toBe(200);

    const setCookie = ([] as string[]).concat(res.headers['set-cookie'] ?? []);
    const sid = setCookie.find((c) => c.startsWith('__Host-sid='));
    expect(sid).toBeDefined();
    const attrs = (sid ?? '').split('; ').slice(1);
    expect(attrs).toEqual(expect.arrayContaining(['Secure', 'HttpOnly', 'SameSite=Lax', 'Path=/']));
    expect(sid).not.toMatch(/Domain=/i);
    // 引換券の Cookie も本番では Secure
    expect(setCookie.find((c) => c.startsWith('pk_ceremony='))).toMatch(/; Secure/);
  });
});
