import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { loadConfig } from '../../src/config.js';
import { openDatabase, type Db } from '../../src/db/connection.js';
import { buildApp } from '../../src/server.js';
import { TestBrowser } from '../helpers/passkey-client.js';
import { SoftAuthenticator } from '../helpers/soft-authenticator.js';

const config = loadConfig({ NODE_ENV: 'test', PORT: '3999', DATABASE_PATH: ':memory:' });

/** DB の全テーブル・全列を 1 つの文字列にする。生値が紛れ込んでいないかを調べるため */
function dumpDb(db: Db): string {
  const tables = db.prepare("SELECT name FROM sqlite_master WHERE type = 'table'").pluck().all() as string[];
  return tables
    .map((t) =>
      JSON.stringify(db.prepare(`SELECT * FROM "${t}"`).all(), (_k, v: unknown) =>
        Buffer.isBuffer(v) ? v.toString('base64url') + v.toString('hex') : v,
      ),
    )
    .join('\n');
}

function auditEvents(db: Db): { event: string; detail: string; user_id: number | null }[] {
  return db.prepare('SELECT event, detail, user_id FROM audit_log ORDER BY id').all() as {
    event: string;
    detail: string;
    user_id: number | null;
  }[];
}

describe('パスキーでの登録とログイン（結合）', () => {
  let db: Db;
  let app: FastifyInstance;
  let browser: TestBrowser;

  beforeEach(async () => {
    db = openDatabase(':memory:');
    app = buildApp(config, { db });
    await app.ready();
    browser = new TestBrowser(app, config.origin);
  });
  afterEach(async () => {
    await app.close();
    db.close();
  });

  it('パスキーで登録 → ログアウト → パスキーでログインできる', async () => {
    const auth = new SoftAuthenticator(config.origin);
    const signup = await browser.signup(auth, ' Alice@Example.com ');
    expect(signup.statusCode).toBe(200);
    expect((await browser.request('GET', '/passkeys')).json()).toMatchObject({
      email: 'alice@example.com',
      hasPassword: false,
      passkeys: [{ deviceName: 'パスキー' }],
    });

    expect((await browser.request('POST', '/logout', {})).statusCode).toBe(200);
    expect((await browser.request('GET', '/passkeys')).statusCode).toBe(401);

    const login = await browser.login(auth);
    expect(login.statusCode).toBe(200);
    const list = (await browser.request('GET', '/passkeys')).json<{ passkeys: { lastUsedAt: number }[] }>();
    expect(list.passkeys[0]?.lastUsedAt).toBeTypeOf('number');

    expect(auditEvents(db).map((e) => e.event)).toEqual([
      'signup',
      'passkey.register',
      'logout',
      'passkey.login.success',
    ]);
  });

  it('S7: セッション Cookie は HttpOnly + SameSite=Lax で、DB には生の ID が残らない', async () => {
    const res = await browser.signup(new SoftAuthenticator(config.origin), 'a@example.com');
    const setCookie = ([] as string[]).concat(res.headers['set-cookie'] ?? []);
    const sid = setCookie.find((c) => c.startsWith('sid='));
    expect(sid).toMatch(/HttpOnly/);
    expect(sid).toMatch(/SameSite=Lax/);
    // 開発・テストは http なので Secure は付かない（本番の __Host-sid と Secure は passkey-hardening.test.ts で確かめている）
    expect(sid).not.toMatch(/Secure/);

    const rawId = browser.cookies.get('sid');
    expect(rawId).toBeDefined();
    // 256bit = 32 バイト = base64url で 43 文字
    expect(rawId).toHaveLength(43);
    expect(dumpDb(db)).not.toContain(rawId);
  });

  it('S6: 署名カウンタが巻き戻った応答ではログインできず、監査ログに種類が残る', async () => {
    const auth = new SoftAuthenticator(config.origin);
    await browser.signup(auth, 'a@example.com');
    await browser.request('POST', '/logout', {});
    expect((await browser.login(auth)).statusCode).toBe(200); // カウンタ 1 を保存
    await browser.request('POST', '/logout', {});

    auth.counter = -1; // login() が +1 して 0 になる＝巻き戻り
    const res = await browser.login(auth);
    expect(res.statusCode).toBe(401);
    expect(browser.cookies.has('sid')).toBe(false);
    const last = auditEvents(db).at(-1);
    expect(last?.event).toBe('passkey.login.failure');
    expect(JSON.parse(last?.detail ?? '{}')).toMatchObject({ kind: 'counter_rollback' });
  });

  it('他人の credential ID を名乗った応答ではログインできない', async () => {
    const alice = new SoftAuthenticator(config.origin);
    const bob = new SoftAuthenticator(config.origin);
    await new TestBrowser(app, config.origin).signup(alice, 'alice@example.com');
    await new TestBrowser(app, config.origin).signup(bob, 'bob@example.com');

    // 「自分の鍵で署名して、他人の鍵の ID を名乗る」攻撃を再現する。サーバーが ID の持ち主の公開鍵で検証していれば通らない
    const res = await browser.login(alice, { claimCredentialId: bob.credentialId });
    expect(res.statusCode).toBe(401);
    expect(res.json()).toEqual({ message: 'パスキーでログインできませんでした。' });
    expect(browser.cookies.has('sid')).toBe(false);
  });

  it('登録されていない鍵の応答も、署名違いと同じ応答で拒否する（手がかりを与えない）', async () => {
    const res = await browser.login(new SoftAuthenticator(config.origin));
    expect(res.statusCode).toBe(401);
    expect(res.json()).toEqual({ message: 'パスキーでログインできませんでした。' });
  });

  it('同じ認証応答をもう一度送っても通らない（チャレンジは使い切り）', async () => {
    const auth = new SoftAuthenticator(config.origin);
    await browser.signup(auth, 'a@example.com');
    const opt = await browser.request('POST', '/passkeys/login/options', {});
    auth.counter = 5;
    const response = auth.authenticate(opt.json());
    const ticket = browser.cookies.get('pk_ceremony') ?? '';
    expect((await browser.request('POST', '/passkeys/login/verify', { response })).statusCode).toBe(200);
    // 盗み見た応答を後から送り直す（リプレイ）攻撃を再現するため、消された引換券の Cookie を戻して再送する
    browser.cookies.set('pk_ceremony', ticket);
    expect((await browser.request('POST', '/passkeys/login/verify', { response })).statusCode).toBe(400);
  });

  it('S13: Origin が無い・違う POST は 403', async () => {
    const other = new TestBrowser(app, 'https://evil.example');
    expect((await other.request('POST', '/passkeys/login/options', {})).statusCode).toBe(403);
    const res = await app.inject({ method: 'POST', url: '/passkeys/register/options', payload: {} });
    expect(res.statusCode).toBe(403);
    expect((await other.request('POST', '/logout', {})).statusCode).toBe(403);
  });

  it('登録済みのメールではパスキーの新規登録ができない', async () => {
    await browser.signup(new SoftAuthenticator(config.origin), 'a@example.com');
    const res = await new TestBrowser(app, config.origin).signup(
      new SoftAuthenticator(config.origin),
      'a@example.com',
    );
    expect(res.statusCode).toBe(409);
  });
});
