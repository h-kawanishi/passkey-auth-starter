import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { PassThrough } from 'node:stream';
import { afterEach, describe, expect, it } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { randomBytes } from 'node:crypto';
import { LOCKOUT_THRESHOLD } from '../../src/auth/lockout.js';
import { loadConfig } from '../../src/config.js';
import { buildApp } from '../../src/server.js';
import type { Db } from '../../src/db/connection.js';
import { body, makeApp, post, randomPassword, sessionCookie, signup, uniqueEmail } from '../helpers/app.js';

/** DB の全テーブル・全列の値を 1 つの文字列にする。BLOB は UTF-8 としても 16 進としても含める */
function dumpDatabase(db: Db): string {
  const tables = db
    .prepare("SELECT name FROM sqlite_master WHERE type = 'table'")
    .pluck()
    .all() as string[];
  const parts: string[] = [];
  for (const table of tables) {
    for (const row of db.prepare(`SELECT * FROM "${table}"`).all() as Record<string, unknown>[]) {
      for (const value of Object.values(row)) {
        if (Buffer.isBuffer(value)) parts.push(value.toString('utf8'), value.toString('hex'));
        else parts.push(String(value));
      }
    }
  }
  return parts.join('\n');
}

let app: FastifyInstance | undefined;
afterEach(async () => {
  await app?.close();
  app = undefined;
});

describe('S1: 平文で保存しない', () => {
  it('登録・ログイン・パスワード変更のあと、DB のどこにもパスワードの文字列が無い', async () => {
    app = await makeApp();
    const { email, password, cookie } = await signup(app);
    await post(app, '/login', { email, password: randomPassword() });
    const newPassword = randomPassword();
    await post(app, '/account/password', { currentPassword: password, newPassword }, { cookie });
    const login = await post(app, '/login', { email, password: newPassword });
    const rawSessionId = sessionCookie(login).split('=')[1]!;

    const dump = dumpDatabase(app.db);
    expect(dump).toContain(email); // ダンプが空でないことの確認
    expect(dump).not.toContain(password);
    expect(dump).not.toContain(newPassword);
    // S7: セッション ID の生値も保存しない
    expect(dump).not.toContain(rawSessionId);
    expect(dump).not.toContain(Buffer.from(rawSessionId).toString('hex'));
  });
});

describe('S3: 漏えい済みパスワード', () => {
  it('一覧にあるパスワードでは登録できず、理由が示される', async () => {
    app = await makeApp();
    const list = readFileSync(
      join(import.meta.dirname, '../../src/auth/breached-passwords.txt'),
      'utf8',
    );
    const leaked = list.split('\n').find((l) => !l.startsWith('#') && l.length >= 15)!;
    const res = await post(app, '/signup', { email: uniqueEmail(), password: leaked });
    expect(res.statusCode).toBe(400);
    expect(body(res).reason).toBe('breached');
    expect(body(res).message).toContain('漏えい');
  });
});

describe('S7: セッション Cookie', () => {
  it('HttpOnly と SameSite=Lax が付き、ID は 256bit の乱数（43 文字の base64url）', async () => {
    app = await makeApp();
    const res = await post(app, '/signup', { email: uniqueEmail(), password: randomPassword() });
    const header = String(res.headers['set-cookie']);
    expect(header).toMatch(/HttpOnly/i);
    expect(header).toMatch(/SameSite=Lax/i);
    // 開発・テストは http なので Secure を付けない（本番の Secure は config のテストで確かめる）
    expect(header).not.toMatch(/Secure/i);
    expect(sessionCookie(res).split('=')[1]).toMatch(/^[A-Za-z0-9_-]{43}$/);
  });

  it('本番では Secure と __Host- 接頭辞が付く', async () => {
    const origin = 'https://login.example.com';
    app = buildApp(
      loadConfig({
        NODE_ENV: 'production',
        RP_ID: 'example.com',
        ORIGIN: origin,
        SESSION_SECRET: randomBytes(32).toString('base64url'),
        DATABASE_PATH: ':memory:',
        LOG_LEVEL: 'silent',
      }),
    );
    const res = await post(app, '/signup', { email: uniqueEmail(), password: randomPassword() }, { origin });
    expect(res.statusCode).toBe(201);
    const header = String(res.headers['set-cookie']);
    expect(header).toMatch(/^__Host-sid=/);
    expect(header).toMatch(/; Secure/i);
    expect(header).toMatch(/HttpOnly/i);
    expect(header).toMatch(/Path=\//);
  });

  it('でたらめな Cookie ではログイン扱いにならない', async () => {
    app = await makeApp();
    const me = await app.inject({
      method: 'GET',
      url: '/account/me',
      headers: { cookie: `sid=${randomPassword(43)}` },
    });
    expect(me.statusCode).toBe(401);
  });
});

describe('S8: IP ごとのレート制限', () => {
  it('上限を超えたログイン要求は 429 で止める', async () => {
    app = await makeApp({ authRateLimit: { max: 3, timeWindowMs: 60_000 } });
    const codes: number[] = [];
    for (let i = 0; i < 4; i++) {
      codes.push((await post(app, '/login', { email: uniqueEmail(), password: randomPassword() })).statusCode);
    }
    expect(codes).toEqual([401, 401, 401, 429]);
  });
});

describe('S8/S9: 連続失敗でのロック', () => {
  it(`${LOCKOUT_THRESHOLD} 回続けて失敗するとロックし、ロック中は正しいパスワードでも入れない`, async () => {
    app = await makeApp();
    const { email, password } = await signup(app);
    for (let i = 0; i < LOCKOUT_THRESHOLD; i++) {
      expect((await post(app, '/login', { email, password: randomPassword() })).statusCode).toBe(401);
    }
    const res = await post(app, '/login', { email, password });
    expect(res.statusCode).toBe(429);
    expect(res.cookies.find((c) => c.name === 'sid')).toBeUndefined();

    const events = app.db.prepare('SELECT event FROM audit_log ORDER BY id').pluck().all();
    expect(events).toContain('account.locked');
    expect(events).toContain('login.locked');
  });

  it('列挙防止: 存在しないメールでも同じ回数で同じロックの応答になる', async () => {
    app = await makeApp();
    const { email } = await signup(app);
    const ghost = uniqueEmail();
    for (let i = 0; i < LOCKOUT_THRESHOLD; i++) {
      await post(app, '/login', { email, password: randomPassword() });
      await post(app, '/login', { email: ghost, password: randomPassword() });
    }
    const real = await post(app, '/login', { email, password: randomPassword() });
    const fake = await post(app, '/login', { email: ghost, password: randomPassword() });
    expect(real.statusCode).toBe(429);
    expect(fake.statusCode).toBe(real.statusCode);
    expect(fake.body).toBe(real.body);
  });
});

describe('S13: Origin ヘッダ検証', () => {
  it('Origin が異なる POST、Origin の無い POST は拒否する', async () => {
    app = await makeApp();
    const { email, password, cookie } = await signup(app);
    const evil = await post(app, '/login', { email, password }, { origin: 'https://evil.example' });
    expect(evil.statusCode).toBe(403);
    const none = await post(app, '/login', { email, password }, { origin: null });
    expect(none.statusCode).toBe(403);
    // ログイン済みの Cookie を持っていても、他サイトからの状態変更は通さない
    const logoutAll = await post(app, '/logout/all', {}, { cookie, origin: 'https://evil.example' });
    expect(logoutAll.statusCode).toBe(403);
    const me = await app.inject({ method: 'GET', url: '/account/me', headers: { cookie } });
    expect(me.statusCode).toBe(200);
  });
});

describe('S12: ログと監査ログに生値を書かない', () => {
  it('アプリのログ・監査ログのどちらにもパスワードとセッション ID が出ない', async () => {
    const stream = new PassThrough();
    const chunks: string[] = [];
    stream.on('data', (c: Buffer) => chunks.push(c.toString('utf8')));
    app = await makeApp({ logStream: stream });
    // 既定の LOG_LEVEL（test では silent）だと何も出ないので、最も詳しい trace にして調べる
    app.log.level = 'trace';

    const { email, password, cookie } = await signup(app);
    const wrong = randomPassword();
    await post(app, '/login', { email, password: wrong });
    await post(app, '/login', { email: uniqueEmail(), password: wrong });
    const login = await post(app, '/login', { email, password });
    const rawSessionId = sessionCookie(login).split('=')[1]!;
    await post(app, '/logout', {}, { cookie });

    const logs = chunks.join('');
    expect(logs.length).toBeGreaterThan(0);
    const audit = (app.db.prepare('SELECT event, detail FROM audit_log').all() as object[])
      .map((r) => JSON.stringify(r))
      .join('\n');
    expect(audit).toContain('login.failure');
    expect(audit).toContain('login.success');
    expect(audit).toContain('logout');
    for (const secret of [password, wrong, rawSessionId, cookie.split('=')[1]!]) {
      expect(logs).not.toContain(secret);
      expect(audit).not.toContain(secret);
    }
  });
});
