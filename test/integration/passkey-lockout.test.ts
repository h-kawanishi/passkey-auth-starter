// S8 / S9: パスキーのログインにも、パスワードと同じアカウント単位のロックが掛かることを確かめる。
// 経路ごとに別々に数えると、片方がロックされている間にもう片方で試し続けられるため、合わせて数えることを確かめる
import { randomBytes } from 'node:crypto';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { LOCKOUT_THRESHOLD } from '../../src/auth/lockout.js';
import { loadConfig } from '../../src/config.js';
import { openDatabase, type Db } from '../../src/db/connection.js';
import { buildApp } from '../../src/server.js';
import { TestBrowser } from '../helpers/passkey-client.js';
import { SoftAuthenticator } from '../helpers/soft-authenticator.js';

const config = loadConfig({ NODE_ENV: 'test', PORT: '3999', DATABASE_PATH: ':memory:' });

function events(db: Db): string[] {
  return db.prepare('SELECT event FROM audit_log ORDER BY id').pluck().all() as string[];
}

describe('パスキーのログインとロック（S9）', () => {
  let db: Db;
  let app: FastifyInstance;

  beforeEach(async () => {
    db = openDatabase(':memory:');
    // IP の制限（S8）に先に当たらないよう、この試験では十分大きくする
    app = buildApp(config, { db, passkeyRateLimit: { max: 1000, timeWindowMs: 60_000 } });
    await app.ready();
  });
  afterEach(async () => {
    await app.close();
    db.close();
  });

  it(`署名の合わない応答が ${LOCKOUT_THRESHOLD} 回続くとロックし、ロック中は本物の鍵でも入れない`, async () => {
    const victimAuth = new SoftAuthenticator(config.origin);
    const victim = new TestBrowser(app, config.origin);
    await victim.signup(victimAuth, 'victim@example.com');
    await victim.request('POST', '/logout', {});

    // 秘密鍵を持たない第三者が、被害者の credential ID を名乗って送り続ける
    const attacker = new TestBrowser(app, config.origin, '203.0.113.9');
    const forger = new SoftAuthenticator(config.origin);
    for (let i = 0; i < LOCKOUT_THRESHOLD; i++) {
      const res = await attacker.login(forger, { claimCredentialId: victimAuth.credentialId });
      expect(res.statusCode).toBe(401);
    }

    const res = await victim.login(victimAuth);
    expect(res.statusCode).toBe(429);
    expect(victim.cookies.has('sid')).toBe(false);
    expect(events(db)).toEqual(expect.arrayContaining(['account.locked', 'passkey.login.locked']));
    // ロック中は署名を検証しないので、カウンタも最終利用日時も進まない
    const row = db.prepare('SELECT counter, last_used_at FROM credentials').get() as {
      counter: number;
      last_used_at: number | null;
    };
    expect(row).toEqual({ counter: 0, last_used_at: null });
  });

  it('パスワードの失敗とパスキーの失敗は同じアカウントの回数として数える（経路を変えて試し続けられない）', async () => {
    const auth = new SoftAuthenticator(config.origin);
    const browser = new TestBrowser(app, config.origin);
    await browser.signup(auth, 'alice@example.com');
    await browser.request('POST', '/logout', {});

    // パスキーのみのユーザーにパスワードで試しても、同じ失敗として数えられる（列挙防止のため応答も同じ）
    for (let i = 0; i < LOCKOUT_THRESHOLD; i++) {
      const res = await browser.request('POST', '/login', {
        email: 'alice@example.com',
        password: randomBytes(24).toString('base64url'),
      });
      expect(res.statusCode).toBe(401);
    }
    expect((await browser.login(auth)).statusCode).toBe(429);
  });

  it('成功したログインで失敗の回数は 0 に戻る', async () => {
    const auth = new SoftAuthenticator(config.origin);
    const browser = new TestBrowser(app, config.origin);
    await browser.signup(auth, 'bob@example.com');
    await browser.request('POST', '/logout', {});
    const forger = new SoftAuthenticator(config.origin);
    const attacker = new TestBrowser(app, config.origin, '203.0.113.9');

    for (let i = 0; i < LOCKOUT_THRESHOLD - 1; i++) {
      await attacker.login(forger, { claimCredentialId: auth.credentialId });
    }
    expect((await browser.login(auth)).statusCode).toBe(200);
    await browser.request('POST', '/logout', {});
    await attacker.login(forger, { claimCredentialId: auth.credentialId });
    expect((await browser.login(auth)).statusCode).toBe(200);
  });
});
