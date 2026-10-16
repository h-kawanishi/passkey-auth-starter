// S9: パスキーのログインはアカウント単位のロックの対象外（人間の判断 3）。
// パスキーは推測で当てられないのでロックしても守りは強くならず、ロックは第三者による締め出しにしか効かない。
// パスワードのログインのロックは今までどおり効くことも、ここで合わせて確かめる。
import { randomBytes } from 'node:crypto';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import type { FastifyInstance } from 'fastify';
import type { PublicKeyCredentialCreationOptionsJSON } from '@simplewebauthn/server';
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
    app = buildApp(config, {
      db,
      authRateLimit: { max: 1000, timeWindowMs: 60_000 },
      passkeyRateLimit: { max: 1000, timeWindowMs: 60_000 },
    });
    await app.ready();
  });
  afterEach(async () => {
    await app.close();
    db.close();
  });

  it(`署名の合わない応答を何回送っても（${LOCKOUT_THRESHOLD * 4} 回）、アカウントはロックされず本物の鍵で入れる`, async () => {
    const victimAuth = new SoftAuthenticator(config.origin);
    const victim = new TestBrowser(app, config.origin);
    await victim.signup(victimAuth, 'victim@example.com');
    await victim.request('POST', '/logout', {});

    // 秘密鍵を持たない第三者が、被害者の credential ID を名乗って送り続ける（締め出しの妨害）
    const attacker = new TestBrowser(app, config.origin, '203.0.113.9');
    const forger = new SoftAuthenticator(config.origin);
    for (let i = 0; i < LOCKOUT_THRESHOLD * 4; i++) {
      const res = await attacker.login(forger, { claimCredentialId: victimAuth.credentialId });
      expect(res.statusCode).toBe(401);
    }

    const res = await victim.login(victimAuth);
    expect(res.statusCode).toBe(200);
    expect(victim.cookies.has('sid')).toBe(true);
    expect(events(db)).not.toContain('account.locked');
    // 失敗は login_attempts に数えず、users.locked_until も書かない。監査ログには失敗として残る
    expect(db.prepare('SELECT count(*) FROM login_attempts').pluck().get()).toBe(0);
    expect(db.prepare('SELECT locked_until FROM users').pluck().get()).toBeNull();
    expect(events(db).filter((e) => e === 'passkey.login.failure')).toHaveLength(LOCKOUT_THRESHOLD * 4);
  });

  it('パスキーの失敗を重ねた後でも、パスワードのログインの回数は 0 のまま（経路をまたいでロックさせられない）', async () => {
    const auth = new SoftAuthenticator(config.origin);
    const browser = new TestBrowser(app, config.origin);
    const password = randomBytes(24).toString('base64url');
    expect((await browser.request('POST', '/signup', { email: 'carol@example.com', password })).statusCode).toBe(201);
    // パスワードのユーザーにパスキーを足しておく（登録直後は本人確認から 5 分以内なので追加できる）
    const opt = await browser.request('POST', '/passkeys/register/options', {});
    const response = auth.register(opt.json<PublicKeyCredentialCreationOptionsJSON>());
    expect((await browser.request('POST', '/passkeys/register/verify', { response })).statusCode).toBe(200);
    await browser.request('POST', '/logout', {});

    const attacker = new TestBrowser(app, config.origin, '203.0.113.9');
    const forger = new SoftAuthenticator(config.origin);
    for (let i = 0; i < LOCKOUT_THRESHOLD * 2; i++) {
      await attacker.login(forger, { claimCredentialId: auth.credentialId });
    }
    expect((await browser.request('POST', '/login', { email: 'carol@example.com', password })).statusCode).toBe(200);
  });

  it(`パスワードのログインは ${LOCKOUT_THRESHOLD} 回の失敗でロックされ、ロック中は正しいパスワードでも入れない（今までどおり）`, async () => {
    const browser = new TestBrowser(app, config.origin);
    const password = randomBytes(24).toString('base64url');
    await browser.request('POST', '/signup', { email: 'dave@example.com', password });
    await browser.request('POST', '/logout', {});
    for (let i = 0; i < LOCKOUT_THRESHOLD; i++) {
      const res = await browser.request('POST', '/login', {
        email: 'dave@example.com',
        password: randomBytes(24).toString('base64url'),
      });
      expect(res.statusCode).toBe(401);
    }
    expect((await browser.request('POST', '/login', { email: 'dave@example.com', password })).statusCode).toBe(429);
    expect(events(db)).toEqual(expect.arrayContaining(['account.locked', 'login.locked']));
  });

  it('パスワードの失敗でロック中のアカウントにも、パスキーでは入れる（ロックの対象外）', async () => {
    const auth = new SoftAuthenticator(config.origin);
    const browser = new TestBrowser(app, config.origin);
    await browser.signup(auth, 'alice@example.com');
    await browser.request('POST', '/logout', {});

    // パスキーのみのユーザーにパスワードで試しても、同じ失敗として数えられる（列挙防止のため応答も同じ）
    const attacker = new TestBrowser(app, config.origin, '203.0.113.9');
    for (let i = 0; i < LOCKOUT_THRESHOLD; i++) {
      const res = await attacker.request('POST', '/login', {
        email: 'alice@example.com',
        password: randomBytes(24).toString('base64url'),
      });
      expect(res.statusCode).toBe(401);
    }
    expect(
      (await attacker.request('POST', '/login', { email: 'alice@example.com', password: randomBytes(24).toString('base64url') })).statusCode,
    ).toBe(429);
    expect((await browser.login(auth)).statusCode).toBe(200);
  });

  it('S8: IP ごとのレート制限はパスキーのログインにも残る', async () => {
    const limited = buildApp(config, { db: openDatabase(':memory:'), passkeyRateLimit: { max: 3, timeWindowMs: 60_000 } });
    await limited.ready();
    try {
      const b = new TestBrowser(limited, config.origin, '198.51.100.7');
      const codes: number[] = [];
      for (let i = 0; i < 4; i++) codes.push((await b.request('POST', '/passkeys/login/options', {})).statusCode);
      expect(codes).toEqual([200, 200, 200, 429]);
    } finally {
      await limited.close();
      limited.db.close();
    }
  });
});
