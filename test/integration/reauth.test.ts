// 人間の判断 2: パスキーの追加には、直近 5 分以内の本人確認（ログイン・パスワード・既存のパスキー）を求める。
// 盗んだ Cookie だけで攻撃者の認証器を登録させないため（threat-model.md §4）。
import { randomBytes } from 'node:crypto';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import type { FastifyInstance, LightMyRequestResponse } from 'fastify';
import type {
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
} from '@simplewebauthn/server';
import { LOCKOUT_THRESHOLD } from '../../src/auth/lockout.js';
import { REAUTH_MAX_AGE_MS } from '../../src/auth/session.js';
import { loadConfig } from '../../src/config.js';
import { openDatabase, type Db } from '../../src/db/connection.js';
import { buildApp } from '../../src/server.js';
import { CaptureMailer, tokenFromMail } from '../helpers/mailer.js';
import { TestBrowser } from '../helpers/passkey-client.js';
import { SoftAuthenticator } from '../helpers/soft-authenticator.js';

const config = loadConfig({ NODE_ENV: 'test', PORT: '3999', DATABASE_PATH: ':memory:' });
const password = () => randomBytes(24).toString('base64url');

describe('パスキー追加の前の再認証（人間の判断 2）', () => {
  let db: Db;
  let app: FastifyInstance;
  let mailer: CaptureMailer;

  beforeEach(async () => {
    db = openDatabase(':memory:');
    mailer = new CaptureMailer();
    app = buildApp(config, {
      db,
      mailer,
      authRateLimit: { max: 1000, timeWindowMs: 60_000 },
      passkeyRateLimit: { max: 1000, timeWindowMs: 60_000 },
    });
    await app.ready();
  });
  afterEach(async () => {
    await app.close();
    db.close();
  });

  /** その人の全セッションの「最後に本人確認した時刻」を、5 分と 1 秒だけ過去にずらす（時間が経った状態を作る） */
  function expireReauth(email: string): void {
    db.prepare(
      `UPDATE sessions SET reauthenticated_at = reauthenticated_at - ?
       WHERE user_id = (SELECT id FROM users WHERE email = ?)`,
    ).run(REAUTH_MAX_AGE_MS + 1000, email);
  }

  const countPasskeys = (email: string) =>
    db
      .prepare('SELECT count(*) FROM credentials WHERE user_id = (SELECT id FROM users WHERE email = ?)')
      .pluck()
      .get(email);

  const lastAudit = () =>
    db.prepare('SELECT event, detail FROM audit_log ORDER BY id DESC LIMIT 1').get() as {
      event: string;
      detail: string;
    };

  /** パスキーの追加を開始し、新しい認証器で応答を作って完了まで送る */
  async function addPasskey(b: TestBrowser): Promise<{ start: LightMyRequestResponse; finish?: LightMyRequestResponse }> {
    const start = await b.request('POST', '/passkeys/register/options', {});
    if (start.statusCode !== 200) return { start };
    const response = new SoftAuthenticator(config.origin).register(start.json<PublicKeyCredentialCreationOptionsJSON>());
    return { start, finish: await b.request('POST', '/passkeys/register/verify', { response, deviceName: '追加' }) };
  }

  async function reauthWithPasskey(b: TestBrowser, auth: SoftAuthenticator): Promise<LightMyRequestResponse> {
    const opt = await b.request('POST', '/passkeys/reauth/options', {});
    expect(opt.statusCode).toBe(200);
    auth.counter += 1;
    const response = auth.authenticate(opt.json<PublicKeyCredentialRequestOptionsJSON>());
    return b.request('POST', '/passkeys/reauth/verify', { response });
  }

  async function passwordUser(email: string): Promise<{ b: TestBrowser; pw: string }> {
    const b = new TestBrowser(app, config.origin);
    const pw = password();
    expect((await b.request('POST', '/signup', { email, password: pw })).statusCode).toBe(201);
    return { b, pw };
  }

  it('ログイン直後（5 分以内）は、ログインそのものを本人確認として追加できる', async () => {
    const { b } = await passwordUser('fresh@example.com');
    const { finish } = await addPasskey(b);
    expect(finish?.statusCode).toBe(200);
    expect(countPasskeys('fresh@example.com')).toBe(1);
  });

  it('本人確認から 5 分を超えると、追加の開始を 403 で断る', async () => {
    const { b } = await passwordUser('stale@example.com');
    expireReauth('stale@example.com');
    const { start } = await addPasskey(b);
    expect(start.statusCode).toBe(403);
    expect(start.json()).toMatchObject({ reason: 'reauth_required' });
    expect(b.cookies.has('pk_ceremony')).toBe(false); // チャレンジも発行しない
    expect(countPasskeys('stale@example.com')).toBe(0);
    expect(lastAudit()).toEqual({ event: 'passkey.register.failure', detail: '{"reason":"reauth_required"}' });
  });

  it('開始の後に 5 分を超えたら、完了も 403 で断る（開始だけ確認しても抜けられない）', async () => {
    const { b } = await passwordUser('mid@example.com');
    const start = await b.request('POST', '/passkeys/register/options', {});
    expect(start.statusCode).toBe(200);
    expireReauth('mid@example.com');
    const response = new SoftAuthenticator(config.origin).register(start.json<PublicKeyCredentialCreationOptionsJSON>());
    const finish = await b.request('POST', '/passkeys/register/verify', { response });
    expect(finish.statusCode).toBe(403);
    expect(finish.json()).toMatchObject({ reason: 'reauth_required' });
    expect(countPasskeys('mid@example.com')).toBe(0);
  });

  it('パスワードで再認証すると追加でき、間違ったパスワードでは確認済みにならない', async () => {
    const { b, pw } = await passwordUser('pw@example.com');
    expireReauth('pw@example.com');

    expect((await b.request('POST', '/account/reauth', { password: password() })).statusCode).toBe(400);
    expect(lastAudit()).toEqual({
      event: 'reauth.failure',
      detail: '{"method":"password","reason":"wrong_password"}',
    });
    expect((await addPasskey(b)).start.statusCode).toBe(403);

    expect((await b.request('POST', '/account/reauth', { password: pw })).statusCode).toBe(200);
    expect(lastAudit()).toEqual({ event: 'reauth', detail: '{"method":"password"}' });
    const { finish } = await addPasskey(b);
    expect(finish?.statusCode).toBe(200);
    expect(countPasskeys('pw@example.com')).toBe(1);
  });

  it('既存のパスキーで再認証すると追加できる（パスキーのみのユーザー）', async () => {
    const auth = new SoftAuthenticator(config.origin);
    const b = new TestBrowser(app, config.origin);
    expect((await b.signup(auth, 'pk@example.com')).statusCode).toBe(200);
    expireReauth('pk@example.com');
    expect((await addPasskey(b)).start.statusCode).toBe(403);

    expect((await reauthWithPasskey(b, auth)).statusCode).toBe(200);
    expect(JSON.parse(lastAudit().detail)).toMatchObject({ method: 'passkey' });
    const { finish } = await addPasskey(b);
    expect(finish?.statusCode).toBe(200);
    expect(countPasskeys('pk@example.com')).toBe(2);
  });

  it('再認証も 5 分で切れる', async () => {
    const { b, pw } = await passwordUser('again@example.com');
    expireReauth('again@example.com');
    expect((await b.request('POST', '/account/reauth', { password: pw })).statusCode).toBe(200);
    expireReauth('again@example.com');
    expect((await addPasskey(b)).start.statusCode).toBe(403);
  });

  it('パスワードのないユーザーはパスワードで再認証できない', async () => {
    const b = new TestBrowser(app, config.origin);
    await b.signup(new SoftAuthenticator(config.origin), 'nopw@example.com');
    expect((await b.request('POST', '/account/reauth', { password: password() })).statusCode).toBe(400);
  });

  it('未ログインでは再認証できない', async () => {
    const anon = new TestBrowser(app, config.origin);
    expect((await anon.request('POST', '/account/reauth', { password: password() })).statusCode).toBe(401);
    expect((await anon.request('POST', '/passkeys/reauth/options', {})).statusCode).toBe(401);
  });

  describe('他人のセッションでは再認証できない', () => {
    it('他人のパスキーで署名しても、自分のセッションの確認にはならない', async () => {
      const aliceAuth = new SoftAuthenticator(config.origin);
      await new TestBrowser(app, config.origin).signup(aliceAuth, 'alice@example.com');
      const bobAuth = new SoftAuthenticator(config.origin);
      const bob = new TestBrowser(app, config.origin);
      await bob.signup(bobAuth, 'bob@example.com');
      expireReauth('bob@example.com');

      // bob のセッションで開始し、alice の認証器で応答する（alice の鍵は本物で、署名も正しい）
      expect((await reauthWithPasskey(bob, aliceAuth)).statusCode).toBe(401);
      expect(JSON.parse(lastAudit().detail)).toMatchObject({ method: 'passkey', kind: 'not_own_credential' });
      expect((await addPasskey(bob)).start.statusCode).toBe(403);
    });

    it('他人のパスワードでは、自分のセッションの確認にはならない', async () => {
      const alice = await passwordUser('alice-pw@example.com');
      const bob = await passwordUser('bob-pw@example.com');
      expireReauth('bob-pw@example.com');
      expect((await bob.b.request('POST', '/account/reauth', { password: alice.pw })).statusCode).toBe(400);
      expect((await addPasskey(bob.b)).start.statusCode).toBe(403);
    });

    it('開始したときと違う人のセッションで完了を送っても通らない', async () => {
      const aliceAuth = new SoftAuthenticator(config.origin);
      const alice = new TestBrowser(app, config.origin);
      await alice.signup(aliceAuth, 'alice2@example.com');
      const bob = new TestBrowser(app, config.origin);
      await bob.signup(new SoftAuthenticator(config.origin), 'bob2@example.com');
      expireReauth('bob2@example.com');

      // alice の引換券（開始）を持ったまま、Cookie だけ bob のセッションに差し替えて完了を送る
      const opt = await alice.request('POST', '/passkeys/reauth/options', {});
      alice.cookies.set('sid', bob.cookies.get('sid')!);
      aliceAuth.counter += 1;
      const response = aliceAuth.authenticate(opt.json<PublicKeyCredentialRequestOptionsJSON>());
      expect((await alice.request('POST', '/passkeys/reauth/verify', { response })).statusCode).toBe(401);
      expect((await addPasskey(bob)).start.statusCode).toBe(403);
    });

    it('確認済みになるのは確認した端末のセッションだけ（同じ人の別の端末には付かない）', async () => {
      const { b: phone, pw } = await passwordUser('two@example.com');
      const laptop = new TestBrowser(app, config.origin);
      expect((await laptop.request('POST', '/login', { email: 'two@example.com', password: pw })).statusCode).toBe(200);
      expireReauth('two@example.com');
      expect((await phone.request('POST', '/account/reauth', { password: pw })).statusCode).toBe(200);
      expect((await addPasskey(laptop)).start.statusCode).toBe(403);
      expect((await addPasskey(phone)).finish?.statusCode).toBe(200);
    });
  });

  it('S9: パスワードでの再認証の失敗はログインと同じ回数に数え、ロック中は正しいパスワードでも確認しない', async () => {
    const { b, pw } = await passwordUser('lock@example.com');
    for (let i = 0; i < LOCKOUT_THRESHOLD; i++) {
      await b.request('POST', '/account/reauth', { password: password() });
    }
    expect((await b.request('POST', '/account/reauth', { password: pw })).statusCode).toBe(429);
  });

  it('パスワードの再設定が済むと、確認済みのセッションも含めて全端末がログアウトされる', async () => {
    const { b, pw } = await passwordUser('reset@example.com');
    const other = new TestBrowser(app, config.origin);
    await other.request('POST', '/login', { email: 'reset@example.com', password: pw });
    expect((await b.request('POST', '/account/reauth', { password: pw })).statusCode).toBe(200);

    await b.request('POST', '/reset', { email: 'reset@example.com' });
    const token = tokenFromMail(await mailer.waitFor(1));
    expect((await b.request('POST', '/reset/confirm', { token, password: password() })).statusCode).toBe(200);
    expect(db.prepare('SELECT count(*) FROM sessions').pluck().get()).toBe(0);
    expect((await b.request('POST', '/passkeys/register/options', {})).statusCode).toBe(400); // 未ログイン扱い
    expect((await other.request('GET', '/passkeys')).statusCode).toBe(401);
  });
});
