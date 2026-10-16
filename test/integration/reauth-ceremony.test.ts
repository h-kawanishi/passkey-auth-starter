// 引換券（ChallengeStore の使い切りの乱数）が、再認証とパスキー追加で正しく効いているかの試験。
// take() は取り出した時点で消し、種類（kind）が違えば渡さない。人間の判断 2 で足した kind 'reauth' の分離と、
// 再送・完了だけの直接送信を、HTTP の経路で確かめる（ChallengeStore 単体の試験は test/unit/challenges.test.ts）。
import { randomBytes } from 'node:crypto';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import type { FastifyInstance } from 'fastify';
import type { PublicKeyCredentialRequestOptionsJSON } from '@simplewebauthn/server';
import { loadConfig } from '../../src/config.js';
import { openDatabase, type Db } from '../../src/db/connection.js';
import { buildApp } from '../../src/server.js';
import { CaptureMailer } from '../helpers/mailer.js';
import { TestBrowser } from '../helpers/passkey-client.js';
import { addPasskeyWith, countPasskeysOf, expireReauthOf } from '../helpers/reauth.js';
import { SoftAuthenticator } from '../helpers/soft-authenticator.js';

const config = loadConfig({ NODE_ENV: 'test', PORT: '3999', DATABASE_PATH: ':memory:' });
const password = () => randomBytes(24).toString('base64url');

describe('パスキー追加・再認証の引換券（チャレンジ）の使い回し・取り違え・省略', () => {
  let db: Db;
  let app: FastifyInstance;

  beforeEach(async () => {
    db = openDatabase(':memory:');
    app = buildApp(config, {
      db,
      mailer: new CaptureMailer(),
      authRateLimit: { max: 1000, timeWindowMs: 60_000 },
      passkeyRateLimit: { max: 1000, timeWindowMs: 60_000 },
    });
    await app.ready();
  });
  afterEach(async () => {
    await app.close();
    db.close();
  });

  const expireReauth = (email: string) => expireReauthOf(db, email);
  const countPasskeys = (email: string) => countPasskeysOf(db, email);
  const addPasskey = (b: TestBrowser) => addPasskeyWith(b, config.origin);

  async function passkeyUser(email: string): Promise<{ b: TestBrowser; auth: SoftAuthenticator }> {
    const auth = new SoftAuthenticator(config.origin);
    const b = new TestBrowser(app, config.origin);
    expect((await b.signup(auth, email)).statusCode).toBe(200);
    return { b, auth };
  }

  it('成功した本人確認の応答を、同じ引換券の Cookie ごと再送しても確認済みにならない', async () => {
    const { b, auth } = await passkeyUser('replay@example.com');
    expireReauth('replay@example.com');

    const opt = await b.request('POST', '/passkeys/reauth/options', {});
    expect(opt.statusCode).toBe(200);
    const ticket = b.cookies.get('pk_ceremony')!;
    auth.counter += 1;
    const response = auth.authenticate(opt.json<PublicKeyCredentialRequestOptionsJSON>());
    expect((await b.request('POST', '/passkeys/reauth/verify', { response })).statusCode).toBe(200);

    expireReauth('replay@example.com');
    // 完了で消された Cookie を、盗み見た値で戻して同じ応答を送る（リプレイ）
    b.cookies.set('pk_ceremony', ticket);
    expect((await b.request('POST', '/passkeys/reauth/verify', { response })).statusCode).toBe(400);
    expect((await addPasskey(b)).start.statusCode).toBe(403);
    expect(countPasskeys('replay@example.com')).toBe(1);
  });

  it('ログイン用の引換券とそれへの署名は、再認証には使えない', async () => {
    const { b, auth } = await passkeyUser('kind@example.com');
    expireReauth('kind@example.com');

    const opt = await b.request('POST', '/passkeys/login/options', {});
    expect(opt.statusCode).toBe(200);
    auth.counter += 1;
    const response = auth.authenticate(opt.json<PublicKeyCredentialRequestOptionsJSON>());
    expect((await b.request('POST', '/passkeys/reauth/verify', { response })).statusCode).toBe(400);
    expect((await addPasskey(b)).start.statusCode).toBe(403);
  });

  it('本人確認の切れたセッションで、開始を呼ばずに完了だけ送っても追加できない', async () => {
    const b = new TestBrowser(app, config.origin);
    const signup = await b.request('POST', '/signup', { email: 'skip@example.com', password: password() });
    expect(signup.statusCode).toBe(201);
    expireReauth('skip@example.com');

    // 引換券を持たないまま、それらしい登録の応答を自分で作って完了だけを送る
    const response = new SoftAuthenticator(config.origin).register({
      challenge: randomBytes(32).toString('base64url'),
      rp: { id: config.rpId, name: 'x' },
      user: { id: randomBytes(16).toString('base64url'), name: 'skip@example.com', displayName: 'skip' },
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
    });
    expect(b.cookies.has('pk_ceremony')).toBe(false);
    const finish = await b.request('POST', '/passkeys/register/verify', { response, deviceName: '追加' });
    expect(finish.statusCode).toBe(400);
    expect(countPasskeys('skip@example.com')).toBe(0);
  });
});
