import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import type { FastifyInstance } from 'fastify';
import type { PublicKeyCredentialCreationOptionsJSON } from '@simplewebauthn/server';
import { loadConfig } from '../../src/config.js';
import { openDatabase, type Db } from '../../src/db/connection.js';
import { buildApp } from '../../src/server.js';
import { TestBrowser } from '../helpers/passkey-client.js';
import { SoftAuthenticator } from '../helpers/soft-authenticator.js';

const config = loadConfig({ NODE_ENV: 'test', PORT: '3999', DATABASE_PATH: ':memory:' });

type ListBody = { passkeys: { id: number; deviceName: string }[] };

describe('パスキーの追加・一覧・名前変更・削除（結合）', () => {
  let db: Db;
  let app: FastifyInstance;
  let alice: TestBrowser;

  beforeEach(async () => {
    db = openDatabase(':memory:');
    app = buildApp(config, { db });
    await app.ready();
    alice = new TestBrowser(app, config.origin);
    await alice.signup(new SoftAuthenticator(config.origin), 'alice@example.com');
  });
  afterEach(async () => {
    await app.close();
    db.close();
  });

  async function addPasskey(browser: TestBrowser, deviceName: string) {
    const opt = await browser.request('POST', '/passkeys/register/options', {});
    const options = opt.json<PublicKeyCredentialCreationOptionsJSON>();
    const auth = new SoftAuthenticator(config.origin);
    return { options, res: await browser.request('POST', '/passkeys/register/verify', {
      response: auth.register(options),
      deviceName,
    }) };
  }

  const list = async (b: TestBrowser) => (await b.request('GET', '/passkeys')).json<ListBody>().passkeys;

  it('ログイン中は既存アカウントにパスキーを追加でき、登録済みの鍵は除外リストに入る', async () => {
    const { options, res } = await addPasskey(alice, '  仕事用ノートPC  ');
    expect(res.statusCode).toBe(200);
    expect(options.excludeCredentials).toHaveLength(1);
    expect((await list(alice)).map((p) => p.deviceName)).toEqual(['パスキー', '仕事用ノートPC']);
  });

  it('一覧に公開鍵や credential ID を出さない', async () => {
    const body = (await alice.request('GET', '/passkeys')).json<{ passkeys: object[] }>();
    expect(Object.keys(body.passkeys[0] ?? {}).sort()).toEqual(['createdAt', 'deviceName', 'id', 'lastUsedAt']);
  });

  it('名前を変えられる。長すぎる名前は 64 文字で切る', async () => {
    const [pk] = await list(alice);
    const res = await alice.request('PATCH', `/passkeys/${pk?.id}`, { deviceName: 'あ'.repeat(100) });
    expect(res.statusCode).toBe(200);
    expect((await list(alice))[0]?.deviceName).toBe('あ'.repeat(64));
  });

  it('パスワードを持たない人は最後のパスキーを削除できない（締め出し防止）', async () => {
    const [pk] = await list(alice);
    expect((await alice.request('DELETE', `/passkeys/${pk?.id}`)).statusCode).toBe(409);
    await addPasskey(alice, '2 本目');
    expect((await alice.request('DELETE', `/passkeys/${pk?.id}`)).statusCode).toBe(200);
    expect((await list(alice)).map((p) => p.deviceName)).toEqual(['2 本目']);
    expect(db.prepare("SELECT count(*) FROM audit_log WHERE event = 'passkey.delete'").pluck().get()).toBe(1);
  });

  it('他人のパスキーは名前変更も削除もできない（自分のものでなければ 404）', async () => {
    const bob = new TestBrowser(app, config.origin);
    await bob.signup(new SoftAuthenticator(config.origin), 'bob@example.com');
    await addPasskey(bob, 'bob 2');
    const [alicePk] = await list(alice);

    expect((await bob.request('PATCH', `/passkeys/${alicePk?.id}`, { deviceName: 'x' })).statusCode).toBe(404);
    expect((await bob.request('DELETE', `/passkeys/${alicePk?.id}`)).statusCode).toBe(404);
    expect((await list(alice))[0]?.deviceName).toBe('パスキー');
  });

  it('未ログインでは一覧・変更・削除・追加ができない', async () => {
    const anon = new TestBrowser(app, config.origin);
    expect((await anon.request('GET', '/passkeys')).statusCode).toBe(401);
    expect((await anon.request('PATCH', '/passkeys/1', { deviceName: 'x' })).statusCode).toBe(401);
    expect((await anon.request('DELETE', '/passkeys/1')).statusCode).toBe(401);
    // 未ログインの登録開始は「新規登録」扱いなので、メールが無ければ 400
    expect((await anon.request('POST', '/passkeys/register/options', {})).statusCode).toBe(400);
  });

  it('S13: Origin の違う PATCH / DELETE は 403', async () => {
    const [pk] = await list(alice);
    const headers = { origin: 'https://evil.example' };
    expect((await alice.request('PATCH', `/passkeys/${pk?.id}`, { deviceName: 'x' }, headers)).statusCode).toBe(403);
    expect((await alice.request('DELETE', `/passkeys/${pk?.id}`, undefined, headers)).statusCode).toBe(403);
  });

  it('アカウント設定画面は未ログインならログイン画面へ送る', async () => {
    const anon = new TestBrowser(app, config.origin);
    const res = await anon.request('GET', '/account');
    expect(res.statusCode).toBe(303);
    expect(res.headers.location).toBe('/login');
    expect((await alice.request('GET', '/account')).statusCode).toBe(200);
  });

  it('S12: 監査ログにセッション ID・公開鍵・credential ID の生値が入らない', () => {
    const sid = alice.cookies.get('sid') ?? '';
    const cred = db.prepare('SELECT credential_id, public_key FROM credentials').get() as {
      credential_id: Buffer;
      public_key: Buffer;
    };
    const log = JSON.stringify(db.prepare('SELECT * FROM audit_log').all());
    expect(sid).not.toBe('');
    for (const secret of [
      sid,
      cred.credential_id.toString('base64url'),
      cred.credential_id.toString('hex'),
      cred.public_key.toString('base64url'),
    ]) {
      expect(log).not.toContain(secret);
    }
  });
});
