// パスワード忘れ（S10, S11）の結合テスト。
import { performance } from 'node:perf_hooks';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { RESET_TOKEN_TTL_MS } from '../../src/auth/reset.js';
import { RESET_MAILS_PER_WINDOW } from '../../src/routes/reset.js';
import { body, makeApp, post, randomPassword, sessionCookie, signup, uniqueEmail } from '../helpers/app.js';
import { CaptureMailer, tokenFromMail } from '../helpers/mailer.js';
import { TestBrowser } from '../helpers/passkey-client.js';
import { SoftAuthenticator } from '../helpers/soft-authenticator.js';

let app: FastifyInstance | undefined;
afterEach(async () => {
  vi.useRealTimers();
  await app?.close();
  app = undefined;
});

async function start(mailer = new CaptureMailer()): Promise<{ a: FastifyInstance; mailer: CaptureMailer }> {
  app = await makeApp({ mailer });
  return { a: app, mailer };
}

/** 再設定メールを依頼し、届いたリンクのトークンを返す */
async function requestToken(a: FastifyInstance, mailer: CaptureMailer, email: string): Promise<string> {
  const before = mailer.sent.length;
  const res = await post(a, '/reset', { email });
  expect(res.statusCode).toBe(200);
  return tokenFromMail(await mailer.waitFor(before + 1));
}

const me = (a: FastifyInstance, cookie: string) =>
  a.inject({ method: 'GET', url: '/account/me', headers: { cookie } });

describe('パスワードの再設定（S10）', () => {
  it('メールのリンクで新しいパスワードを決めると、新しいパスワードで入れて、古いパスワードでは入れない', async () => {
    const { a, mailer } = await start();
    const { email, password, cookie } = await signup(a);
    const token = await requestToken(a, mailer, email);
    expect(mailer.sent[0]!.to).toBe(email);

    const newPassword = randomPassword();
    const res = await post(a, '/reset/confirm', { token, password: newPassword });
    expect(res.statusCode).toBe(200);
    // S11: 再設定ではログイン状態にしない
    expect(res.cookies.find((c) => c.name === 'sid')).toBeUndefined();

    expect((await post(a, '/login', { email, password })).statusCode).toBe(401);
    expect((await post(a, '/login', { email, password: newPassword })).statusCode).toBe(200);
    // 再設定の前から入っていた端末はログアウトされる
    expect((await me(a, cookie)).statusCode).toBe(401);
  });

  it('トークンは 1 回使うと無効になる', async () => {
    const { a, mailer } = await start();
    const { email } = await signup(a);
    const token = await requestToken(a, mailer, email);
    expect((await post(a, '/reset/confirm', { token, password: randomPassword() })).statusCode).toBe(200);
    const again = await post(a, '/reset/confirm', { token, password: randomPassword() });
    expect(again.statusCode).toBe(400);
    expect(body(again).message).toContain('このリンクは使えません');
  });

  it('同じリンクを同時に 2 回送っても、通るのは 1 回だけ', async () => {
    const { a, mailer } = await start();
    const { email } = await signup(a);
    const token = await requestToken(a, mailer, email);
    const results = await Promise.all([
      post(a, '/reset/confirm', { token, password: randomPassword() }),
      post(a, '/reset/confirm', { token, password: randomPassword() }),
    ]);
    expect(results.map((r) => r.statusCode).sort()).toEqual([200, 400]);
  });

  it('トークンは 15 分で無効になる', async () => {
    const { a, mailer } = await start();
    const { email, password } = await signup(a);
    const token = await requestToken(a, mailer, email);
    // Date だけを進める（setImmediate などのタイマーは本物のまま）
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(Date.now() + RESET_TOKEN_TTL_MS + 1);
    const res = await post(a, '/reset/confirm', { token, password: randomPassword() });
    expect(res.statusCode).toBe(400);
    vi.useRealTimers();
    // パスワードは変わっていない
    expect((await post(a, '/login', { email, password })).statusCode).toBe(200);
  });

  it('DB にはトークンのハッシュしか無い', async () => {
    const { a, mailer } = await start();
    const { email } = await signup(a);
    const token = await requestToken(a, mailer, email);
    const rows = a.db.prepare('SELECT * FROM reset_tokens').all() as Record<string, unknown>[];
    expect(rows).toHaveLength(1);
    const tables = a.db.prepare("SELECT name FROM sqlite_master WHERE type = 'table'").pluck().all() as string[];
    const dump = tables
      .flatMap((t) => a.db.prepare(`SELECT * FROM "${t}"`).all() as Record<string, unknown>[])
      .flatMap((r) => Object.values(r))
      .map((v) => (Buffer.isBuffer(v) ? `${v.toString('utf8')}|${v.toString('hex')}` : String(v)))
      .join('\n');
    expect(dump).not.toContain(token);
    expect(dump).not.toContain(Buffer.from(token).toString('hex'));
  });

  it('新しいパスワードが規則に合わないときはトークンを使い切らず、言い直せる（S2）', async () => {
    const { a, mailer } = await start();
    const { email } = await signup(a);
    const token = await requestToken(a, mailer, email);
    const short = await post(a, '/reset/confirm', { token, password: randomPassword(10) });
    expect(short.statusCode).toBe(400);
    expect(body(short).reason).toBe('too_short');
    expect((await post(a, '/reset/confirm', { token, password: randomPassword() })).statusCode).toBe(200);
  });

  it('パスワードを変更すると、それより前に送ったリンクは使えなくなる', async () => {
    const { a, mailer } = await start();
    const { email, password, cookie } = await signup(a);
    const token = await requestToken(a, mailer, email);
    const change = await post(
      a,
      '/account/password',
      { currentPassword: password, newPassword: randomPassword() },
      { cookie },
    );
    expect(change.statusCode).toBe(200);
    expect((await post(a, '/reset/confirm', { token, password: randomPassword() })).statusCode).toBe(400);
  });

  it('パスキーのみのユーザーも、再設定でパスワードを足せる（パスキーを失くしたときの回復, §7-5）', async () => {
    const { a, mailer } = await start();
    const browser = new TestBrowser(a, 'http://localhost:3000');
    expect((await browser.signup(new SoftAuthenticator('http://localhost:3000'), 'pk@example.com')).statusCode).toBe(200);
    const token = await requestToken(a, mailer, 'pk@example.com');
    const newPassword = randomPassword();
    expect((await post(a, '/reset/confirm', { token, password: newPassword })).statusCode).toBe(200);
    const login = await post(a, '/login', { email: 'pk@example.com', password: newPassword });
    expect(login.statusCode).toBe(200);
    expect(body(await me(a, sessionCookie(login)))).toMatchObject({ hasPassword: true });
  });

  it('S13: 他サイトからの再設定の依頼・確定は受け付けない', async () => {
    const { a } = await start();
    const { email } = await signup(a);
    expect((await post(a, '/reset', { email }, { origin: 'https://evil.example' })).statusCode).toBe(403);
    expect((await post(a, '/reset', { email }, { origin: null })).statusCode).toBe(403);
    expect(
      (await post(a, '/reset/confirm', { token: 'x', password: randomPassword() }, { origin: null })).statusCode,
    ).toBe(403);
  });
});

describe('列挙防止: 登録の有無で応答を変えない', () => {
  it('存在しないメールでも、状態コード・本文・Cookie が同じで、メールは送らない', async () => {
    const { a, mailer } = await start();
    const { email } = await signup(a);
    const known = await post(a, '/reset', { email });
    const unknown = await post(a, '/reset', { email: uniqueEmail() });
    expect(unknown.statusCode).toBe(known.statusCode);
    expect(unknown.body).toBe(known.body);
    expect(unknown.headers['set-cookie']).toBe(known.headers['set-cookie']);
    await mailer.waitFor(1);
    await new Promise((r) => setTimeout(r, 50));
    expect(mailer.sent.map((m) => m.to)).toEqual([email]);
  });

  it('存在しないメールでも所要時間が同等（送信に時間がかかる事業者でも、送信を待たずに返す）', async () => {
    // 送信に 300ms かかる Mailer。応答が送信を待っていれば、登録済みのメールだけが 300ms 以上遅くなる
    const { a } = await start(new CaptureMailer(300));
    const emails: string[] = [];
    for (let i = 0; i < 5; i++) emails.push((await signup(a)).email);

    const measure = async (email: string): Promise<number> => {
      const t = performance.now();
      const res = await post(a, '/reset', { email });
      expect(res.statusCode).toBe(200);
      return performance.now() - t;
    };
    const knownTimes: number[] = [];
    const unknownTimes: number[] = [];
    // 交互に測り、途中の GC や JIT の影響が片方にだけ偏らないようにする。
    // 利用者ごとの送信上限（RESET_MAILS_PER_WINDOW）に当たらない回数にとどめる
    for (let round = 0; round < RESET_MAILS_PER_WINDOW; round++) {
      for (const email of emails) {
        knownTimes.push(await measure(email));
        unknownTimes.push(await measure(uniqueEmail()));
      }
    }
    const median = (xs: number[]) => [...xs].sort((x, y) => x - y)[Math.floor(xs.length / 2)]!;
    // 送信を待っていない: どの応答も送信時間（300ms）よりずっと短い
    expect(Math.max(...knownTimes)).toBeLessThan(150);
    // 中央値の差が小さい（DB の 1 行の読み書き程度。CI の揺れを見込んで 20ms までを許す）
    expect(Math.abs(median(knownTimes) - median(unknownTimes))).toBeLessThan(20);
  });

  it(`同じ利用者へのメールは 15 分に ${RESET_MAILS_PER_WINDOW} 通まで。超えても応答は同じ（S8）`, async () => {
    const { a, mailer } = await start();
    const { email } = await signup(a);
    const bodies: string[] = [];
    for (let i = 0; i < RESET_MAILS_PER_WINDOW + 2; i++) {
      const res = await post(a, '/reset', { email });
      expect(res.statusCode).toBe(200);
      bodies.push(res.body);
    }
    expect(new Set(bodies).size).toBe(1);
    await mailer.waitFor(RESET_MAILS_PER_WINDOW);
    await new Promise((r) => setTimeout(r, 50));
    expect(mailer.sent).toHaveLength(RESET_MAILS_PER_WINDOW);
  });

  it('S8: IP ごとのレート制限が掛かる', async () => {
    app = await makeApp({ authRateLimit: { max: 2, timeWindowMs: 60_000 } });
    const codes: number[] = [];
    for (let i = 0; i < 3; i++) codes.push((await post(app, '/reset', { email: uniqueEmail() })).statusCode);
    expect(codes).toEqual([200, 200, 429]);
  });
});
