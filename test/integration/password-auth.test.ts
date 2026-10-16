import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { body, makeApp, post, randomPassword, sessionCookie, signup, uniqueEmail } from '../helpers/app.js';

describe('登録・ログイン・ログアウト', () => {
  let app: FastifyInstance;
  beforeEach(async () => {
    app = await makeApp();
  });
  afterEach(async () => {
    await app.close();
  });

  it('登録するとログイン状態になり、アカウント情報が見られる', async () => {
    const { email, cookie } = await signup(app);
    const me = await app.inject({ method: 'GET', url: '/account/me', headers: { cookie } });
    expect(me.statusCode).toBe(200);
    expect(me.json()).toEqual({ email, hasPassword: true });
  });

  it('メールアドレスは大文字小文字を区別せず、同じアドレスでは二重に登録できない', async () => {
    const email = uniqueEmail();
    await signup(app, email);
    const res = await post(app, '/signup', { email: email.toUpperCase(), password: randomPassword() });
    expect(res.statusCode).toBe(409);
  });

  it('S2: 14 文字は拒否、15 文字・64 文字超・記号なしは受理', async () => {
    const short = await post(app, '/signup', { email: uniqueEmail(), password: randomPassword(14) });
    expect(short.statusCode).toBe(400);
    expect(body(short).reason).toBe('too_short');

    for (const password of [
      randomPassword(15),
      randomPassword(100),
      randomPassword(40).toLowerCase().replace(/[^a-z]/g, ''),
    ]) {
      const res = await post(app, '/signup', { email: uniqueEmail(), password });
      expect(res.statusCode).toBe(201);
    }
  });

  it('正しいパスワードでログインでき、ログアウトでセッションが失効する', async () => {
    const { email, password } = await signup(app);
    const login = await post(app, '/login', { email, password });
    expect(login.statusCode).toBe(200);
    const cookie = sessionCookie(login);

    const out = await post(app, '/logout', {}, { cookie });
    expect(out.statusCode).toBe(200);
    // Cookie を消すだけでなく、サーバー側のセッションも消えていること（盗まれた Cookie が使えない）
    const me = await app.inject({ method: 'GET', url: '/account/me', headers: { cookie } });
    expect(me.statusCode).toBe(401);
  });

  it('列挙防止: 存在しないメールとパスワード違いで応答が同じ', async () => {
    const { email } = await signup(app);
    const wrongPassword = await post(app, '/login', { email, password: randomPassword() });
    const unknownEmail = await post(app, '/login', { email: uniqueEmail(), password: randomPassword() });
    expect(wrongPassword.statusCode).toBe(401);
    expect(unknownEmail.statusCode).toBe(wrongPassword.statusCode);
    expect(unknownEmail.body).toBe(wrongPassword.body);
    expect(unknownEmail.cookies).toEqual(wrongPassword.cookies);
  });

  it('未ログインでアカウント画面を開くとログイン画面へ送る', async () => {
    const res = await app.inject({ method: 'GET', url: '/account' });
    expect(res.statusCode).toBe(302);
    expect(res.headers.location).toBe('/login');
  });

  it('登録・ログイン画面が開ける', async () => {
    for (const url of ['/signup', '/login']) {
      const res = await app.inject({ method: 'GET', url });
      expect(res.statusCode).toBe(200);
      expect(res.headers['content-type']).toMatch(/^text\/html/);
    }
  });
});

describe('パスワード変更と全端末ログアウト', () => {
  let app: FastifyInstance;
  beforeEach(async () => {
    app = await makeApp();
  });
  afterEach(async () => {
    await app.close();
  });

  it('パスワードを変えると、古いパスワードでは入れず、ほかの端末はログアウトされる', async () => {
    const { email, password, cookie } = await signup(app);
    const other = sessionCookie(await post(app, '/login', { email, password }));
    const newPassword = randomPassword();

    const res = await post(app, '/account/password', { currentPassword: password, newPassword }, { cookie });
    expect(res.statusCode).toBe(200);

    expect((await post(app, '/login', { email, password })).statusCode).toBe(401);
    expect((await post(app, '/login', { email, password: newPassword })).statusCode).toBe(200);
    const meHere = await app.inject({ method: 'GET', url: '/account/me', headers: { cookie } });
    const meOther = await app.inject({ method: 'GET', url: '/account/me', headers: { cookie: other } });
    expect(meHere.statusCode).toBe(200);
    expect(meOther.statusCode).toBe(401);
  });

  it('現在のパスワードが違えば変更しない。新しいパスワードにも S2 の規則を当てる', async () => {
    const { password, cookie } = await signup(app);
    const wrong = await post(
      app,
      '/account/password',
      { currentPassword: randomPassword(), newPassword: randomPassword() },
      { cookie },
    );
    expect(wrong.statusCode).toBe(400);
    const short = await post(
      app,
      '/account/password',
      { currentPassword: password, newPassword: randomPassword(14) },
      { cookie },
    );
    expect(short.statusCode).toBe(400);
    expect(body(short).reason).toBe('too_short');
  });

  it('未ログインではパスワードを変更できない', async () => {
    const res = await post(app, '/account/password', {
      currentPassword: randomPassword(),
      newPassword: randomPassword(),
    });
    expect(res.statusCode).toBe(401);
  });

  it('全端末ログアウトで、その利用者のすべてのセッションが失効する', async () => {
    const { email, password, cookie } = await signup(app);
    const other = sessionCookie(await post(app, '/login', { email, password }));
    const res = await post(app, '/logout/all', {}, { cookie });
    expect(res.statusCode).toBe(200);
    for (const c of [cookie, other]) {
      const me = await app.inject({ method: 'GET', url: '/account/me', headers: { cookie: c } });
      expect(me.statusCode).toBe(401);
    }
  });
});
