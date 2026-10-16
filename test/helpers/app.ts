import { randomBytes } from 'node:crypto';
import type { FastifyInstance, LightMyRequestResponse } from 'fastify';
import { loadConfig } from '../../src/config.js';
import { buildApp } from '../../src/server.js';
import type { AppOptions } from '../../src/types.js';
import { CaptureMailer } from './mailer.js';

export const ORIGIN = 'http://localhost:3000';

/**
 * テスト用のアプリ。DB はメモリ上に作り、テストごとに捨てる。
 * レート制限（S8）は既定では十分大きくし、制限そのものを調べるテストだけ小さくする。
 */
export async function makeApp(options: AppOptions = {}): Promise<FastifyInstance> {
  const app = buildApp(
    loadConfig({
      NODE_ENV: 'test',
      ORIGIN,
      DATABASE_PATH: ':memory:',
      SESSION_SECRET: randomBytes(32).toString('base64url'),
    }),
    // 再設定メールは標準出力に出さず、テストから中身を読めるよう覚えておく
    { authRateLimit: { max: 1000, timeWindowMs: 60_000 }, mailer: new CaptureMailer(), ...options },
  );
  await app.ready();
  return app;
}

/**
 * テストで使うパスワードを毎回ランダムに作る（CLAUDE.md: テストの期待値に生値を書かない）。
 * base64url の文字だけなので、漏えい一覧に偶然当たることは現実的にない。
 */
export function randomPassword(length = 20): string {
  let s = '';
  while (s.length < length) s += randomBytes(48).toString('base64url');
  return s.slice(0, length);
}

let counter = 0;
export function uniqueEmail(): string {
  counter += 1;
  return `user${counter}-${randomBytes(4).toString('hex')}@example.com`;
}

/** 自分のオリジンからの POST（S13 の検証を通る形）。cookie を渡すとログイン状態で送る */
export function post(
  app: FastifyInstance,
  url: string,
  payload: object,
  opts: { cookie?: string; origin?: string | null } = {},
): Promise<LightMyRequestResponse> {
  const headers: Record<string, string> = {};
  if (opts.origin !== null) headers.origin = opts.origin ?? ORIGIN;
  if (opts.cookie) headers.cookie = opts.cookie;
  return app.inject({ method: 'POST', url, payload, headers });
}

/** Set-Cookie からセッション Cookie を「名前=値」の形で取り出す */
export function sessionCookie(res: LightMyRequestResponse): string {
  const c = res.cookies.find((x) => x.name === 'sid');
  if (!c) throw new Error('セッション Cookie が発行されていません');
  return `${c.name}=${c.value}`;
}

export async function signup(
  app: FastifyInstance,
  email = uniqueEmail(),
  password = randomPassword(),
): Promise<{ email: string; password: string; cookie: string }> {
  const res = await post(app, '/signup', { email, password });
  if (res.statusCode !== 201) throw new Error(`登録に失敗: ${res.statusCode}`);
  return { email, password, cookie: sessionCookie(res) };
}

/** 応答の JSON を、テストで読む形に型付けして返す（any のまま触らないため） */
export function body(res: LightMyRequestResponse): { message?: string; reason?: string } {
  return res.json<{ message?: string; reason?: string }>();
}
