// 画面（素の HTML）と、画面が読み込む JavaScript の配信。
// 起動時に一度だけ読み込む。要求のたびにファイルを読むと、パスの組み立て次第で
// 意図しないファイルを返す（パストラバーサル）余地が生まれるため、配る物を固定の一覧にしている。
//
// TODO(D: B と統合): B がログイン・登録・アカウント画面を login.ts / signup.ts / account.ts に置いた場合は、
//   画面の配信をどちらかに寄せる。
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import type { FastifyPluginCallback } from 'fastify';
import { getSessionUser } from '../auth/session.js';
import type { RouteDeps } from './context.js';

const WEB_DIR = join(import.meta.dirname, '..', 'web');

// @simplewebauthn/browser の配布物のうち、<script> でそのまま読める UMD 版を配る。
// ビルド工程（バンドラ）を入れずに済ませ、初心者が「npm run dev だけで動く」状態を保つため
function browserBundlePath(): string {
  const require = createRequire(import.meta.url);
  // package.json の exports が dist/ を公開していないので、本体の位置からパッケージの根を割り出す
  const entry = require.resolve('@simplewebauthn/browser'); // .../script/index.js
  return join(dirname(entry), '..', 'dist', 'bundle', 'index.umd.min.js');
}

const read = (file: string): string => readFileSync(join(WEB_DIR, file), 'utf8');

// ルートを登録するだけで待つ処理が無いので、async ではなく done で終わりを知らせる形にしている
export const pageRoutes: FastifyPluginCallback<RouteDeps> = (app, deps, done) => {
  const loginHtml = read('login.html');
  const signupHtml = read('signup.html');
  const accountHtml = read('account.html');
  const appJs = read('app.js');
  const browserJs = readFileSync(browserBundlePath(), 'utf8');

  const html = 'text/html; charset=utf-8';
  const js = 'text/javascript; charset=utf-8';

  app.get('/login', (_req, reply) => reply.type(html).send(loginHtml));
  app.get('/signup', (_req, reply) => reply.type(html).send(signupHtml));
  app.get('/account', (req, reply) => {
    // 未ログインなら画面を出さずにログインへ送る（中身は API 側でも必ず確かめている）
    if (!getSessionUser(deps.db, deps.config, req)) return reply.redirect('/login', 303);
    return reply.type(html).send(accountHtml);
  });
  app.get('/assets/app.js', (_req, reply) => reply.type(js).send(appJs));
  app.get('/assets/simplewebauthn-browser.js', (_req, reply) => reply.type(js).send(browserJs));
  done();
};
