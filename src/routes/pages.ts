// 画面（素の HTML）と、画面が読み込む JavaScript の配信をここに集める。
// 起動時に一度だけ読み込む。要求のたびにファイルを読むと遅く、途中でファイルが変わると画面と API の版がずれるうえ、
// パスの組み立て次第で意図しないファイルを返す（パストラバーサル）余地が生まれるため、配る物を固定の一覧にしている。
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import type { FastifyPluginCallback } from 'fastify';
import { currentUser } from '../auth/session.js';

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
export const pageRoutes: FastifyPluginCallback = (app, _opts, done) => {
  const html = 'text/html; charset=utf-8';
  const js = 'text/javascript; charset=utf-8';

  const pages: Record<string, string> = {
    '/': read('index.html'),
    '/login': read('login.html'),
    '/signup': read('signup.html'),
    // パスワード忘れ（D）。/reset はメール入力、/reset/new はメールのリンクから開く新パスワードの入力
    '/reset': read('reset.html'),
    '/reset/new': read('reset-new.html'),
  };
  for (const [url, body] of Object.entries(pages)) {
    app.get(url, (_req, reply) => reply.type(html).send(body));
  }

  const accountHtml = read('account.html');
  app.get('/account', (req, reply) => {
    // 未ログインなら画面を出さずにログインへ送る（中身は API 側でも必ず確かめている）
    if (!currentUser(req)) return reply.redirect('/login');
    return reply.type(html).send(accountHtml);
  });

  const appJs = read('app.js');
  const browserJs = readFileSync(browserBundlePath(), 'utf8');
  app.get('/assets/app.js', (_req, reply) => reply.type(js).send(appJs));
  app.get('/assets/simplewebauthn-browser.js', (_req, reply) => reply.type(js).send(browserJs));
  done();
};
