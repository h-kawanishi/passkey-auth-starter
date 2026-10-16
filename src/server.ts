import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import fastifyCookie from '@fastify/cookie';
import fastifyRateLimit from '@fastify/rate-limit';
import Fastify, { type FastifyInstance } from 'fastify';
import { verifyOrigin } from './auth/origin.js';
import { ConfigError, loadConfig, type Config } from './config.js';
import { openDatabase } from './db/connection.js';
import { migrate } from './db/migrate.js';
import { accountRoutes } from './routes/account.js';
import { loginRoutes } from './routes/login.js';
import { logoutRoutes } from './routes/logout.js';
import { passkeysRoutes } from './routes/passkeys.js';
import { resetRoutes } from './routes/reset.js';
import { signupRoutes } from './routes/signup.js';
import type { AppOptions } from './types.js';

const WEB_DIR = join(import.meta.dirname, 'web');

/**
 * アプリを組み立てて返す（listen はしない）。
 * 起動と分けているのは、テストで app.inject() を使い、ポートを開かずに要求を試せるようにするため。
 */
export function buildApp(config: Config, options: AppOptions = {}): FastifyInstance {
  const app = Fastify({
    logger: {
      level: config.logLevel,
      // S12: 将来 Cookie や Authorization ヘッダをログに出す設定にしても、値が残らないよう伏せておく
      redact: ['req.headers.cookie', 'req.headers.authorization', 'res.headers["set-cookie"]'],
      ...(options.logStream ? { stream: options.logStream } : {}),
    },
  });

  // DB を開いて未適用のマイグレーションを当てる。E2E のように :memory: で起動したときも表がそろうように
  const db = openDatabase(config.databasePath);
  migrate(db);
  app.decorate('config', config);
  app.decorate('db', db);
  app.addHook('onClose', () => db.close());

  // セッション Cookie の読み書き。署名は使わない（ID 自体が 256bit 乱数で、DB 側の HMAC で照合するため）
  void app.register(fastifyCookie);
  // S8: IP ごとのレート制限。全体には掛けず、ログイン・登録などのルートが config.rateLimit で個別に使う
  const limit = options.authRateLimit ?? { max: 30, timeWindowMs: 15 * 60 * 1000 };
  app.decorate('authRateLimit', { max: limit.max, timeWindow: limit.timeWindowMs });
  void app.register(fastifyRateLimit, {
    global: false,
    errorResponseBuilder: (_req, context) => ({
      statusCode: context.statusCode,
      error: 'Too Many Requests',
      message: `短い時間に要求が多すぎます。${Math.ceil(context.ttl / 60000)} 分ほど待ってからもう一度お試しください`,
    }),
  });
  // S13: 状態を変える要求は Origin ヘッダを検証する
  app.addHook('onRequest', verifyOrigin);

  // 起動時に一度だけ読む。登録・ログインなどの画面は各ルートが src/web/pages.ts で配信する
  const indexHtml = readFileSync(join(WEB_DIR, 'index.html'), 'utf8');
  app.get('/', (_req, reply) => reply.type('text/html; charset=utf-8').send(indexHtml));
  // 各画面が共通で読む小さなスクリプト（フォーム送信とエラー表示）
  const appJs = readFileSync(join(WEB_DIR, 'app.js'), 'utf8');
  app.get('/app.js', (_req, reply) => reply.type('text/javascript; charset=utf-8').send(appJs));

  // 死活監視用。ロードバランサやコンテナの健康診断が叩く。秘密や内部情報は返さない
  app.get('/healthz', () => ({ status: 'ok' }));

  void app.register(signupRoutes);
  void app.register(loginRoutes);
  void app.register(logoutRoutes);
  void app.register(passkeysRoutes);
  void app.register(accountRoutes);
  void app.register(resetRoutes);

  return app;
}

async function main(): Promise<void> {
  let config: Config;
  try {
    config = loadConfig();
  } catch (err) {
    if (err instanceof ConfigError) {
      console.error(err.message);
      process.exit(1);
    }
    throw err;
  }

  const app = buildApp(config);
  if (config.sessionSecretIsEphemeral) {
    app.log.warn('SESSION_SECRET が未設定のため、使い捨ての値で起動しました（再起動でログイン状態は消えます）');
  }
  await app.listen({ host: config.host, port: config.port });
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  await main();
}
