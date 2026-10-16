import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import Fastify, { type FastifyInstance } from 'fastify';
import { ChallengeStore } from './auth/challenges.js';
import { ConfigError, loadConfig, type Config } from './config.js';
import { openDatabase, type Db } from './db/connection.js';
import { migrate } from './db/migrate.js';
import { accountRoutes } from './routes/account.js';
import type { RouteDeps } from './routes/context.js';
import { loginRoutes } from './routes/login.js';
import { logoutRoutes } from './routes/logout.js';
import { pageRoutes } from './routes/pages.js';
import { passkeyLoginRoutes } from './routes/passkey-login.js';
import { passkeysRoutes } from './routes/passkeys.js';
import { resetRoutes } from './routes/reset.js';
import { signupRoutes } from './routes/signup.js';

const WEB_DIR = join(import.meta.dirname, 'web');

export interface BuildOptions {
  /** テストで同じ DB を外から覗けるよう、開いた DB を渡せるようにする。省略時は config の場所を開く */
  db?: Db;
}

/**
 * アプリを組み立てて返す（listen はしない）。
 * 起動と分けているのは、テストで app.inject() を使い、ポートを開かずに要求を試せるようにするため。
 */
export function buildApp(config: Config, options: BuildOptions = {}): FastifyInstance {
  const app = Fastify({
    logger: {
      level: config.logLevel,
      // S12: 将来 Cookie や Authorization ヘッダをログに出す設定にしても、値が残らないよう伏せておく
      redact: ['req.headers.cookie', 'req.headers.authorization', 'res.headers["set-cookie"]'],
    },
  });

  // 起動時に一度だけ読む。画面は B 以降で増えるので、そのときに配信の仕組みを見直す
  const indexHtml = readFileSync(join(WEB_DIR, 'index.html'), 'utf8');
  app.get('/', (_req, reply) => reply.type('text/html; charset=utf-8').send(indexHtml));

  // 死活監視用。ロードバランサやコンテナの健康診断が叩く。秘密や内部情報は返さない
  app.get('/healthz', () => ({ status: 'ok' }));

  // 起動のたびに未適用のマイグレーションを当てる。:memory: の DB（E2E）でも表がある状態で始めるため
  const db = options.db ?? openDatabase(config.databasePath);
  migrate(db);
  if (!options.db) {
    // 自分で開いた DB だけを閉じる。渡された DB はテスト側が閉じる
    app.addHook('onClose', () => {
      db.close();
    });
  }
  const deps: RouteDeps = { config, db, challenges: new ChallengeStore() };

  void app.register(pageRoutes, deps);
  void app.register(signupRoutes);
  void app.register(loginRoutes);
  void app.register(logoutRoutes, deps);
  void app.register(passkeysRoutes, deps);
  void app.register(passkeyLoginRoutes, deps);
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
