import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import Fastify, { type FastifyInstance } from 'fastify';
import { ConfigError, loadConfig, type Config } from './config.js';
import { accountRoutes } from './routes/account.js';
import { loginRoutes } from './routes/login.js';
import { logoutRoutes } from './routes/logout.js';
import { passkeysRoutes } from './routes/passkeys.js';
import { resetRoutes } from './routes/reset.js';
import { signupRoutes } from './routes/signup.js';

const WEB_DIR = join(import.meta.dirname, 'web');

/**
 * アプリを組み立てて返す（listen はしない）。
 * 起動と分けているのは、テストで app.inject() を使い、ポートを開かずに要求を試せるようにするため。
 */
export function buildApp(config: Config): FastifyInstance {
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
