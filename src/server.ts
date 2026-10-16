import { fileURLToPath } from 'node:url';
import fastifyCookie from '@fastify/cookie';
import fastifyRateLimit from '@fastify/rate-limit';
import Fastify, { type FastifyInstance } from 'fastify';
import { ChallengeStore } from './auth/challenges.js';
import { verifyOrigin } from './auth/origin.js';
import { ConfigError, loadConfig, type Config } from './config.js';
import { openDatabase } from './db/connection.js';
import { migrate } from './db/migrate.js';
import { ConsoleMailer } from './mail/console-mailer.js';
import type { Mailer } from './mail/mailer.js';
import { accountRoutes } from './routes/account.js';
import { loginRoutes } from './routes/login.js';
import { logoutRoutes } from './routes/logout.js';
import { pageRoutes } from './routes/pages.js';
import { passkeyLoginRoutes } from './routes/passkey-login.js';
import { passkeysRoutes } from './routes/passkeys.js';
import { resetRoutes } from './routes/reset.js';
import { signupRoutes } from './routes/signup.js';
import type { AppOptions } from './types.js';

/**
 * 本番では、送信事業者につながる Mailer を必ず渡させる。
 * 黙ってコンソールに出すと、再設定メールが誰にも届かないまま「送りました」と答え続けることになるため、
 * 起動の時点で止める（S10: 再設定はメールでのみ通知する）。
 */
function chooseMailer(config: Config, mailer: Mailer | undefined): Mailer {
  if (mailer) return mailer;
  if (config.nodeEnv === 'production') {
    throw new ConfigError([
      '本番では再設定メールの送信手段（Mailer）を buildApp の mailer に渡してください（src/mail/mailer.ts）',
    ]);
  }
  return new ConsoleMailer(config.nodeEnv);
}

/**
 * アプリを組み立てて返す（listen はしない）。
 * 起動と分けているのは、テストで app.inject() を使い、ポートを開かずに要求を試せるようにするため。
 */
export function buildApp(config: Config, options: AppOptions = {}): FastifyInstance {
  const mailer = chooseMailer(config, options.mailer);
  const app = Fastify({
    logger: {
      level: config.logLevel,
      // S12: 将来 Cookie や Authorization ヘッダをログに出す設定にしても、値が残らないよう伏せておく
      redact: ['req.headers.cookie', 'req.headers.authorization', 'res.headers["set-cookie"]'],
      ...(options.logStream ? { stream: options.logStream } : {}),
    },
  });

  // DB を開いて未適用のマイグレーションを当てる。E2E のように :memory: で起動したときも表がそろうように
  const db = options.db ?? openDatabase(config.databasePath);
  migrate(db);
  if (!options.db) {
    // 自分で開いた DB だけを閉じる。渡された DB はテスト側が閉じる
    app.addHook('onClose', () => db.close());
  }
  app.decorate('config', config);
  app.decorate('db', db);
  app.decorate('mailer', mailer);
  app.decorate('challenges', new ChallengeStore());

  // セッション Cookie の読み書き。署名は使わない（ID 自体が 256bit 乱数で、DB 側の HMAC で照合するため）
  void app.register(fastifyCookie);
  // S8: IP ごとのレート制限。全体には掛けず、ログイン・登録などのルートが config.rateLimit で個別に使う
  const auth = options.authRateLimit ?? { max: 30, timeWindowMs: 15 * 60 * 1000 };
  app.decorate('authRateLimit', { max: auth.max, timeWindow: auth.timeWindowMs });
  const passkey = options.passkeyRateLimit ?? { max: 30, timeWindowMs: 60 * 1000 };
  app.decorate('passkeyRateLimit', { max: passkey.max, timeWindow: passkey.timeWindowMs });
  void app.register(fastifyRateLimit, {
    global: false,
    errorResponseBuilder: (_req, context) => ({
      statusCode: context.statusCode,
      error: 'Too Many Requests',
      message: `短い時間に要求が多すぎます。${Math.ceil(context.ttl / 60000)} 分ほど待ってからもう一度お試しください`,
    }),
  });
  // S13: 状態を変える要求は Origin ヘッダを検証する。全ルートに一度で掛け、付け忘れを無くす
  app.addHook('onRequest', verifyOrigin);

  // 死活監視用。ロードバランサやコンテナの健康診断が叩く。秘密や内部情報は返さない
  app.get('/healthz', () => ({ status: 'ok' }));

  void app.register(pageRoutes);
  void app.register(signupRoutes);
  void app.register(loginRoutes);
  void app.register(logoutRoutes);
  void app.register(passkeysRoutes);
  void app.register(passkeyLoginRoutes);
  void app.register(accountRoutes);
  void app.register(resetRoutes);

  return app;
}

async function main(): Promise<void> {
  let app: FastifyInstance;
  let config: Config;
  try {
    config = loadConfig();
    // 本番で使うときは、ここで自分の送信事業者向けの Mailer を渡す: buildApp(config, { mailer })
    app = buildApp(config);
  } catch (err) {
    if (err instanceof ConfigError) {
      console.error(err.message);
      process.exit(1);
    }
    throw err;
  }

  if (config.sessionSecretIsEphemeral) {
    app.log.warn('SESSION_SECRET が未設定のため、使い捨ての値で起動しました（再起動でログイン状態は消えます）');
  }
  await app.listen({ host: config.host, port: config.port });
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  await main();
}
