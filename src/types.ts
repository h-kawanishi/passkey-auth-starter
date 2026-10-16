import type { Config } from './config.js';
import type { Db } from './db/connection.js';

/** buildApp に渡せる、テストや運用で変えたい値。環境変数ではなく引数にしているのは、テストごとに変えたいため */
export interface AppOptions {
  /**
   * S8: IP ごとのレート制限（ログイン・登録・パスワード変更）。
   * 既定は 15 分あたり 30 回。人の操作では届かず、総当たりの速度は大きく落ちる値にしている。
   */
  authRateLimit?: { max: number; timeWindowMs: number };
  /** ログの出力先。テストでログを捕まえて「生値が出ていないか」を調べるため（S12） */
  logStream?: NodeJS.WritableStream;
}

// Fastify のインスタンスに設定と DB を持たせる（decorate）。
// ルートや auth/ の関数が request.server.db のように使えるよう、型をここで宣言しておく。
declare module 'fastify' {
  interface FastifyInstance {
    config: Config;
    db: Db;
    authRateLimit: { max: number; timeWindow: number };
  }
}
