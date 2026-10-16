import type { ChallengeStore } from './auth/challenges.js';
import type { Config } from './config.js';
import type { Db } from './db/connection.js';

/** レート制限の設定。@fastify/rate-limit の route config にそのまま渡す形 */
export interface RateLimitSetting {
  max: number;
  timeWindowMs: number;
}

/** buildApp に渡せる、テストや運用で変えたい値。環境変数ではなく引数にしているのは、テストごとに変えたいため */
export interface AppOptions {
  /**
   * S8: IP ごとのレート制限（ログイン・登録・パスワード変更）。
   * 既定は 15 分あたり 30 回。人の操作では届かず、総当たりの速度は大きく落ちる値にしている。
   */
  authRateLimit?: RateLimitSetting;
  /**
   * S8: パスキーの開始・完了に掛ける IP ごとのレート制限。既定は 1 分あたり 30 回。
   * ログイン画面は開くたびに条件付き UI の開始要求を送るので、パスワードより緩くしないと
   * 共有回線（会社など）の利用者が普通に使うだけで止まってしまう。署名は推測できないので総当たりの心配は小さい。
   */
  passkeyRateLimit?: RateLimitSetting;
  /** ログの出力先。テストでログを捕まえて「生値が出ていないか」を調べるため（S12） */
  logStream?: NodeJS.WritableStream;
  /**
   * 使う DB。テストで同じ DB を外から覗けるよう、開いた DB を渡せるようにする。
   * 省略時は config.databasePath を開き、アプリを閉じるときに一緒に閉じる。
   */
  db?: Db;
}

// Fastify のインスタンスに設定と DB を持たせる（decorate）。
// ルートや auth/ の関数が request.server.db のように使えるよう、型をここで宣言しておく。
declare module 'fastify' {
  interface FastifyInstance {
    config: Config;
    db: Db;
    /** パスキーのチャレンジ（使い捨ての乱数）の一時保管 */
    challenges: ChallengeStore;
    authRateLimit: { max: number; timeWindow: number };
    passkeyRateLimit: { max: number; timeWindow: number };
  }
}
