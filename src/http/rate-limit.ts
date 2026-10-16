// S8: 送信元（IP）ごとのレート制限。パスキーの開始・完了の要求に掛ける。
//
// 依存を増やさないための最小実装（固定時間窓のカウンタ。メモリに置く）。
// パスキーのルートはログイン前に誰でも呼べるので、制限が無いと
// 1) チャレンジの置き場を大量の要求で埋める妨害 2) 応答の総当たり、を安く試せてしまう。
// アカウント単位の制限と連続失敗のロック（S9）はパスワードのログイン（B）の仕組みに寄せる。
// TODO(D: B と統合): B が @fastify/rate-limit を入れた場合はそちらの設定に寄せ、このファイルは消す。
//   複数台・複数プロセスで動かす場合も、カウンタを共有の置き場（Redis など）に移す必要がある。
import type { FastifyReply, FastifyRequest } from 'fastify';

export interface RateLimitOptions {
  /** 1 つの窓の中で許す要求の数 */
  max: number;
  /** 窓の長さ（ミリ秒） */
  windowMs: number;
  now?: () => number;
}

/**
 * preHandler として使う。同じ IP からの要求が窓の中で max を超えたら 429 を返す。
 * 窓は全送信元で共通にし、窓が切り替わるたびに表を丸ごと空にする。
 * 送信元ごとに期限を持たせるより粗いが、表が 1 つの窓の間に来た送信元の数より大きくならず、
 * 古い記録を掃除する処理が要らない。
 */
export function rateLimitByIp(options: RateLimitOptions) {
  const now = options.now ?? Date.now;
  const counts = new Map<string, number>();
  let windowStart = now();

  return async (req: FastifyRequest, reply: FastifyReply): Promise<FastifyReply | undefined> => {
    const t = now();
    if (t - windowStart >= options.windowMs) {
      counts.clear();
      windowStart = t;
    }
    const n = (counts.get(req.ip) ?? 0) + 1;
    counts.set(req.ip, n);
    if (n <= options.max) return undefined;
    const retryAfter = Math.max(1, Math.ceil((windowStart + options.windowMs - t) / 1000));
    // どの要求で何回目かは返さない。利用者に必要なのは「少し待つ」ことだけ
    return reply
      .code(429)
      .header('retry-after', String(retryAfter))
      .send({ error: '試行が多すぎます。しばらく待ってからもう一度お試しください。' });
  };
}
