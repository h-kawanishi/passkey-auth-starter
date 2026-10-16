// S13: CSRF 対策の Origin ヘッダ検証。
// SameSite=Lax の Cookie だけでも他サイトからの POST には Cookie が付かないが、古いブラウザや
// 同じサイト内の別サブドメインからの要求まで防ぐため、状態を変える要求は Origin も照合する。
//
// TODO(D: B と統合): B も同じ役割のフックを作る予定。D でどちらか一方に寄せる。
import type { FastifyReply, FastifyRequest } from 'fastify';
import type { Config } from '../config.js';

// 読むだけの要求は状態を変えないので照合しない（GET で状態を変えるルートは作らない前提）
const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

/**
 * preHandler として使う。Origin が無い、または設定の ORIGIN と違う要求は 403 で止める。
 * Origin の無い要求を通さないのは、ブラウザは fetch の POST/PATCH/DELETE に必ず Origin を付けるため、
 * 無いのはブラウザ以外（あるいはヘッダを消す細工）だと判断できるから。
 */
export function requireSameOrigin(config: Config) {
  return async (req: FastifyRequest, reply: FastifyReply): Promise<FastifyReply | undefined> => {
    if (SAFE_METHODS.has(req.method)) return undefined;
    if (req.headers.origin === config.origin) return undefined;
    // 応答は短く同じにする。どこが違ったかを返すと攻撃者の試行錯誤を助けるため。
    // reply を返すと Fastify はこの先のハンドラを呼ばない
    return reply.code(403).send({ error: '要求元を確認できませんでした。画面を開き直してください。' });
  };
}
