// S13: CSRF 対策の Origin ヘッダ検証。
import type { FastifyReply, FastifyRequest } from 'fastify';

// 読み取りだけの要求は状態を変えないので検証しない（GET で状態を変えるルートを作らないことが前提）
const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

/**
 * 状態を変える要求（POST など）は、Origin ヘッダが自分のオリジンと一致するときだけ通す。
 * SameSite=Lax の Cookie だけでも他サイトからの POST には Cookie が付かないが、
 * 古いブラウザや同一サイト内の別サブドメインからの攻撃に備え、二重に守る。
 * Origin が無い要求も拒否する。主要なブラウザは POST に必ず Origin を付けるため、
 * 付いていないのはブラウザ以外からの要求で、ここで受け付ける理由がない。
 */
export async function verifyOrigin(request: FastifyRequest, reply: FastifyReply): Promise<void> {
  if (SAFE_METHODS.has(request.method)) return;
  if (request.headers.origin === request.server.config.origin) return;
  request.log.warn({ origin: request.headers.origin ?? null }, 'Origin が一致しない要求を拒否しました');
  await reply.code(403).send({ message: '不正な送信元からの要求のため、処理しませんでした' });
}
