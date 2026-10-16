// パスキーの「開始（options）→ 完了（verify）」の 2 往復をつなぐ引換券の Cookie。
// チャレンジそのものはサーバーのメモリに置き、ブラウザには乱数の引換券だけを持たせる。
// 引換券を Cookie（HttpOnly）にするのは、開始した同じブラウザでしか完了できないようにするため。
import type { FastifyReply, FastifyRequest } from 'fastify';
import type { PendingCeremony } from '../auth/challenges.js';

const NAME = 'pk_ceremony';
// /passkeys/ 以下の要求にだけ送らせる。ほかの画面の要求に余計な Cookie を載せないため
const PATH = '/passkeys/';
const MAX_AGE_SECONDS = 5 * 60; // challenges.ts の有効期限と同じ

function cookieOptions(req: FastifyRequest) {
  return {
    httpOnly: true, // S7: ページの JavaScript から読ませない
    sameSite: 'lax', // S7 / S13: 他サイトからの POST には付けない
    secure: req.server.config.cookieSecure, // S7: 本番は Secure
    path: PATH,
  } as const;
}

export function readCeremonyTicket(req: FastifyRequest): string | undefined {
  return req.cookies[NAME];
}

export function clearCeremonyCookie(req: FastifyRequest, reply: FastifyReply): void {
  void reply.clearCookie(NAME, cookieOptions(req));
}

/**
 * チャレンジを保管して引換券の Cookie を付ける。置き場が満杯なら 503 を送って false を返す
 * （呼び出し側は false なら reply をそのまま返す）。満杯のときに他人のチャレンジを押し出さず
 * 新しい要求を断るのは、開始の要求を大量に送るだけで他の利用者を失敗させる妨害を防ぐため。
 */
export function issueCeremony(
  req: FastifyRequest,
  reply: FastifyReply,
  entry: Omit<PendingCeremony, 'expiresAt'>,
): boolean {
  const ticket = req.server.challenges.put(entry, req.ip);
  if (!ticket) {
    void reply
      .code(503)
      .header('retry-after', '60')
      .send({ message: '混み合っています。しばらく待ってからもう一度お試しください。' });
    return false;
  }
  void reply.setCookie(NAME, ticket, { ...cookieOptions(req), maxAge: MAX_AGE_SECONDS });
  return true;
}
