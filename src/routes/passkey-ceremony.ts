// パスキーの「開始（options）→ 完了（verify）」の 2 往復をつなぐ引換券の Cookie。
// チャレンジそのものはサーバーのメモリに置き、ブラウザには乱数の引換券だけを持たせる。
// 引換券を Cookie（HttpOnly）にするのは、開始した同じブラウザでしか完了できないようにするため。
import type { FastifyReply, FastifyRequest } from 'fastify';
import type { Config } from '../config.js';
import { parseCookies, serializeCookie } from '../http/cookies.js';

const NAME = 'pk_ceremony';
// /passkeys/ 以下の要求にだけ送らせる。ほかの画面の要求に余計な Cookie を載せないため
const PATH = '/passkeys/';
const MAX_AGE_SECONDS = 5 * 60; // challenges.ts の有効期限と同じ

export function setCeremonyCookie(config: Config, reply: FastifyReply, ticket: string): void {
  void reply.header(
    'set-cookie',
    serializeCookie(NAME, ticket, { maxAge: MAX_AGE_SECONDS, secure: config.cookieSecure, path: PATH }),
  );
}

export function readCeremonyTicket(req: FastifyRequest): string | undefined {
  return parseCookies(req.headers.cookie).get(NAME);
}

export function clearCeremonyCookie(config: Config, reply: FastifyReply): void {
  void reply.header(
    'set-cookie',
    serializeCookie(NAME, '', { maxAge: 0, secure: config.cookieSecure, path: PATH }),
  );
}
