// セッションの発行・検証・失効。
//
// これはセッション C（パスキー）が「ログイン状態」を作るために置いた最小実装。
// セッションの本実装（全端末ログアウト、期限の延長、ID の再発行など）はセッション B の担当で、
// TODO(D: B と統合): D で B の session.ts と統合する。関数名 createSession / getSessionUser / destroySession は
//   B と合わせる約束になっている。
import { createHash, randomBytes } from 'node:crypto';
import type { FastifyReply, FastifyRequest } from 'fastify';
import type { Config } from '../config.js';
import type { Db } from '../db/connection.js';
import { deleteSession, findSessionUser, insertSession, type UserRow } from '../db/repo.js';
import { parseCookies, serializeCookie } from '../http/cookies.js';

// 本番は __Host- 接頭辞を付ける。ブラウザが「Secure・Path=/・Domain なし」のときしか受け付けないため、
// サブドメインから同名 Cookie を差し込まれる攻撃（セッション固定）を防げる。http の開発環境では使えない。
function cookieName(config: Config): string {
  return config.cookieSecure ? '__Host-sid' : 'sid';
}

// ログイン状態を保つ時間。長すぎると盗まれた Cookie が長く使え、短すぎると何度もログインさせる。
// TODO(D: B と統合): 期限の値と延長の方針は B に合わせる
const SESSION_TTL_MS = 24 * 60 * 60 * 1000;

/**
 * S7: Cookie に入れる生の ID は保存せず、SHA-256 だけを DB に置く。DB が漏れても Cookie は作れない。
 * ID は 256bit の乱数なので、総当たりで元に戻すことはできず、ソルトや低速ハッシュは要らない。
 */
function hashSessionId(rawId: string): Buffer {
  return createHash('sha256').update(rawId).digest();
}

/** ログイン成功時に呼ぶ。新しいセッションを作り、Set-Cookie を付ける */
export function createSession(
  db: Db,
  config: Config,
  req: FastifyRequest,
  reply: FastifyReply,
  userId: number,
): void {
  // ログイン前から持っていた Cookie は使い回さず消す。攻撃者が事前に仕込んだ ID のまま
  // ログインさせる「セッション固定」を防ぐため
  const oldId = parseCookies(req.headers.cookie).get(cookieName(config));
  if (oldId) deleteSession(db, hashSessionId(oldId));

  // S7: 256bit 乱数。予測できない値でなければ、他人のセッションを推測で乗っ取れてしまう
  const rawId = randomBytes(32).toString('base64url');
  const now = Date.now();
  insertSession(db, {
    idHash: hashSessionId(rawId),
    userId,
    createdAt: now,
    expiresAt: now + SESSION_TTL_MS,
    ip: req.ip,
    userAgent: req.headers['user-agent'] ?? null,
  });
  void reply.header(
    'set-cookie',
    serializeCookie(cookieName(config), rawId, {
      maxAge: Math.floor(SESSION_TTL_MS / 1000),
      secure: config.cookieSecure,
    }),
  );
}

/** 要求の Cookie からログイン中のユーザーを返す。無効・期限切れなら null */
export function getSessionUser(db: Db, config: Config, req: FastifyRequest): UserRow | null {
  const rawId = parseCookies(req.headers.cookie).get(cookieName(config));
  if (!rawId) return null;
  return findSessionUser(db, hashSessionId(rawId), Date.now()) ?? null;
}

/** ログアウト。DB からセッションを消し、ブラウザの Cookie も消させる */
export function destroySession(
  db: Db,
  config: Config,
  req: FastifyRequest,
  reply: FastifyReply,
): void {
  const rawId = parseCookies(req.headers.cookie).get(cookieName(config));
  if (rawId) deleteSession(db, hashSessionId(rawId));
  void reply.header(
    'set-cookie',
    serializeCookie(cookieName(config), '', { maxAge: 0, secure: config.cookieSecure }),
  );
}
