// セッションの発行・検証・失効。
// パスワードとパスキーのどちらで入っても同じ仕組みのセッションになるよう、「今のユーザーを得る」「ログイン状態にする」を
// ここの関数として公開する。
import { createHmac, randomBytes } from 'node:crypto';
import type { FastifyReply, FastifyRequest } from 'fastify';
import {
  deleteExpiredSessions,
  deleteSession,
  deleteSessionsOfUser,
  findActiveSession,
  findUserById,
  insertSession,
  setSessionReauthenticatedAt,
  type UserRow,
} from '../db/repo.js';

/** ログイン状態を保つ時間。長すぎると盗まれた Cookie が長く使え、短すぎると何度もログインさせることになる */
export const SESSION_TTL_MS = 24 * 60 * 60 * 1000;

/**
 * パスキーの追加の前に求める「直近の本人確認」の有効時間（人間の判断 2、threat-model.md §4）。
 * Cookie を盗んだ攻撃者に自分の認証器を登録させないため、Cookie だけでなく直前の本人確認を求める。
 * 短いほど盗まれた Cookie で使える時間は減るが、確認してから追加の操作を終えるまでの時間は要る
 */
export const REAUTH_MAX_AGE_MS = 5 * 60 * 1000;

/**
 * Cookie の名前。本番は `__Host-` 接頭辞を付ける。ブラウザはこの名前の Cookie を
 * 「Secure 付き・Path=/・Domain 指定なし」でしか受け付けないので、サブドメインからの上書きを防げる。
 * 開発（http://localhost）では Secure を付けられないため、接頭辞なしの名前を使う。
 */
export function sessionCookieName(request: FastifyRequest): string {
  return request.server.config.cookieSecure ? '__Host-sid' : 'sid';
}

/**
 * S7: DB にはセッション ID そのものではなく、SESSION_SECRET を鍵にした HMAC-SHA256 だけを保存する。
 * DB が漏れても、鍵が無ければそこから有効な Cookie を作れない。
 */
function hashSessionId(request: FastifyRequest, rawId: string): Buffer {
  return createHmac('sha256', request.server.config.sessionSecret).update(rawId).digest();
}

function rawSessionId(request: FastifyRequest): string | undefined {
  const value = request.cookies[sessionCookieName(request)];
  // 256bit を base64url にすると 43 文字。形の違う値は DB を引く前に捨てる
  return value !== undefined && /^[A-Za-z0-9_-]{43}$/.test(value) ? value : undefined;
}

/**
 * ログイン状態にする（新しいセッションを発行して Cookie に入れる）。
 * ログインのたびに新しい ID を作るので、ログイン前に仕込まれた ID をそのまま使わされる
 * 「セッション固定攻撃」が成り立たない。
 */
export function startSession(request: FastifyRequest, reply: FastifyReply, userId: number): void {
  const db = request.server.db;
  const now = Date.now();
  // S7: 256bit の乱数。推測で他人のセッションに当てることは現実的にできない
  const rawId = randomBytes(32).toString('base64url');
  // すでに Cookie が指すセッションがあれば消しておく。古い ID が残ると、その Cookie が盗まれていた場合に
  // 新しい ID を発行した後も使われ続けてしまう
  const previous = currentSessionIdHash(request);
  if (previous) deleteSession(db, previous);
  // 期限切れの行がたまり続けないよう、発行のついでに掃除する
  deleteExpiredSessions(db, now);
  insertSession(db, {
    idHash: hashSessionId(request, rawId),
    userId,
    createdAt: now,
    expiresAt: now + SESSION_TTL_MS,
    // ログインそのものが本人確認なので、発行した時刻を「最後に本人確認した時刻」にする
    reauthenticatedAt: now,
    ip: request.ip,
    userAgent: request.headers['user-agent']?.slice(0, 512) ?? null,
  });
  void reply.setCookie(sessionCookieName(request), rawId, {
    // S7: HttpOnly。ページの JavaScript から読めないので、XSS があっても Cookie を盗み出せない
    httpOnly: true,
    // S7/S13: SameSite=Lax。他サイトから送られる POST には Cookie が付かない
    sameSite: 'lax',
    // S7: 本番（https）では Secure。平文の通信路に Cookie を流さない
    secure: request.server.config.cookieSecure,
    path: '/',
    maxAge: SESSION_TTL_MS / 1000,
  });
}

export interface CurrentUser {
  id: number;
  email: string;
  /** false は「パスキーのみ」のユーザー。画面がパスワード変更の代わりに再設定の案内を出すために使う */
  hasPassword: boolean;
  /** このセッションで最後に本人確認した時刻（ログイン・再認証）。null はまだしていない */
  reauthenticatedAt: number | null;
}

/** 今のリクエストのログインユーザー。ログインしていなければ null */
export function currentUser(request: FastifyRequest): CurrentUser | null {
  const rawId = rawSessionId(request);
  if (rawId === undefined) return null;
  const db = request.server.db;
  const session = findActiveSession(db, hashSessionId(request, rawId), Date.now());
  if (!session) return null;
  const user: UserRow | undefined = findUserById(db, session.user_id);
  if (!user) return null;
  return {
    id: user.id,
    email: user.email,
    hasPassword: user.password_hash !== null,
    reauthenticatedAt: session.reauthenticated_at,
  };
}

/** このセッションで、直近 REAUTH_MAX_AGE_MS 以内に本人確認しているか */
export function isRecentlyReauthenticated(user: CurrentUser, now = Date.now()): boolean {
  return user.reauthenticatedAt !== null && now - user.reauthenticatedAt <= REAUTH_MAX_AGE_MS;
}

/**
 * 今のセッション（この端末の Cookie が指すもの）に「今、本人確認した」と記録する。
 * 記録先は今のセッションだけ。同じ人の別の端末のセッションや、他人のセッションには付けない
 */
export function markReauthenticated(request: FastifyRequest, userId: number): boolean {
  const idHash = currentSessionIdHash(request);
  if (!idHash) return false;
  return setSessionReauthenticatedAt(request.server.db, idHash, userId, Date.now());
}

/** 今のセッションの ID ハッシュ。「この端末以外をログアウト」のときに残す 1 つを指すために使う */
export function currentSessionIdHash(request: FastifyRequest): Buffer | undefined {
  const rawId = rawSessionId(request);
  return rawId === undefined ? undefined : hashSessionId(request, rawId);
}

/** この端末のセッションを失効させ、Cookie も消す */
export function endSession(request: FastifyRequest, reply: FastifyReply): void {
  const idHash = currentSessionIdHash(request);
  if (idHash) deleteSession(request.server.db, idHash);
  clearSessionCookie(request, reply);
}

/** その利用者の全セッションを失効させる。keepCurrent なら今の端末だけ残す（パスワード変更後など） */
export function endAllSessions(
  request: FastifyRequest,
  userId: number,
  options: { keepCurrent: boolean },
): number {
  const keep = options.keepCurrent ? currentSessionIdHash(request) : undefined;
  return deleteSessionsOfUser(request.server.db, userId, keep);
}

export function clearSessionCookie(request: FastifyRequest, reply: FastifyReply): void {
  void reply.clearCookie(sessionCookieName(request), {
    httpOnly: true,
    sameSite: 'lax',
    secure: request.server.config.cookieSecure,
    path: '/',
  });
}

/**
 * ログインが必要な API の入口で使う。未ログインなら 401 を返して null。
 * 使い方: `const user = requireUser(request, reply); if (!user) return reply;`
 */
export function requireUser(request: FastifyRequest, reply: FastifyReply): CurrentUser | null {
  const user = currentUser(request);
  if (!user) {
    void reply.code(401).send({ message: 'ログインしてください' });
    return null;
  }
  return user;
}
