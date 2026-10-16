// S12: 監査ログを書く窓口。
import type { FastifyRequest } from 'fastify';
import { insertAuditLog, type AuditDetail } from '../db/repo.js';

/**
 * 監査ログに残すイベント名。文字列を各所で手書きすると綴りの揺れで検索できなくなるため、ここに集める。
 * C（パスキー）・D（回復）はここに追加する。
 */
export type AuditEvent =
  | 'signup'
  | 'login.success'
  | 'login.failure'
  | 'login.locked'
  | 'account.locked'
  | 'logout'
  | 'logout.all'
  | 'password.change'
  | 'password.change.failure';

/**
 * 監査ログを 1 件書く。detail にパスワード・セッション ID などの生値を入れないこと（S12）。
 * IP は「どこから来た攻撃か」を後で調べるために残す。
 */
export function audit(
  request: FastifyRequest,
  event: AuditEvent,
  userId: number | null,
  detail?: AuditDetail,
): void {
  insertAuditLog(request.server.db, {
    userId,
    event,
    ...(detail ? { detail } : {}),
    at: Date.now(),
    ip: request.ip,
  });
}
