// S12: 監査ログを書く窓口。
import type { FastifyRequest } from 'fastify';
import { insertAuditLog, type AuditDetail } from '../db/repo.js';

/**
 * 監査ログに残すイベント名の一覧。文字列を各所で手書きすると綴りの揺れで検索できなくなるため、ここに集める。
 * 一覧を配列（値）としても持つのは、「すべてのイベントが実際に記録されるか」をテストで確かめるため
 * （test/integration/audit.test.ts）。イベントを足したら、そのテストにも記録させる手順を足す。
 */
export const AUDIT_EVENTS = [
  // 登録（パスワード・パスキーとも。detail.method で見分ける）
  'signup',
  // パスワードでのログイン
  'login.success',
  'login.failure',
  'login.locked',
  // S9: この失敗でアカウントのロックが始まった（パスワードの照合の失敗だけが数えられる。パスキーは対象外）
  'account.locked',
  'logout',
  'logout.all',
  'password.change',
  'password.change.failure',
  // パスキー（C）
  'passkey.register',
  'passkey.register.failure',
  'passkey.login.success',
  'passkey.login.failure',
  'passkey.rename',
  'passkey.delete',
  // 再認証（パスキーの追加の前の本人確認）。detail.method で password / passkey を見分ける
  'reauth',
  'reauth.failure',
  // パスワード再設定（D, S10）。request は「登録済みのメールで受け付けた」ときだけ user_id が入る
  'password.reset.request',
  'password.reset.complete',
  'password.reset.failure',
] as const;

export type AuditEvent = (typeof AUDIT_EVENTS)[number];

/**
 * 監査ログを 1 件書く。detail にパスワード・セッション ID・再設定トークンなどの生値を入れないこと（S12）。
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
