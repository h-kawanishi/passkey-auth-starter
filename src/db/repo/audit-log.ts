// audit_log 表（S12）への読み書き。SQL を集める理由は src/db/repo.ts の冒頭を参照。
import type { Db } from '../connection.js';

/**
 * S12: 監査ログを 1 件書く。detail にはパスワード・トークン・セッション ID の生値を入れない。
 * 何を入れてよいかを呼び出し側の注意だけに頼らないよう、型で「短い文字列・数値・真偽値」に絞っている。
 */
export type AuditDetail = Record<string, string | number | boolean | null>;

export function insertAuditLog(
  db: Db,
  e: { userId: number | null; event: string; detail?: AuditDetail; at: number; ip: string | null },
): void {
  db.prepare('INSERT INTO audit_log (user_id, event, detail, at, ip) VALUES (?, ?, ?, ?, ?)').run(
    e.userId,
    e.event,
    JSON.stringify(e.detail ?? {}),
    e.at,
    e.ip,
  );
}

