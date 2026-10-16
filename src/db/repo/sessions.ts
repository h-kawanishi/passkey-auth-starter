// sessions 表への読み書き。SQL を集める理由は src/db/repo.ts の冒頭を参照。
import type { Db } from '../connection.js';

export interface SessionRow {
  user_id: number;
  created_at: number;
  expires_at: number;
}

/** S7: 受け取るのはセッション ID のハッシュだけ。生の ID はこの層まで降りてこない */
export function insertSession(
  db: Db,
  s: {
    idHash: Buffer;
    userId: number;
    createdAt: number;
    expiresAt: number;
    ip: string | null;
    userAgent: string | null;
  },
): void {
  db.prepare(
    `INSERT INTO sessions (id_hash, user_id, created_at, expires_at, ip, user_agent)
     VALUES (?, ?, ?, ?, ?, ?)`,
  ).run(s.idHash, s.userId, s.createdAt, s.expiresAt, s.ip, s.userAgent);
}

/** 期限内のセッションだけを返す。期限切れを「無い」と同じに扱えば、呼び出し側で期限の比較を忘れられない */
export function findActiveSession(db: Db, idHash: Buffer, now: number): SessionRow | undefined {
  return db
    .prepare('SELECT user_id, created_at, expires_at FROM sessions WHERE id_hash = ? AND expires_at > ?')
    .get(idHash, now) as SessionRow | undefined;
}

export function deleteSession(db: Db, idHash: Buffer): void {
  db.prepare('DELETE FROM sessions WHERE id_hash = ?').run(idHash);
}

/** 全端末ログアウトやパスワード変更で使う。exceptIdHash を渡すと、その 1 つ（今の端末）だけ残す */
export function deleteSessionsOfUser(db: Db, userId: number, exceptIdHash?: Buffer): number {
  const result = exceptIdHash
    ? db.prepare('DELETE FROM sessions WHERE user_id = ? AND id_hash != ?').run(userId, exceptIdHash)
    : db.prepare('DELETE FROM sessions WHERE user_id = ?').run(userId);
  return result.changes;
}

export function deleteExpiredSessions(db: Db, now: number): void {
  db.prepare('DELETE FROM sessions WHERE expires_at <= ?').run(now);
}
