// sessions 表への読み書き。SQL を集める理由は src/db/repo.ts の冒頭を参照。
import type { Db } from '../connection.js';

export interface SessionRow {
  user_id: number;
  created_at: number;
  expires_at: number;
  /** 最後に本人確認した時刻（ログイン・再認証）。NULL はまだしていない（002 より前のセッション） */
  reauthenticated_at: number | null;
}

/** S7: 受け取るのはセッション ID のハッシュだけ。生の ID はこの層まで降りてこない */
export function insertSession(
  db: Db,
  s: {
    idHash: Buffer;
    userId: number;
    createdAt: number;
    expiresAt: number;
    reauthenticatedAt: number;
    ip: string | null;
    userAgent: string | null;
  },
): void {
  db.prepare(
    `INSERT INTO sessions (id_hash, user_id, created_at, expires_at, reauthenticated_at, ip, user_agent)
     VALUES (?, ?, ?, ?, ?, ?, ?)`,
  ).run(s.idHash, s.userId, s.createdAt, s.expiresAt, s.reauthenticatedAt, s.ip, s.userAgent);
}

/** 期限内のセッションだけを返す。期限切れを「無い」と同じに扱えば、呼び出し側で期限の比較を忘れられない */
export function findActiveSession(db: Db, idHash: Buffer, now: number): SessionRow | undefined {
  return db
    .prepare(
      `SELECT user_id, created_at, expires_at, reauthenticated_at
       FROM sessions WHERE id_hash = ? AND expires_at > ?`,
    )
    .get(idHash, now) as SessionRow | undefined;
}

/**
 * 再認証に成功したセッションの時刻を書き換える。id_hash だけでなく user_id も条件に入れるのは、
 * 確かめた本人とは別の人のセッションに「確認済み」を付けてしまう取り違えを SQL の段階で起こさないため。
 * 期限切れのセッションは対象にしない。書き換えた行が無ければ false
 */
export function setSessionReauthenticatedAt(db: Db, idHash: Buffer, userId: number, at: number): boolean {
  const result = db
    .prepare('UPDATE sessions SET reauthenticated_at = ? WHERE id_hash = ? AND user_id = ? AND expires_at > ?')
    .run(at, idHash, userId, at);
  return result.changes === 1;
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
