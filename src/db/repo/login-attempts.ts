// login_attempts 表（S8 / S9）への読み書き。SQL を集める理由は src/db/repo.ts の冒頭を参照。
import type { Db } from '../connection.js';

/**
 * S8 / S9: ログイン試行を記録する。存在しないメールへの試行も email で記録する。
 * 存在するメールだけを数えると、ロックの有無から「登録済みかどうか」が分かってしまうため（列挙防止）。
 */
export function insertLoginAttempt(
  db: Db,
  a: { userId: number | null; email: string; succeeded: boolean; at: number; ip: string | null },
): number {
  const result = db
    .prepare('INSERT INTO login_attempts (user_id, email, succeeded, at, ip) VALUES (?, ?, ?, ?, ?)')
    .run(a.userId, a.email, a.succeeded ? 1 : 0, a.at, a.ip);
  return Number(result.lastInsertRowid);
}

/** S9: 照合の前に「失敗」として予約した行を、照合の結果で書き換える */
export function setLoginAttemptSucceeded(db: Db, id: number, succeeded: boolean): void {
  db.prepare('UPDATE login_attempts SET succeeded = ? WHERE id = ?').run(succeeded ? 1 : 0, id);
}

export interface LoginAttemptRow {
  id: number;
  succeeded: 0 | 1;
  at: number;
}

/** since 以降の試行を古い順に返す */
export function listLoginAttempts(db: Db, email: string, since: number): LoginAttemptRow[] {
  return db
    .prepare('SELECT id, succeeded, at FROM login_attempts WHERE email = ? AND at >= ? ORDER BY at, id')
    .all(email, since) as LoginAttemptRow[];
}
