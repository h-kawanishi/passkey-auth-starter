// users 表への読み書き。SQL を集める理由は src/db/repo.ts の冒頭を参照。
import type { Db } from '../connection.js';

export interface UserRow {
  id: number;
  email: string;
  /** S1: Argon2id の PHC 文字列。NULL は「パスキーのみ」のユーザー（C の範囲） */
  password_hash: string | null;
  created_at: number;
  locked_until: number | null;
}

/**
 * 利用者を作る。メールが既に使われていれば null を返す。
 * 「探してから入れる」と、同時に 2 つの登録が来たときに両方が通り抜けうるため、
 * UNIQUE 制約に任せて INSERT の失敗で判定する。
 */
export function createUser(
  db: Db,
  user: { email: string; passwordHash: string | null; now: number },
): number | null {
  try {
    const result = db
      .prepare('INSERT INTO users (email, password_hash, created_at) VALUES (?, ?, ?)')
      .run(user.email, user.passwordHash, user.now);
    return Number(result.lastInsertRowid);
  } catch (err) {
    if (isUniqueViolation(err)) return null;
    throw err;
  }
}

function isUniqueViolation(err: unknown): boolean {
  return (
    typeof err === 'object' &&
    err !== null &&
    'code' in err &&
    err.code === 'SQLITE_CONSTRAINT_UNIQUE'
  );
}

export function findUserByEmail(db: Db, email: string): UserRow | undefined {
  return db.prepare('SELECT * FROM users WHERE email = ?').get(email) as UserRow | undefined;
}

export function findUserById(db: Db, id: number): UserRow | undefined {
  return db.prepare('SELECT * FROM users WHERE id = ?').get(id) as UserRow | undefined;
}

export function updatePasswordHash(db: Db, userId: number, passwordHash: string): void {
  db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(passwordHash, userId);
}

/** S9: ロックの終了時刻を記録する。解除後も値は残し、「いつロックされたか」を後から追えるようにする */
export function setLockedUntil(db: Db, userId: number, lockedUntil: number): void {
  db.prepare('UPDATE users SET locked_until = ? WHERE id = ?').run(lockedUntil, userId);
}
