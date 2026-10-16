// users / credentials / sessions / reset_tokens / login_attempts / audit_log への読み書き。
// SQL はこのファイルに集め、ルートや auth/ からは関数として呼ぶ（SQL がアプリ中に散らばると、
// 「秘密の生値を保存していないか」をレビューで確かめにくくなるため）。
//
// TODO(C): credentials の読み書き
// TODO(D): reset_tokens の読み書き
import type { Db } from './connection.js';

// ---- users -------------------------------------------------------------------

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

// ---- sessions ----------------------------------------------------------------

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

// ---- login_attempts ----------------------------------------------------------

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

// ---- audit_log ---------------------------------------------------------------

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
