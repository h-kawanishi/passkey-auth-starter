// users / credentials / sessions / reset_tokens / login_attempts / audit_log への読み書き。
// SQL はこのファイルに集め、ルートや auth/ からは関数として呼ぶ（SQL がアプリ中に散らばると、
// 「秘密の生値を保存していないか」をレビューで確かめにくくなるため）。
//
// TODO(B): users（パスワード関連）・login_attempts の読み書き
// TODO(D): reset_tokens の読み書き
// TODO(D: B と統合): セッション C は users / sessions / audit_log について、パスキーに要る最小の関数だけを
//   置いている。B が同じ役割の関数を持ち込んだら、名前と引数をそろえて片方に寄せる。
import type { Db } from './connection.js';

// ---------------------------------------------------------------- users（C が使う最小限）

export interface UserRow {
  id: number;
  email: string;
}

export function findUserByEmail(db: Db, email: string): UserRow | undefined {
  return db.prepare('SELECT id, email FROM users WHERE email = ?').get(email) as UserRow | undefined;
}

export function findUserById(db: Db, id: number): UserRow | undefined {
  return db.prepare('SELECT id, email FROM users WHERE id = ?').get(id) as UserRow | undefined;
}

/** パスキーだけで登録するユーザーを作る。password_hash は NULL（§5: 「パスキーのみ」のユーザー） */
export function insertPasskeyOnlyUser(db: Db, email: string, now: number): number {
  const result = db
    .prepare('INSERT INTO users (email, password_hash, created_at) VALUES (?, NULL, ?)')
    .run(email, now);
  return Number(result.lastInsertRowid);
}

/** パスワードを持っているか。最後のパスキーを消すと入れなくなる人を守る判定に使う */
export function userHasPassword(db: Db, userId: number): boolean {
  const v = db.prepare('SELECT password_hash IS NOT NULL FROM users WHERE id = ?').pluck().get(userId);
  return v === 1;
}

// ---------------------------------------------------------------- credentials

export interface CredentialRow {
  id: number;
  userId: number;
  /** 認証器が発行した ID（バイト列） */
  credentialId: Buffer;
  /** 公開鍵（COSE 形式のバイト列）。漏れてもログインには使えない */
  publicKey: Buffer;
  counter: number;
  transports: string[];
  deviceName: string;
  createdAt: number;
  lastUsedAt: number | null;
}

interface CredentialDbRow {
  id: number;
  user_id: number;
  credential_id: Buffer;
  public_key: Buffer;
  counter: number;
  transports: string;
  device_name: string;
  created_at: number;
  last_used_at: number | null;
}

function toCredential(row: CredentialDbRow): CredentialRow {
  return {
    id: row.id,
    userId: row.user_id,
    credentialId: row.credential_id,
    publicKey: row.public_key,
    counter: row.counter,
    transports: JSON.parse(row.transports) as string[],
    deviceName: row.device_name,
    createdAt: row.created_at,
    lastUsedAt: row.last_used_at,
  };
}

export interface NewCredential {
  userId: number;
  credentialId: Uint8Array;
  publicKey: Uint8Array;
  counter: number;
  transports: string[];
  deviceName: string;
  createdAt: number;
}

export function insertCredential(db: Db, c: NewCredential): number {
  const result = db
    .prepare(
      `INSERT INTO credentials (user_id, credential_id, public_key, counter, transports, device_name, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
    )
    .run(
      c.userId,
      Buffer.from(c.credentialId),
      Buffer.from(c.publicKey),
      c.counter,
      JSON.stringify(c.transports),
      c.deviceName,
      c.createdAt,
    );
  return Number(result.lastInsertRowid);
}

/** ログイン時、認証器が返した credential ID から公開鍵を引く */
export function findCredentialByCredentialId(db: Db, credentialId: Uint8Array): CredentialRow | undefined {
  const row = db
    .prepare('SELECT * FROM credentials WHERE credential_id = ?')
    .get(Buffer.from(credentialId)) as CredentialDbRow | undefined;
  return row && toCredential(row);
}

export function listCredentialsByUser(db: Db, userId: number): CredentialRow[] {
  const rows = db
    .prepare('SELECT * FROM credentials WHERE user_id = ? ORDER BY created_at, id')
    .all(userId) as CredentialDbRow[];
  return rows.map(toCredential);
}

/**
 * S6: ログイン成功時に署名カウンタと最終利用日時を進める。
 * 「今より大きい値にしか更新しない」条件を SQL にも入れ、同時に 2 つの要求が来ても巻き戻らないようにする。
 */
export function updateCredentialAfterLogin(
  db: Db,
  id: number,
  newCounter: number,
  now: number,
): void {
  db.prepare(
    `UPDATE credentials SET counter = MAX(counter, ?), last_used_at = ? WHERE id = ?`,
  ).run(newCounter, now, id);
}

/**
 * 名前変更と削除は「そのユーザーのものか」を必ず WHERE に含める。
 * id だけで更新すると、他人のパスキー番号を指定した要求で他人の鍵を消せてしまう（IDOR）。
 */
export function renameCredential(db: Db, userId: number, id: number, deviceName: string): boolean {
  const r = db
    .prepare('UPDATE credentials SET device_name = ? WHERE id = ? AND user_id = ?')
    .run(deviceName, id, userId);
  return r.changes === 1;
}

export function deleteCredential(db: Db, userId: number, id: number): boolean {
  const r = db.prepare('DELETE FROM credentials WHERE id = ? AND user_id = ?').run(id, userId);
  return r.changes === 1;
}

export function countCredentialsByUser(db: Db, userId: number): number {
  return db.prepare('SELECT count(*) FROM credentials WHERE user_id = ?').pluck().get(userId) as number;
}

// ---------------------------------------------------------------- sessions（C の最小実装。D で B と統合）

export interface NewSession {
  idHash: Buffer;
  userId: number;
  createdAt: number;
  expiresAt: number;
  ip: string | null;
  userAgent: string | null;
}

export function insertSession(db: Db, s: NewSession): void {
  db.prepare(
    `INSERT INTO sessions (id_hash, user_id, created_at, expires_at, ip, user_agent)
     VALUES (?, ?, ?, ?, ?, ?)`,
  ).run(s.idHash, s.userId, s.createdAt, s.expiresAt, s.ip, s.userAgent);
}

/** 有効期限内のセッションに紐づくユーザーを返す。期限切れは見つからない扱いにする */
export function findSessionUser(db: Db, idHash: Buffer, now: number): UserRow | undefined {
  return db
    .prepare(
      `SELECT users.id, users.email FROM sessions
       JOIN users ON users.id = sessions.user_id
       WHERE sessions.id_hash = ? AND sessions.expires_at > ?`,
    )
    .get(idHash, now) as UserRow | undefined;
}

export function deleteSession(db: Db, idHash: Buffer): void {
  db.prepare('DELETE FROM sessions WHERE id_hash = ?').run(idHash);
}

// ---------------------------------------------------------------- audit_log（C の最小実装。D で仕上げる）

export interface AuditEntry {
  userId: number | null;
  event: string;
  /** S12: パスワード・トークン・セッション ID などの生値は入れない。呼び出し側で番号や名前だけを渡す */
  detail?: Record<string, string | number | boolean | null>;
  ip: string | null;
  at: number;
}

export function insertAuditLog(db: Db, e: AuditEntry): void {
  db.prepare('INSERT INTO audit_log (user_id, event, detail, at, ip) VALUES (?, ?, ?, ?, ?)').run(
    e.userId,
    e.event,
    JSON.stringify(e.detail ?? {}),
    e.at,
    e.ip,
  );
}
