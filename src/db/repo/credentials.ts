// credentials 表（パスキーの公開鍵）への読み書き。SQL を集める理由は src/db/repo.ts の冒頭を参照。
import type { Db } from '../connection.js';

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
