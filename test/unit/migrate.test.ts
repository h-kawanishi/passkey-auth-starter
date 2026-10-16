import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { openDatabase, type Db } from '../../src/db/connection.js';
import { migrate } from '../../src/db/migrate.js';

describe('migrate', () => {
  let db: Db;
  beforeEach(() => {
    db = openDatabase(':memory:');
  });
  afterEach(() => {
    db.close();
  });

  it('§5 の表をすべて作る', () => {
    const { applied } = migrate(db);
    expect(applied).toEqual(['001_init.sql']);

    const tables = db
      .prepare("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")
      .pluck()
      .all();
    expect(tables).toEqual([
      'audit_log',
      'credentials',
      'login_attempts',
      'reset_tokens',
      'schema_migrations',
      'sessions',
      'users',
    ]);
  });

  it('2 回目は何も適用しない（何度実行しても壊れない）', () => {
    migrate(db);
    expect(migrate(db).applied).toEqual([]);
  });

  it('セッションと再設定トークンは生値の列を持たず、ハッシュだけを持つ（S7, S10）', () => {
    migrate(db);
    const columns = (table: string): unknown[] =>
      db.prepare(`SELECT name FROM pragma_table_info(?)`).pluck().all(table);
    expect(columns('sessions')).toContain('id_hash');
    expect(columns('sessions')).not.toContain('id');
    expect(columns('reset_tokens')).toContain('token_hash');
    expect(columns('reset_tokens')).not.toContain('token');
  });

  it('外部キーが有効で、ユーザー削除でパスキーとセッションも消える', () => {
    migrate(db);
    const now = Date.now();
    const userId = db
      .prepare('INSERT INTO users (email, created_at) VALUES (?, ?)')
      .run('user@example.com', now).lastInsertRowid;
    db.prepare(
      `INSERT INTO credentials (user_id, credential_id, public_key, device_name, created_at)
       VALUES (?, ?, ?, ?, ?)`,
    ).run(userId, Buffer.from([1]), Buffer.from([2]), 'test', now);
    db.prepare(
      'INSERT INTO sessions (id_hash, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)',
    ).run(Buffer.from([3]), userId, now, now + 1000);

    // 存在しないユーザーへの参照は拒否される
    expect(() =>
      db
        .prepare('INSERT INTO sessions (id_hash, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)')
        .run(Buffer.from([4]), 9999, now, now),
    ).toThrow(/FOREIGN KEY/);

    db.prepare('DELETE FROM users WHERE id = ?').run(userId);
    expect(db.prepare('SELECT count(*) FROM credentials').pluck().get()).toBe(0);
    expect(db.prepare('SELECT count(*) FROM sessions').pluck().get()).toBe(0);
  });
});
