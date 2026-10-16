import { createHash, randomBytes } from 'node:crypto';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  RESET_TOKEN_TTL_MS,
  consumeResetToken,
  hashResetToken,
  issueResetToken,
  resetLink,
} from '../../src/auth/reset.js';
import { openDatabase, type Db } from '../../src/db/connection.js';
import { migrate } from '../../src/db/migrate.js';
import { createUser } from '../../src/db/repo.js';

let db: Db;
let userId: number;
const T0 = 1_800_000_000_000;

beforeEach(() => {
  db = openDatabase(':memory:');
  migrate(db);
  userId = createUser(db, { email: 'a@example.com', passwordHash: null, now: T0 })!;
});
afterEach(() => db.close());

describe('S10: 再設定トークン', () => {
  it('256bit の乱数（43 文字の base64url）で、DB にはハッシュしか無い', () => {
    const token = issueResetToken(db, userId, T0);
    expect(token).toMatch(/^[A-Za-z0-9_-]{43}$/);
    const rows = db.prepare('SELECT * FROM reset_tokens').all() as Record<string, unknown>[];
    expect(rows).toHaveLength(1);
    const dump = rows
      .flatMap((r) => Object.values(r))
      .map((v) => (Buffer.isBuffer(v) ? `${v.toString('utf8')}|${v.toString('hex')}|${v.toString('base64url')}` : String(v)))
      .join('\n');
    expect(dump).not.toContain(token);
    expect(dump).not.toContain(Buffer.from(token).toString('hex'));
    // 保存されているのは SHA-256 そのもの
    expect(rows[0]!.token_hash).toEqual(createHash('sha256').update(token).digest());
    expect(hashResetToken(token)).toEqual(rows[0]!.token_hash);
  });

  it('1 回使うと無効になる', () => {
    const token = issueResetToken(db, userId, T0);
    expect(consumeResetToken(db, token, T0 + 1000)).toBe(userId);
    expect(consumeResetToken(db, token, T0 + 2000)).toBeUndefined();
  });

  it('15 分で無効になる（15 分ちょうどで使えない、その直前は使える）', () => {
    const late = issueResetToken(db, userId, T0);
    expect(consumeResetToken(db, late, T0 + RESET_TOKEN_TTL_MS)).toBeUndefined();
    const inTime = issueResetToken(db, userId, T0);
    expect(consumeResetToken(db, inTime, T0 + RESET_TOKEN_TTL_MS - 1)).toBe(userId);
    expect(RESET_TOKEN_TTL_MS).toBe(15 * 60 * 1000);
  });

  it('新しいトークンを発行すると、同じ人の古い未使用のトークンは使えなくなる', () => {
    const first = issueResetToken(db, userId, T0);
    const second = issueResetToken(db, userId, T0 + 1000);
    expect(consumeResetToken(db, first, T0 + 2000)).toBeUndefined();
    expect(consumeResetToken(db, second, T0 + 2000)).toBe(userId);
  });

  it('発行していない値・形の違う値は通らない', () => {
    issueResetToken(db, userId, T0);
    expect(consumeResetToken(db, randomBytes(32).toString('base64url'), T0)).toBeUndefined();
    expect(consumeResetToken(db, '', T0)).toBeUndefined();
    expect(consumeResetToken(db, "' OR 1=1 --", T0)).toBeUndefined();
  });

  it('リンクはトークンを # の後ろ（サーバーへ送られない部分）に置く', () => {
    const link = resetLink('https://example.com', 'abc');
    expect(link).toBe('https://example.com/reset/new#token=abc');
    expect(new URL(link).pathname).toBe('/reset/new');
  });
});
