import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { openDatabase, type Db } from '../../src/db/connection.js';
import { migrate } from '../../src/db/migrate.js';
import {
  LOCKOUT_MS,
  LOCKOUT_THRESHOLD,
  lockedUntil,
  recordLoginAttempt,
} from '../../src/auth/lockout.js';
import { createUser, findUserById } from '../../src/db/repo.js';

describe('S9: 連続失敗でのロック', () => {
  let db: Db;
  const email = 'lock@example.com';
  const t0 = 1_700_000_000_000;

  beforeEach(() => {
    db = openDatabase(':memory:');
    migrate(db);
  });
  afterEach(() => db.close());

  const fail = (now: number, userId: number | null = null) =>
    recordLoginAttempt(db, { email, userId, succeeded: false, ip: '127.0.0.1', now });
  const succeed = (now: number) =>
    recordLoginAttempt(db, { email, userId: null, succeeded: true, ip: '127.0.0.1', now });

  it(`${LOCKOUT_THRESHOLD} 回続けて失敗するとロックし、${LOCKOUT_MS / 60000} 分で解ける`, () => {
    for (let i = 0; i < LOCKOUT_THRESHOLD - 1; i++) {
      expect(fail(t0 + i).lockedNow).toBe(false);
    }
    expect(lockedUntil(db, email, t0 + 10)).toBeNull();
    const last = t0 + LOCKOUT_THRESHOLD;
    expect(fail(last).lockedNow).toBe(true);
    expect(lockedUntil(db, email, last + 1)).toBe(last + LOCKOUT_MS);
    expect(lockedUntil(db, email, last + LOCKOUT_MS)).toBeNull();
  });

  it('途中で成功すると数え直す', () => {
    for (let i = 0; i < LOCKOUT_THRESHOLD - 1; i++) fail(t0 + i);
    succeed(t0 + 100);
    for (let i = 0; i < LOCKOUT_THRESHOLD - 1; i++) fail(t0 + 200 + i);
    expect(lockedUntil(db, email, t0 + 300)).toBeNull();
  });

  it('ロックが明けたら 0 から数え直す（明けた直後の 1 回の失敗で再びロックしない）', () => {
    for (let i = 0; i < LOCKOUT_THRESHOLD; i++) fail(t0 + i);
    const after = t0 + LOCKOUT_THRESHOLD + LOCKOUT_MS;
    expect(fail(after).lockedNow).toBe(false);
    expect(lockedUntil(db, email, after + 1)).toBeNull();
  });

  it('存在する利用者なら users.locked_until に記録し、解除後も残す', () => {
    const userId = createUser(db, { email, passwordHash: null, now: t0 });
    expect(userId).not.toBeNull();
    for (let i = 0; i < LOCKOUT_THRESHOLD; i++) fail(t0 + i, userId);
    const until = findUserById(db, userId!)?.locked_until;
    expect(until).toBe(t0 + LOCKOUT_THRESHOLD - 1 + LOCKOUT_MS);
    expect(lockedUntil(db, email, until! + 1)).toBeNull();
    expect(findUserById(db, userId!)?.locked_until).toBe(until);
  });
});
