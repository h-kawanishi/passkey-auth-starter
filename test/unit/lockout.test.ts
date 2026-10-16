import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { openDatabase, type Db } from '../../src/db/connection.js';
import { migrate } from '../../src/db/migrate.js';
import {
  LOCKOUT_MS,
  LOCKOUT_THRESHOLD,
  lockedUntil,
  verifyWithLockout,
} from '../../src/auth/lockout.js';
import { createUser, findUserById } from '../../src/db/repo.js';

describe('S9: 連続失敗でのロック', () => {
  let db: Db;
  const email = 'lock@example.com';
  const t0 = 1_700_000_000_000;

  beforeEach(() => {
    vi.useFakeTimers({ toFake: ['Date'] });
    db = openDatabase(':memory:');
    migrate(db);
  });
  afterEach(() => {
    db.close();
    vi.useRealTimers();
  });

  // 記録の時刻を now に固定して数えられるよう、Date.now も合わせる
  const attempt = async (now: number, ok: boolean, userId: number | null = null) => {
    vi.setSystemTime(now);
    const r = await verifyWithLockout(db, { email, userId, ip: '127.0.0.1', now }, () =>
      Promise.resolve(ok),
    );
    return { lockedNow: r.status === 'verified' && r.lockedNow, status: r.status };
  };
  const fail = (now: number, userId: number | null = null) => attempt(now, false, userId);
  const succeed = (now: number) => attempt(now, true);

  it(`${LOCKOUT_THRESHOLD} 回続けて失敗するとロックし、${LOCKOUT_MS / 60000} 分で解ける`, async () => {
    for (let i = 0; i < LOCKOUT_THRESHOLD - 1; i++) {
      expect((await fail(t0 + i)).lockedNow).toBe(false);
    }
    expect(lockedUntil(db, email, t0 + 10)).toBeNull();
    const last = t0 + LOCKOUT_THRESHOLD;
    expect((await fail(last)).lockedNow).toBe(true);
    expect(lockedUntil(db, email, last + 1)).toBe(last + LOCKOUT_MS);
    expect(lockedUntil(db, email, last + LOCKOUT_MS)).toBeNull();
  });

  it('途中で成功すると数え直す', async () => {
    for (let i = 0; i < LOCKOUT_THRESHOLD - 1; i++) await fail(t0 + i);
    await succeed(t0 + 100);
    for (let i = 0; i < LOCKOUT_THRESHOLD - 1; i++) await fail(t0 + 200 + i);
    expect(lockedUntil(db, email, t0 + 300)).toBeNull();
  });

  it('ロックが明けたら 0 から数え直す（明けた直後の 1 回の失敗で再びロックしない）', async () => {
    for (let i = 0; i < LOCKOUT_THRESHOLD; i++) await fail(t0 + i);
    const after = t0 + LOCKOUT_THRESHOLD + LOCKOUT_MS;
    expect((await fail(after)).lockedNow).toBe(false);
    expect(lockedUntil(db, email, after + 1)).toBeNull();
  });

  it('存在する利用者なら users.locked_until に記録し、解除後も残す', async () => {
    const userId = createUser(db, { email, passwordHash: null, now: t0 });
    expect(userId).not.toBeNull();
    for (let i = 0; i < LOCKOUT_THRESHOLD; i++) await fail(t0 + i, userId);
    const until = findUserById(db, userId!)?.locked_until;
    expect(until).toBe(t0 + LOCKOUT_THRESHOLD - 1 + LOCKOUT_MS);
    expect(lockedUntil(db, email, until! + 1)).toBeNull();
    expect(findUserById(db, userId!)?.locked_until).toBe(until);
  });

  it('ロック中は照合せず、記録も増やさない', async () => {
    for (let i = 0; i < LOCKOUT_THRESHOLD; i++) await fail(t0 + i);
    let called = false;
    const r = await verifyWithLockout(db, { email, userId: null, ip: null, now: t0 + 10 }, () => {
      called = true;
      return Promise.resolve(true);
    });
    expect(r.status).toBe('locked');
    expect(called).toBe(false);
    expect(db.prepare('SELECT COUNT(*) FROM login_attempts').pluck().get()).toBe(LOCKOUT_THRESHOLD);
  });

  it('照合中の要求も失敗として数えるので、同時に来た要求は上限を超えて照合されない', async () => {
    vi.setSystemTime(t0);
    // 照合がまだ終わっていない要求を上限の数だけ作る（同時に届いた束の再現）
    const inFlight = Array.from({ length: LOCKOUT_THRESHOLD }, () =>
      verifyWithLockout(db, { email, userId: null, ip: null, now: t0 }, () => new Promise<boolean>(() => {})),
    );
    expect(inFlight).toHaveLength(LOCKOUT_THRESHOLD);
    let called = false;
    const late = await verifyWithLockout(db, { email, userId: null, ip: null, now: t0 }, () => {
      called = true;
      return Promise.resolve(true);
    });
    expect(late.status).toBe('locked');
    expect(called).toBe(false);
  });
});
