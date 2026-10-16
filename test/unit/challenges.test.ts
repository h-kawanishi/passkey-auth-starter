import { describe, expect, it } from 'vitest';
import { ChallengeStore } from '../../src/auth/challenges.js';

const IP = '192.0.2.1';

describe('ChallengeStore', () => {
  it('1 回取り出したら消える（使い切り）', () => {
    const store = new ChallengeStore();
    const ticket = store.put({ kind: 'login', challenge: 'c1' }, IP);
    expect(store.take(ticket, 'login')?.challenge).toBe('c1');
    expect(store.take(ticket, 'login')).toBeUndefined();
  });

  it('5 分を過ぎたら無効', () => {
    let now = 1_000_000;
    const store = new ChallengeStore({ now: () => now });
    const ticket = store.put({ kind: 'login', challenge: 'c1' }, IP);
    now += 5 * 60 * 1000;
    expect(store.take(ticket, 'login')).toBeUndefined();
  });

  it('登録用の引換券をログインには使えない', () => {
    const store = new ChallengeStore();
    const ticket = store.put({ kind: 'register', challenge: 'c1', userId: null, email: 'a@example.com' }, IP);
    expect(store.take(ticket, 'login')).toBeUndefined();
  });

  it('引換券が無い・知らない値なら undefined', () => {
    const store = new ChallengeStore();
    expect(store.take(undefined, 'login')).toBeUndefined();
    expect(store.take('unknown', 'login')).toBeUndefined();
  });

  it('全体が満杯でも他人の期限内のチャレンジは押し出さず、新しい要求のほうを断る', () => {
    const store = new ChallengeStore({ maxEntries: 100, maxPerOwner: 5 });
    const victim = store.put({ kind: 'login', challenge: 'victim' }, '198.51.100.7');
    // 多数の送信元から置き場を埋める
    let refused = 0;
    for (let i = 0; i < 1000; i++) {
      if (store.put({ kind: 'login', challenge: `x${i}` }, `203.0.113.${i % 250}`) === undefined) refused += 1;
    }
    expect(refused).toBeGreaterThan(0);
    expect(store.take(victim, 'login')?.challenge).toBe('victim');
  });

  it('1 つの送信元が上限を超えたら、その送信元自身の古いものだけを捨てる', () => {
    const store = new ChallengeStore({ maxPerOwner: 3 });
    const other = store.put({ kind: 'login', challenge: 'other' }, '198.51.100.7');
    const first = store.put({ kind: 'login', challenge: 'a1' }, IP);
    for (let i = 0; i < 10; i++) store.put({ kind: 'login', challenge: `a${i + 2}` }, IP);
    const latest = store.put({ kind: 'login', challenge: 'latest' }, IP);
    expect(store.take(first, 'login')).toBeUndefined();
    expect(store.take(latest, 'login')?.challenge).toBe('latest');
    expect(store.take(other, 'login')?.challenge).toBe('other');
  });

  it('期限切れは次の保管のときに片付き、満杯が解ける', () => {
    let now = 1_000_000;
    const store = new ChallengeStore({ now: () => now, maxEntries: 2, maxPerOwner: 2 });
    store.put({ kind: 'login', challenge: 'c1' }, IP);
    store.put({ kind: 'login', challenge: 'c2' }, '198.51.100.7');
    expect(store.put({ kind: 'login', challenge: 'c3' }, '198.51.100.8')).toBeUndefined();
    now += 5 * 60 * 1000;
    expect(store.put({ kind: 'login', challenge: 'c4' }, '198.51.100.8')).toBeTypeOf('string');
  });
});
