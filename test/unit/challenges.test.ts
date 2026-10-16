import { describe, expect, it } from 'vitest';
import { ChallengeStore } from '../../src/auth/challenges.js';

describe('ChallengeStore', () => {
  it('1 回取り出したら消える（使い切り）', () => {
    const store = new ChallengeStore();
    const ticket = store.put({ kind: 'login', challenge: 'c1' });
    expect(store.take(ticket, 'login')?.challenge).toBe('c1');
    expect(store.take(ticket, 'login')).toBeUndefined();
  });

  it('5 分を過ぎたら無効', () => {
    let now = 1_000_000;
    const store = new ChallengeStore(() => now);
    const ticket = store.put({ kind: 'login', challenge: 'c1' });
    now += 5 * 60 * 1000;
    expect(store.take(ticket, 'login')).toBeUndefined();
  });

  it('登録用の引換券をログインには使えない', () => {
    const store = new ChallengeStore();
    const ticket = store.put({ kind: 'register', challenge: 'c1', userId: null, email: 'a@example.com' });
    expect(store.take(ticket, 'login')).toBeUndefined();
  });

  it('引換券が無い・知らない値なら undefined', () => {
    const store = new ChallengeStore();
    expect(store.take(undefined, 'login')).toBeUndefined();
    expect(store.take('unknown', 'login')).toBeUndefined();
  });
});
