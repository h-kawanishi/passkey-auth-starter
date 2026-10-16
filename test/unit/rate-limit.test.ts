import Fastify from 'fastify';
import { describe, expect, it } from 'vitest';
import { rateLimitByIp } from '../../src/http/rate-limit.js';

/** 制限を掛けた最小のアプリ。remoteAddress で送信元を変えて試す */
function appWith(limit: ReturnType<typeof rateLimitByIp>) {
  const app = Fastify();
  app.post('/x', { preHandler: limit }, () => ({ ok: true }));
  return app;
}

describe('S8: rateLimitByIp', () => {
  it('同じ IP からの要求が窓の中で上限を超えたら 429 と Retry-After を返す', async () => {
    const app = appWith(rateLimitByIp({ max: 3, windowMs: 60_000 }));
    const codes: number[] = [];
    for (let i = 0; i < 5; i++) {
      codes.push((await app.inject({ method: 'POST', url: '/x', remoteAddress: '192.0.2.1' })).statusCode);
    }
    expect(codes).toEqual([200, 200, 200, 429, 429]);
    const res = await app.inject({ method: 'POST', url: '/x', remoteAddress: '192.0.2.1' });
    expect(Number(res.headers['retry-after'])).toBeGreaterThan(0);
  });

  it('別の IP は数えない', async () => {
    const app = appWith(rateLimitByIp({ max: 1, windowMs: 60_000 }));
    expect((await app.inject({ method: 'POST', url: '/x', remoteAddress: '192.0.2.1' })).statusCode).toBe(200);
    expect((await app.inject({ method: 'POST', url: '/x', remoteAddress: '192.0.2.2' })).statusCode).toBe(200);
  });

  it('窓が切り替われば、また通る', async () => {
    let now = 0;
    const app = appWith(rateLimitByIp({ max: 1, windowMs: 60_000, now: () => now }));
    expect((await app.inject({ method: 'POST', url: '/x' })).statusCode).toBe(200);
    expect((await app.inject({ method: 'POST', url: '/x' })).statusCode).toBe(429);
    now += 60_000;
    expect((await app.inject({ method: 'POST', url: '/x' })).statusCode).toBe(200);
  });
});
