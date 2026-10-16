import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { loadConfig } from '../../src/config.js';
import { buildApp } from '../../src/server.js';

describe('server', () => {
  let app: FastifyInstance;
  beforeAll(async () => {
    app = buildApp(loadConfig({ NODE_ENV: 'test', DATABASE_PATH: ':memory:' }));
    await app.ready();
  });
  afterAll(async () => {
    await app.close();
  });

  it('GET / はトップ画面の HTML を返す', async () => {
    const res = await app.inject({ method: 'GET', url: '/' });
    expect(res.statusCode).toBe(200);
    expect(res.headers['content-type']).toMatch(/^text\/html/);
    expect(res.body).toContain('<h1>passkey-auth-starter</h1>');
  });

  it('GET /healthz は ok を返す', async () => {
    const res = await app.inject({ method: 'GET', url: '/healthz' });
    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({ status: 'ok' });
  });

  it('ログイン画面のメール欄は条件付き UI（autocomplete="username webauthn"）に対応する（S5）', async () => {
    const res = await app.inject({ method: 'GET', url: '/login' });
    expect(res.statusCode).toBe(200);
    expect(res.body).toContain('autocomplete="username webauthn"');
  });

  it('画面用の JavaScript（app.js と @simplewebauthn/browser）を配る', async () => {
    for (const url of ['/assets/app.js', '/assets/simplewebauthn-browser.js']) {
      const res = await app.inject({ method: 'GET', url });
      expect(res.statusCode).toBe(200);
      expect(res.headers['content-type']).toMatch(/^text\/javascript/);
    }
  });
});
