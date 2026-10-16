import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { loadConfig } from '../../src/config.js';
import { buildApp } from '../../src/server.js';

describe('server', () => {
  let app: FastifyInstance;
  beforeAll(async () => {
    // DATABASE_PATH を指定しないと ./data/app.sqlite を作ってしまうので、メモリ上の DB にする
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
});
