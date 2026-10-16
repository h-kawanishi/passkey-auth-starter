import { randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { ConfigError, loadConfig } from '../../src/config.js';

// テストのたびに作る。固定の秘密をリポジトリに書かないため（CLAUDE.md）
const secret = (): string => randomBytes(32).toString('base64url');

describe('loadConfig', () => {
  it('何も設定しなくても開発用の既定値で起動できる（README の 5 分手順のため）', () => {
    const config = loadConfig({});
    expect(config.nodeEnv).toBe('development');
    expect(config.port).toBe(3000);
    expect(config.rpId).toBe('localhost');
    expect(config.origin).toBe('http://localhost:3000');
    expect(config.cookieSecure).toBe(false);
    expect(config.sessionSecretIsEphemeral).toBe(true);
    expect(config.sessionSecret.length).toBeGreaterThanOrEqual(32);
  });

  it('本番では SESSION_SECRET と https の ORIGIN を必須にし、Cookie を Secure にする（S7）', () => {
    expect(() => loadConfig({ NODE_ENV: 'production', ORIGIN: 'http://localhost:3000' })).toThrow(
      ConfigError,
    );

    const config = loadConfig({
      NODE_ENV: 'production',
      RP_ID: 'example.com',
      ORIGIN: 'https://login.example.com',
      SESSION_SECRET: secret(),
    });
    expect(config.cookieSecure).toBe(true);
    expect(config.sessionSecretIsEphemeral).toBe(false);
  });

  it('RP_ID が ORIGIN のホスト名と合わなければ拒否する（S5: RP ID はドメイン固定）', () => {
    expect(() => loadConfig({ RP_ID: 'example.com', ORIGIN: 'https://evil-example.com' })).toThrow(
      /RP_ID/,
    );
  });

  it('誤りをまとめて報告し、秘密の値そのものはエラー文に含めない', () => {
    const shortSecret = 'too-short-secret-value';
    try {
      loadConfig({ PORT: 'abc', SESSION_SECRET: shortSecret, ORIGIN: 'http://localhost:3000/' });
      expect.unreachable();
    } catch (err) {
      expect(err).toBeInstanceOf(ConfigError);
      const e = err as ConfigError;
      expect(e.problems.length).toBe(3);
      expect(e.message).not.toContain(shortSecret);
    }
  });
});
