import { describe, expect, it } from 'vitest';
import {
  createAuthenticationOptions,
  createRegistrationOptions,
  verifyAuthentication,
  verifyRegistration,
} from '../../src/auth/passkey.js';
import { loadConfig } from '../../src/config.js';
import { SoftAuthenticator } from '../helpers/soft-authenticator.js';

const config = loadConfig({ NODE_ENV: 'test', PORT: '3999', RP_ID: 'localhost' });

/** 登録まで済ませ、DB に保存されるのと同じ形の「保存済みの鍵」を返す */
async function registered(auth = new SoftAuthenticator(config.origin)) {
  const options = await createRegistrationOptions(config, { email: 'a@example.com', existing: [] });
  const result = await verifyRegistration(config, auth.register(options), options.challenge);
  if (!result.ok) throw new Error(result.reason);
  const stored = {
    credentialId: Buffer.from(result.credentialId),
    publicKey: Buffer.from(result.publicKey),
    counter: result.counter,
    transports: result.transports,
  };
  return { auth, stored };
}

describe('passkey: 登録', () => {
  it('S5: Discoverable 必須・user verification は preferred・RP ID は設定の値', async () => {
    const options = await createRegistrationOptions(config, { email: 'a@example.com', existing: [] });
    expect(options.rp.id).toBe('localhost');
    expect(options.authenticatorSelection?.residentKey).toBe('required');
    expect(options.authenticatorSelection?.requireResidentKey).toBe(true);
    expect(options.authenticatorSelection?.userVerification).toBe('preferred');
    expect(options.attestation).toBe('none');
  });

  it('正しい登録応答は受理し、公開鍵と credential ID を返す', async () => {
    const { auth, stored } = await registered();
    expect(stored.credentialId.equals(auth.credentialId)).toBe(true);
    expect(stored.publicKey.length).toBeGreaterThan(0);
  });

  it('別のチャレンジに対する登録応答は拒否する（リプレイ防止）', async () => {
    const auth = new SoftAuthenticator(config.origin);
    const options = await createRegistrationOptions(config, { email: 'a@example.com', existing: [] });
    const other = await createRegistrationOptions(config, { email: 'a@example.com', existing: [] });
    const result = await verifyRegistration(config, auth.register(options), other.challenge);
    expect(result.ok).toBe(false);
  });

  it('別のオリジン（偽サイト）で作られた登録応答は拒否する（S5）', async () => {
    const auth = new SoftAuthenticator('http://localhost.evil.example');
    const options = await createRegistrationOptions(config, { email: 'a@example.com', existing: [] });
    const result = await verifyRegistration(config, auth.register(options), options.challenge);
    expect(result.ok).toBe(false);
  });
});

describe('passkey: 認証', () => {
  it('S5: allowCredentials は空（Discoverable）、user verification は preferred', async () => {
    const options = await createAuthenticationOptions(config);
    expect(options.rpId).toBe('localhost');
    expect(options.allowCredentials ?? []).toEqual([]);
    expect(options.userVerification).toBe('preferred');
  });

  it('正しい認証応答は受理し、新しいカウンタを返す', async () => {
    const { auth, stored } = await registered();
    auth.counter = 1;
    const options = await createAuthenticationOptions(config);
    const result = await verifyAuthentication(config, auth.authenticate(options), options.challenge, stored);
    expect(result).toEqual({ ok: true, newCounter: 1 });
  });

  it('S6: 署名カウンタが保存値より小さい（巻き戻った）応答は拒否する', async () => {
    const { auth, stored } = await registered();
    stored.counter = 10;
    auth.counter = 5;
    const options = await createAuthenticationOptions(config);
    const result = await verifyAuthentication(config, auth.authenticate(options), options.challenge, stored);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toMatch(/counter/i);
  });

  it('S6: 署名カウンタが保存値と同じ（進んでいない）応答も拒否する', async () => {
    const { auth, stored } = await registered();
    stored.counter = 10;
    auth.counter = 10;
    const options = await createAuthenticationOptions(config);
    const result = await verifyAuthentication(config, auth.authenticate(options), options.challenge, stored);
    expect(result.ok).toBe(false);
  });

  it('S6: カウンタが進んでいれば受理する', async () => {
    const { auth, stored } = await registered();
    stored.counter = 10;
    auth.counter = 11;
    const options = await createAuthenticationOptions(config);
    const result = await verifyAuthentication(config, auth.authenticate(options), options.challenge, stored);
    expect(result).toEqual({ ok: true, newCounter: 11 });
  });

  it('他人の credential ID を名乗っても、その人の公開鍵で検証されるので通らない', async () => {
    const alice = await registered();
    const bob = await registered();
    alice.auth.counter = 1;
    const options = await createAuthenticationOptions(config);
    // Alice の鍵で署名し、ID だけ Bob のものにする。サーバーは Bob の公開鍵で検証する
    const forged = alice.auth.authenticate(options, { claimCredentialId: bob.stored.credentialId });
    const result = await verifyAuthentication(config, forged, options.challenge, bob.stored);
    expect(result.ok).toBe(false);
  });

  it('偽サイトのオリジンで作られた認証応答は拒否する（S5: フィッシング耐性）', async () => {
    const { auth, stored } = await registered();
    auth.counter = 1;
    const options = await createAuthenticationOptions(config);
    const response = auth.authenticate(options, { origin: 'https://phishing.example' });
    const result = await verifyAuthentication(config, response, options.challenge, stored);
    expect(result.ok).toBe(false);
  });
});
