// 再認証（人間の判断 2）の結合テストで共通に使う操作。reauth.test.ts と reauth-ceremony.test.ts から使う
import type { LightMyRequestResponse } from 'fastify';
import type { PublicKeyCredentialCreationOptionsJSON } from '@simplewebauthn/server';
import { REAUTH_MAX_AGE_MS } from '../../src/auth/session.js';
import type { Db } from '../../src/db/connection.js';
import type { TestBrowser } from './passkey-client.js';
import { SoftAuthenticator } from './soft-authenticator.js';

/** その人の全セッションの「最後に本人確認した時刻」を、5 分と 1 秒だけ過去にずらす（時間が経った状態を作る） */
export function expireReauthOf(db: Db, email: string): void {
  db.prepare(
    `UPDATE sessions SET reauthenticated_at = reauthenticated_at - ?
     WHERE user_id = (SELECT id FROM users WHERE email = ?)`,
  ).run(REAUTH_MAX_AGE_MS + 1000, email);
}

export function countPasskeysOf(db: Db, email: string): unknown {
  return db
    .prepare('SELECT count(*) FROM credentials WHERE user_id = (SELECT id FROM users WHERE email = ?)')
    .pluck()
    .get(email);
}

/** パスキーの追加を開始し、新しい認証器で応答を作って完了まで送る */
export async function addPasskeyWith(
  b: TestBrowser,
  origin: string,
): Promise<{ start: LightMyRequestResponse; finish?: LightMyRequestResponse }> {
  const start = await b.request('POST', '/passkeys/register/options', {});
  if (start.statusCode !== 200) return { start };
  const response = new SoftAuthenticator(origin).register(start.json<PublicKeyCredentialCreationOptionsJSON>());
  return { start, finish: await b.request('POST', '/passkeys/register/verify', { response, deviceName: '追加' }) };
}
