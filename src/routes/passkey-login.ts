// パスキーでのログイン（条件付き UI＝自動入力、または「パスキーでログイン」ボタン）。
//
// TODO(D: B と統合): S8 のレート制限（IP とアカウントの両方）と S9 の連続失敗ロックを、パスワードの
//   ログインと同じ仕組みでここにも掛ける。C では B の lockout.ts / レート制限がまだ無いため入れていない。
import type { AuthenticationResponseJSON } from '@simplewebauthn/server';
import type { FastifyPluginCallback } from 'fastify';
import {
  createAuthenticationOptions,
  credentialIdFromResponse,
  verifyAuthentication,
} from '../auth/passkey.js';
import { createSession } from '../auth/session.js';
import { findCredentialByCredentialId, updateCredentialAfterLogin } from '../db/repo.js';
import { requireSameOrigin } from '../http/origin.js';
import { audit, type RouteDeps } from './context.js';
import { clearCeremonyCookie, readCeremonyTicket, setCeremonyCookie } from './passkey-ceremony.js';

// 利用者にはどの段階で失敗したかを区別せずに返す。「その鍵は登録されていない」と「署名が違う」を
// 分けて返すと、攻撃者に手がかりを与えるため（パスワードの列挙防止と同じ考え方）
const LOGIN_FAILED = { error: 'パスキーでログインできませんでした。' } as const;

/**
 * 監査ログには失敗の「種類」だけを残す。ライブラリのエラー文にはチャレンジの値などが含まれるため、
 * 文そのものは書かない（S12）。S6 の巻き戻りは不正の兆候なので、種類として区別して残す。
 */
function failureKind(reason: string): string {
  if (/counter/i.test(reason)) return 'counter_rollback'; // S6
  if (/signature/i.test(reason)) return 'bad_signature';
  if (/challenge/i.test(reason)) return 'bad_challenge';
  if (/origin|rp ?id/i.test(reason)) return 'wrong_site';
  return 'verification_failed';
}

// ルートを登録するだけで待つ処理が無いので、async ではなく done で終わりを知らせる形にしている
export const passkeyLoginRoutes: FastifyPluginCallback<RouteDeps> = (app, deps, done) => {
  const { config, db, challenges } = deps;
  app.addHook('preHandler', requireSameOrigin(config)); // S13

  app.post('/passkeys/login/options', async (_req, reply) => {
    const options = await createAuthenticationOptions(config);
    const ticket = challenges.put({ kind: 'login', challenge: options.challenge });
    setCeremonyCookie(config, reply, ticket);
    return options;
  });

  app.post<{ Body: { response: AuthenticationResponseJSON } }>(
    '/passkeys/login/verify',
    {
      schema: {
        body: { type: 'object', required: ['response'], properties: { response: { type: 'object' } } },
      },
    },
    async (req, reply) => {
      const pending = challenges.take(readCeremonyTicket(req), 'login');
      clearCeremonyCookie(config, reply);
      if (!pending) return reply.code(400).send({ error: '時間が経ちすぎました。もう一度お試しください。' });

      // 応答の credential ID で公開鍵を引く。どのユーザーかは鍵が決める（Discoverable Credential, S5）。
      // 他人の credential ID を名乗っても、その人の公開鍵で署名を検証するので通らない
      const credentialId = credentialIdFromResponse(req.body.response.id);
      const stored = credentialId && findCredentialByCredentialId(db, credentialId);
      if (!stored) {
        audit(deps, req, { userId: null, event: 'passkey.login.failure', detail: { kind: 'unknown_credential' } });
        return reply.code(401).send(LOGIN_FAILED);
      }

      const result = await verifyAuthentication(config, req.body.response, pending.challenge, stored);
      if (!result.ok) {
        audit(deps, req, {
          userId: stored.userId,
          event: 'passkey.login.failure',
          detail: { credential: stored.id, kind: failureKind(result.reason) },
        });
        return reply.code(401).send(LOGIN_FAILED);
      }

      const now = Date.now();
      updateCredentialAfterLogin(db, stored.id, result.newCounter, now); // S6: 次回の巻き戻り判定の基準
      createSession(db, config, req, reply, stored.userId);
      audit(deps, req, {
        userId: stored.userId,
        event: 'passkey.login.success',
        detail: { credential: stored.id },
      });
      return { ok: true };
    },
  );
  done();
};
