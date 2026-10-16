// パスキーでのログイン（条件付き UI＝自動入力、または「パスキーでログイン」ボタン）。
//
// S8: IP ごとのレート制限は app.passkeyRateLimit（@fastify/rate-limit）で掛けている。
// S9: パスキーのログインは、アカウント単位のロックの対象外にしている（人間の判断 3、threat-model.md §1）。
//   ロックは「推測で当てる」総当たりの速度を落とすためのもの。パスキーの署名は秘密鍵が無ければ作れず、
//   何回試しても当たる見込みが増えないので、ロックしても守りは強くならない。残る効果は、
//   メールや credential ID を知る第三者が失敗を送り続けて本人を締め出す妨害だけになる。
//   そのため失敗を login_attempts に数えず、パスワードの失敗でロック中のアカウントにもパスキーでは入れる。
//   IP ごとのレート制限（S8）は、要求の洪水を抑えるために残している。
// S13: Origin の検証は server.ts の onRequest フック（auth/origin.ts）が全ルートに掛けている。
import type { AuthenticationResponseJSON } from '@simplewebauthn/server';
import type { FastifyPluginCallback } from 'fastify';
import { audit } from '../auth/audit.js';
import { createAuthenticationOptions, credentialIdFromResponse, verifyAuthentication } from '../auth/passkey.js';
import { startSession } from '../auth/session.js';
import { findCredentialByCredentialId, findUserById, updateCredentialAfterLogin } from '../db/repo.js';
import { clearCeremonyCookie, issueCeremony, readCeremonyTicket } from './passkey-ceremony.js';

// 利用者にはどの段階で失敗したかを区別せずに返す。「その鍵は登録されていない」と「署名が違う」を
// 分けて返すと、攻撃者に手がかりを与えるため（パスワードの列挙防止と同じ考え方）
const LOGIN_FAILED = { message: 'パスキーでログインできませんでした。' } as const;

/**
 * 監査ログには失敗の「種類」だけを残す。ライブラリのエラー文にはチャレンジの値などが含まれるため、
 * 文そのものは書かない（S12）。S6 の巻き戻りは不正の兆候なので、種類として区別して残す。
 * 'counter rollback' は署名が正しいと確かめた上でしか返らない（passkey.ts の verifyAuthentication）。
 * 秘密鍵を持たない第三者が他人の credential ID で送ってきた応答は 'bad signature' になる。
 */
export function failureKind(reason: string): string {
  if (reason === 'counter rollback') return 'counter_rollback'; // S6
  if (reason === 'bad signature') return 'bad_signature';
  if (/challenge/i.test(reason)) return 'bad_challenge';
  if (/origin|rp ?id/i.test(reason)) return 'wrong_site';
  return 'verification_failed';
}

// ルートを登録するだけで待つ処理が無いので、async ではなく done で終わりを知らせる形にしている
export const passkeyLoginRoutes: FastifyPluginCallback = (app, _opts, done) => {
  const { config, db, challenges } = app;
  // S8: このプラグインのルートはすべてログイン前に呼べるので、IP ごとの制限を掛ける
  const rateLimit = { rateLimit: app.passkeyRateLimit };

  app.post('/passkeys/login/options', { config: rateLimit }, async (req, reply) => {
    const options = await createAuthenticationOptions(config);
    if (!issueCeremony(req, reply, { kind: 'login', challenge: options.challenge })) return reply;
    return options;
  });

  app.post<{ Body: { response: AuthenticationResponseJSON } }>(
    '/passkeys/login/verify',
    {
      config: rateLimit,
      schema: {
        body: { type: 'object', required: ['response'], properties: { response: { type: 'object' } } },
      },
    },
    async (req, reply) => {
      const pending = challenges.take(readCeremonyTicket(req), 'login');
      clearCeremonyCookie(req, reply);
      if (!pending) return reply.code(400).send({ message: '時間が経ちすぎました。もう一度お試しください。' });

      // 応答の credential ID で公開鍵を引く。どのユーザーかは鍵が決める（Discoverable Credential, S5）。
      // 他人の credential ID を名乗っても、その人の公開鍵で署名を検証するので通らない
      const credentialId = credentialIdFromResponse(req.body.response.id);
      const stored = credentialId && findCredentialByCredentialId(db, credentialId);
      const owner = stored ? findUserById(db, stored.userId) : undefined;
      if (!stored || !owner) {
        audit(req, 'passkey.login.failure', null, { kind: 'unknown_credential' });
        return reply.code(401).send(LOGIN_FAILED);
      }

      // S9: アカウント単位のロックは確かめず、失敗も数えない（冒頭のコメント）。
      // 失敗は監査ログには残すので、同じ鍵を名乗る失敗が続けば運用者は気づける
      const result = await verifyAuthentication(config, req.body.response, pending.challenge, stored);
      if (!result.ok) {
        audit(req, 'passkey.login.failure', owner.id, {
          credential: stored.id,
          kind: failureKind(result.reason),
        });
        return reply.code(401).send(LOGIN_FAILED);
      }

      updateCredentialAfterLogin(db, stored.id, result.newCounter, Date.now()); // S6: 次回の巻き戻り判定の基準
      startSession(req, reply, owner.id);
      audit(req, 'passkey.login.success', owner.id, { credential: stored.id });
      return { ok: true };
    },
  );
  done();
};
