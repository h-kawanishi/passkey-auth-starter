// パスキーでのログイン（条件付き UI＝自動入力、または「パスキーでログイン」ボタン）。
//
// S8: IP ごとのレート制限は app.passkeyRateLimit（@fastify/rate-limit）で掛けている。
// S8 / S9: アカウント単位の制限と連続失敗のロックは、パスワードのログインと同じ verifyWithLockout を使う。
//   ロックはアカウント（メールアドレス）単位で、パスワードとパスキーの失敗を合わせて数える。
//   経路ごとに別々に数えると、片方のロック中にもう片方で試し続けられてしまうため。
// S13: Origin の検証は server.ts の onRequest フック（auth/origin.ts）が全ルートに掛けている。
import type { AuthenticationResponseJSON } from '@simplewebauthn/server';
import type { FastifyPluginCallback } from 'fastify';
import { audit } from '../auth/audit.js';
import { LOCKED_MESSAGE, verifyWithLockout } from '../auth/lockout.js';
import {
  createAuthenticationOptions,
  credentialIdFromResponse,
  verifyAuthentication,
  type Result,
} from '../auth/passkey.js';
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
function failureKind(reason: string): string {
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

      // S9: ロック中なら署名を検証しない。判定と記録を 1 つのトランザクションで先に済ませるので、
      // 同時に送られた要求でも上限を超えて検証しない（lockout.ts の verifyWithLockout を参照）
      // 検証の結果（新しいカウンタや失敗の種類）は下で使うので、照合の関数の外に持ち出す。
      // as で型を広げておかないと、TypeScript が「初期値の ok: false のまま」と決めつけてしまう
      let result = { ok: false, reason: 'not verified' } as Result<{ newCounter: number }>;
      const guarded = await verifyWithLockout(
        db,
        { email: owner.email, userId: owner.id, ip: req.ip, now: Date.now() },
        async () => {
          result = await verifyAuthentication(config, req.body.response, pending.challenge, stored);
          return result.ok;
        },
      );
      if (guarded.status === 'locked') {
        audit(req, 'passkey.login.locked', owner.id, { credential: stored.id });
        return reply.code(429).send({ message: LOCKED_MESSAGE });
      }
      if (!result.ok) {
        audit(req, 'passkey.login.failure', owner.id, {
          credential: stored.id,
          kind: failureKind(result.reason),
        });
        if (guarded.lockedNow) audit(req, 'account.locked', owner.id);
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
