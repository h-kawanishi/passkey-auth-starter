// 再認証（ログイン中の本人確認）。パスキーの追加の前に、直近 5 分以内の本人確認を求める（人間の判断 2）。
//
// なぜ要るか: セッション Cookie を盗んだ攻撃者が自分の認証器をパスキーとして登録すると、利用者がパスワードを
// 変えても再設定しても、そのパスキーで入り直せてしまう（threat-model.md §4）。Cookie だけでは足りず、
// 「今この画面の前にいるのが本人だ」と確かめてから登録させる。
//
// 確認の手段は 2 つ。パスワード（持っている人だけ）と、登録済みのパスキー。メールのコードは使わない（S11）。
// 結果は今のセッションの行（sessions.reauthenticated_at）にだけ記録する。ほかの端末のセッションには付かない。
import type { AuthenticationResponseJSON } from '@simplewebauthn/server';
import type { FastifyPluginCallback } from 'fastify';
import { audit } from '../auth/audit.js';
import { LOCKED_MESSAGE, verifyWithLockout } from '../auth/lockout.js';
import {
  createReauthenticationOptions,
  credentialIdFromResponse,
  verifyAuthentication,
} from '../auth/passkey.js';
import { verifyPassword } from '../auth/password.js';
import { markReauthenticated, requireUser } from '../auth/session.js';
import {
  findCredentialByCredentialId,
  findUserById,
  listCredentialsByUser,
  updateCredentialAfterLogin,
} from '../db/repo.js';
import { clearCeremonyCookie, issueCeremony, readCeremonyTicket } from './passkey-ceremony.js';
import { failureKind } from './passkey-login.js';

const REAUTH_OK = { message: '本人確認ができました。5 分以内に操作を済ませてください。' } as const;
const PASSKEY_FAILED = { message: 'パスキーで本人確認できませんでした。' } as const;

// ルートを登録するだけで待つ処理が無いので、async ではなく done で終わりを知らせる形にしている
export const reauthRoutes: FastifyPluginCallback = (app, _opts, done) => {
  const { config, db, challenges } = app;

  // パスワードで本人確認する
  app.post<{ Body: { password: string } }>(
    '/account/reauth',
    {
      // S8: 盗んだセッションからパスワードを総当たりされないよう、ログインと同じ IP ごとの制限を掛ける
      config: { rateLimit: app.authRateLimit },
      schema: {
        body: {
          type: 'object',
          required: ['password'],
          properties: { password: { type: 'string', maxLength: 4096 } },
        },
      },
    },
    async (req, reply) => {
      const user = requireUser(req, reply);
      if (!user) return reply;
      const row = findUserById(db, user.id);
      if (!row?.password_hash) {
        return reply.code(400).send({ message: 'このアカウントにはパスワードがありません。パスキーで確認してください。' });
      }
      // S9: パスワードの照合なので、ログイン・パスワード変更と同じ失敗回数に数える。
      // ここだけ数えないと、盗んだセッションからパスワードを試し放題になる
      const passwordHash = row.password_hash;
      const result = await verifyWithLockout(
        db,
        { email: row.email, userId: row.id, ip: req.ip, now: Date.now() },
        () => verifyPassword(passwordHash, req.body.password),
      );
      if (result.status === 'locked') {
        audit(req, 'reauth.failure', row.id, { method: 'password', reason: 'locked' });
        return reply.code(429).send({ message: LOCKED_MESSAGE });
      }
      if (!result.ok) {
        audit(req, 'reauth.failure', row.id, { method: 'password', reason: 'wrong_password' });
        if (result.lockedNow) audit(req, 'account.locked', row.id);
        return reply.code(400).send({ message: 'パスワードが違います' });
      }
      if (!markReauthenticated(req, row.id)) return reply.code(401).send({ message: 'ログインしてください' });
      audit(req, 'reauth', row.id, { method: 'password' });
      return REAUTH_OK;
    },
  );

  // 登録済みのパスキーで本人確認する（開始）。引換券の Cookie が /passkeys/ 以下にしか送られないので、この場所に置く
  app.post('/passkeys/reauth/options', { config: { rateLimit: app.passkeyRateLimit } }, async (req, reply) => {
    const user = requireUser(req, reply);
    if (!user) return reply;
    const existing = listCredentialsByUser(db, user.id);
    if (existing.length === 0) {
      return reply.code(400).send({ message: 'このアカウントにはパスキーがありません。パスワードで確認してください。' });
    }
    const options = await createReauthenticationOptions(config, existing);
    if (!issueCeremony(req, reply, { kind: 'reauth', challenge: options.challenge, userId: user.id })) return reply;
    return options;
  });

  // 登録済みのパスキーで本人確認する（完了）
  app.post<{ Body: { response: AuthenticationResponseJSON } }>(
    '/passkeys/reauth/verify',
    {
      config: { rateLimit: app.passkeyRateLimit }, // S8
      schema: {
        body: { type: 'object', required: ['response'], properties: { response: { type: 'object' } } },
      },
    },
    async (req, reply) => {
      const pending = challenges.take(readCeremonyTicket(req), 'reauth');
      clearCeremonyCookie(req, reply);
      if (!pending) return reply.code(400).send({ message: '時間が経ちすぎました。もう一度お試しください。' });
      // 開始したときと同じ人がまだログインしているか。途中で別の人に入れ替わっていたら確認済みにしない
      const user = requireUser(req, reply);
      if (!user) return reply;
      if (user.id !== pending.userId) return reply.code(401).send({ message: 'ログインしてください' });

      // 鍵はこの人のものに限る。他人のパスキーで確認しても、このセッションの本人確認にはならない
      const credentialId = credentialIdFromResponse(req.body.response.id);
      const stored = credentialId && findCredentialByCredentialId(db, credentialId);
      if (!stored || stored.userId !== user.id) {
        audit(req, 'reauth.failure', user.id, { method: 'passkey', kind: 'not_own_credential' });
        return reply.code(401).send(PASSKEY_FAILED);
      }
      // S9: パスキーはロックの対象外（passkey-login.ts の冒頭と同じ理由）
      const result = await verifyAuthentication(config, req.body.response, pending.challenge, stored);
      if (!result.ok) {
        audit(req, 'reauth.failure', user.id, { method: 'passkey', credential: stored.id, kind: failureKind(result.reason) });
        return reply.code(401).send(PASSKEY_FAILED);
      }
      updateCredentialAfterLogin(db, stored.id, result.newCounter, Date.now()); // S6: 次回の巻き戻り判定の基準
      if (!markReauthenticated(req, user.id)) return reply.code(401).send({ message: 'ログインしてください' });
      audit(req, 'reauth', user.id, { method: 'passkey', credential: stored.id });
      return REAUTH_OK;
    },
  );
  done();
};
