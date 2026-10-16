import type { FastifyPluginCallback } from 'fastify';
import { audit } from '../auth/audit.js';
import { LOCKED_MESSAGE, verifyWithLockout } from '../auth/lockout.js';
import {
  checkNewPassword,
  hashPassword,
  passwordProblemMessage,
  verifyPassword,
} from '../auth/password.js';
import { endAllSessions, requireUser, startSession } from '../auth/session.js';
import { findUserById, invalidateResetTokensOfUser, updatePasswordHash } from '../db/repo.js';

// アカウント設定のうち、自分の情報とパスワード変更。画面は routes/pages.ts、パスキーの管理は routes/passkeys.ts にある。
export const accountRoutes: FastifyPluginCallback = (app, _opts, done) => {
  // 画面に表示する自分の情報。秘密に当たる値（ハッシュなど）は返さない
  app.get('/account/me', (request, reply) => {
    const user = requireUser(request, reply);
    if (!user) return reply;
    return reply.send({ email: user.email, hasPassword: user.hasPassword });
  });

  app.post<{ Body: { currentPassword: string; newPassword: string } }>(
    '/account/password',
    {
      // S8: 盗んだセッションで現在のパスワードを総当たりされないよう、ここにも制限をかける
      config: { rateLimit: app.authRateLimit },
      schema: {
        body: {
          type: 'object',
          required: ['currentPassword', 'newPassword'],
          properties: {
            currentPassword: { type: 'string', maxLength: 4096 },
            newPassword: { type: 'string', maxLength: 4096 },
          },
        },
      },
    },
    async (request, reply) => {
      const user = requireUser(request, reply);
      if (!user) return reply;
      const row = findUserById(app.db, user.id);
      if (!row?.password_hash) {
        // パスキーのみのユーザーは、ログイン画面の「パスワードを忘れた場合」（再設定メール）でパスワードを足せる。
        // ログイン中の画面からその場で足せるようにするかは未決（人間の判断待ち）
        return reply.code(400).send({ message: 'このアカウントにはパスワードが設定されていません' });
      }

      // S9: 現在のパスワードの照合もログインと同じ失敗回数に数える。ここが総当たりの抜け道にならないように。
      // 同時に送られた要求でも上限を超えて照合しないよう、ログインと同じ関数で判定・記録する
      const passwordHash = row.password_hash;
      const result = await verifyWithLockout(
        app.db,
        { email: row.email, userId: row.id, ip: request.ip, now: Date.now() },
        () => verifyPassword(passwordHash, request.body.currentPassword),
      );
      if (result.status === 'locked') {
        audit(request, 'password.change.failure', row.id, { reason: 'locked' });
        return reply.code(429).send({ message: LOCKED_MESSAGE });
      }
      const { ok, lockedNow } = result;
      if (!ok) {
        audit(request, 'password.change.failure', row.id, { reason: 'wrong_current_password' });
        if (lockedNow) audit(request, 'account.locked', row.id);
        return reply.code(400).send({ message: '現在のパスワードが違います' });
      }

      // S2 / S3: 新しいパスワードにも登録時と同じ規則を当てる
      const problem = checkNewPassword(request.body.newPassword);
      if (problem) {
        return reply.code(400).send({ message: passwordProblemMessage(problem), reason: problem });
      }
      updatePasswordHash(app.db, row.id, await hashPassword(request.body.newPassword));
      // S10: 変更前に発行された再設定リンクは使えなくする。古いリンクで新しいパスワードを上書きされないように
      invalidateResetTokensOfUser(app.db, row.id, Date.now());
      // 古いパスワードで入っていたかもしれない端末を締め出す。今の端末も、同じ ID を使い続けると
      // その Cookie が盗まれていた場合に変更後も使われ続けるので、いったん消して新しい ID を発行し直す
      // （権限や資格情報が変わったときにセッション ID を作り直す。OWASP Session Management の推奨）
      const ended = endAllSessions(request, row.id, { keepCurrent: false });
      startSession(request, reply, row.id);
      audit(request, 'password.change', row.id, { otherSessionsEnded: Math.max(ended - 1, 0) });
      return reply.send({ message: 'パスワードを変更しました。ほかの端末はログアウトされました' });
    },
  );
  done();
};
