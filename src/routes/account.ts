import type { FastifyPluginCallback } from 'fastify';
import { audit } from '../auth/audit.js';
import { LOCKED_MESSAGE, lockedUntil, recordLoginAttempt } from '../auth/lockout.js';
import {
  checkNewPassword,
  hashPassword,
  passwordProblemMessage,
  verifyPassword,
} from '../auth/password.js';
import { currentUser, endAllSessions, requireUser } from '../auth/session.js';
import { findUserById, updatePasswordHash } from '../db/repo.js';
import { htmlPage } from '../web/pages.js';

// アカウント設定画面とパスワード変更。
// TODO(C): パスキー一覧・追加・名前変更・削除、パスキーのみのユーザーがパスワードを足す流れ
export const accountRoutes: FastifyPluginCallback = (app, _opts, done) => {
  const page = htmlPage('account.html');
  app.get('/account', (request, reply) => {
    if (!currentUser(request)) return reply.redirect('/login');
    return page(reply);
  });

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
        // TODO(C): パスキーのみのユーザーがパスワードを追加する流れ
        return reply.code(400).send({ message: 'このアカウントにはパスワードが設定されていません' });
      }

      const now = Date.now();
      // S9: 現在のパスワードの照合もログインと同じ失敗回数に数える。ここが総当たりの抜け道にならないように
      if (lockedUntil(app.db, row.email, now) !== null) {
        return reply.code(429).send({ message: LOCKED_MESSAGE });
      }
      const ok = await verifyPassword(row.password_hash, request.body.currentPassword);
      const { lockedNow } = recordLoginAttempt(app.db, {
        email: row.email,
        userId: row.id,
        succeeded: ok,
        ip: request.ip,
        now,
      });
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
      // 古いパスワードで入っていたかもしれない他の端末を締め出す。今の端末は使い続けられるよう残す
      const ended = endAllSessions(request, row.id, { keepCurrent: true });
      audit(request, 'password.change', row.id, { otherSessionsEnded: ended });
      return reply.send({ message: 'パスワードを変更しました。ほかの端末はログアウトされました' });
    },
  );
  done();
};
