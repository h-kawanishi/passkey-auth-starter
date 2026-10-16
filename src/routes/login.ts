import type { FastifyPluginCallback } from 'fastify';
import { audit } from '../auth/audit.js';
import { normalizeEmail } from '../auth/email.js';
import { LOCKED_MESSAGE, lockedUntil, recordLoginAttempt } from '../auth/lockout.js';
import { hashPassword, needsRehash, verifyAgainstDummy, verifyPassword } from '../auth/password.js';
import { startSession } from '../auth/session.js';
import { findUserByEmail, updatePasswordHash } from '../db/repo.js';
import { htmlPage } from '../web/pages.js';

// 列挙防止: 「存在しないメール」と「パスワード違い」で同じ文言・同じ状態コードを返す
const BAD_CREDENTIALS_MESSAGE = 'メールアドレスまたはパスワードが違います';

// ログイン（パスワード）。
// TODO(C): パスキーでのログイン（条件付き UI、S5, S6）
export const loginRoutes: FastifyPluginCallback = (app, _opts, done) => {
  const page = htmlPage('login.html');
  app.get('/login', (_req, reply) => page(reply));

  app.post<{ Body: { email: string; password: string } }>(
    '/login',
    {
      // S8: IP ごとのレート制限。アカウント側の制限は下の lockout（S9）が受け持つ
      config: { rateLimit: app.authRateLimit },
      schema: {
        body: {
          type: 'object',
          required: ['email', 'password'],
          properties: {
            email: { type: 'string', maxLength: 1024 },
            password: { type: 'string', maxLength: 4096 },
          },
        },
      },
    },
    async (request, reply) => {
      const now = Date.now();
      const email = normalizeEmail(request.body.email);
      const user = findUserByEmail(app.db, email);

      // S9: ロック中は、正しいパスワードでも照合しない。
      // ロックはメールアドレス単位で、未登録のメールにも同じ規則が働く（ロックの有無から登録を推測させない）
      if (lockedUntil(app.db, email, now) !== null) {
        audit(request, 'login.locked', user?.id ?? null);
        return reply.code(429).send({ message: LOCKED_MESSAGE });
      }

      // 未登録・パスキーのみのユーザーでも、本物と同じだけ時間をかけてから失敗にする（列挙防止）
      // TODO(C): password_hash が NULL（パスキーのみ）のユーザーには、パスキーでのログインを案内する
      const ok = user?.password_hash
        ? await verifyPassword(user.password_hash, request.body.password)
        : await verifyAgainstDummy(request.body.password);

      const { lockedNow } = recordLoginAttempt(app.db, {
        email,
        userId: user?.id ?? null,
        succeeded: ok,
        ip: request.ip,
        now,
      });

      if (!user || !ok) {
        // 監査ログには理由を分けて残す（運用者が攻撃の種類を見分けるため）。利用者への応答は分けない
        audit(request, 'login.failure', user?.id ?? null, {
          reason: user ? 'wrong_password' : 'unknown_email',
        });
        if (lockedNow) audit(request, 'account.locked', user?.id ?? null);
        return reply.code(401).send({ message: BAD_CREDENTIALS_MESSAGE });
      }

      // ハッシュのパラメータを強くしたあとは、正しいパスワードが手元にあるこの瞬間に作り直す
      if (user.password_hash && needsRehash(user.password_hash)) {
        updatePasswordHash(app.db, user.id, await hashPassword(request.body.password));
      }
      audit(request, 'login.success', user.id, { method: 'password' });
      startSession(request, reply, user.id);
      return reply.send({ redirect: '/account' });
    },
  );
  done();
};
