import type { FastifyPluginCallback } from 'fastify';
import { audit } from '../auth/audit.js';
import { normalizeEmail } from '../auth/email.js';
import { LOCKED_MESSAGE, verifyWithLockout } from '../auth/lockout.js';
import { hashPassword, needsRehash, verifyAgainstDummy, verifyPassword } from '../auth/password.js';
import { startSession } from '../auth/session.js';
import { findUserByEmail, updatePasswordHash } from '../db/repo.js';

// 列挙防止: 「存在しないメール」と「パスワード違い」で同じ文言・同じ状態コードを返す
const BAD_CREDENTIALS_MESSAGE = 'メールアドレスまたはパスワードが違います';

// ログイン（パスワード）。画面は routes/pages.ts、パスキーでのログインは routes/passkey-login.ts にある。
export const loginRoutes: FastifyPluginCallback = (app, _opts, done) => {
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
      // 未登録・パスキーのみのユーザーでも、本物と同じだけ時間をかけてから失敗にする（列挙防止）
      // パスキーのみのユーザー（password_hash が NULL）にも同じ失敗を返す。「パスキーでログインしてください」と
      // 返し分けると、そのメールが登録済みだと分かってしまうため。案内はログイン画面に常に出しておく
      const result = await verifyWithLockout(
        app.db,
        { email, userId: user?.id ?? null, ip: request.ip, now },
        () =>
          user?.password_hash
            ? verifyPassword(user.password_hash, request.body.password)
            : verifyAgainstDummy(request.body.password),
      );
      if (result.status === 'locked') {
        audit(request, 'login.locked', user?.id ?? null);
        return reply.code(429).send({ message: LOCKED_MESSAGE });
      }
      const { ok, lockedNow } = result;

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
