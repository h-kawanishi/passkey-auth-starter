import type { FastifyPluginCallback } from 'fastify';
import { audit } from '../auth/audit.js';
import { isPlausibleEmail, normalizeEmail } from '../auth/email.js';
import { checkNewPassword, hashPassword, passwordProblemMessage } from '../auth/password.js';
import { startSession } from '../auth/session.js';
import { createUser } from '../db/repo.js';

// 新規登録（メール + パスワード）。画面は routes/pages.ts、パスキーでの登録は routes/passkeys.ts にある。
export const signupRoutes: FastifyPluginCallback = (app, _opts, done) => {
  app.post<{ Body: { email: string; password: string } }>(
    '/signup',
    {
      // S8: 登録の連打（アカウントの大量作成や、登録済みメールの探索）を IP ごとに抑える
      config: { rateLimit: app.authRateLimit },
      schema: {
        body: {
          type: 'object',
          required: ['email', 'password'],
          properties: {
            email: { type: 'string', maxLength: 1024 },
            // 長さの規則（S2）はここではなく checkNewPassword で調べ、理由を日本語で返す
            password: { type: 'string', maxLength: 4096 },
          },
        },
      },
    },
    async (request, reply) => {
      const email = normalizeEmail(request.body.email);
      if (!isPlausibleEmail(email)) {
        return reply.code(400).send({ message: 'メールアドレスの形が正しくありません' });
      }
      // S2 / S3: 長さと漏えい一覧だけを調べる。文字種は問わない
      const problem = checkNewPassword(request.body.password);
      if (problem) {
        return reply.code(400).send({ message: passwordProblemMessage(problem), reason: problem });
      }

      // S1: 保存するのはハッシュだけ。生のパスワードはこの関数を出たら残らない
      const passwordHash = await hashPassword(request.body.password);
      const userId = createUser(app.db, { email, passwordHash, now: Date.now() });
      if (userId === null) {
        // 登録済みであることは、この画面では伝えざるを得ない（伝えないと本人が先へ進めない）。
        // 列挙の速度はレート制限（S8）で抑える。確認メールを挟む方式は D 以降で検討する。
        return reply.code(409).send({
          message:
            'このメールアドレスでは登録できません。登録済みの場合はログインするか、パスワードの再設定をお試しください',
        });
      }
      audit(request, 'signup', userId, { method: 'password' });
      startSession(request, reply, userId);
      return reply.code(201).send({ redirect: '/account' });
    },
  );
  done();
};
