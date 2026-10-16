import type { FastifyPluginCallback } from 'fastify';
import { destroySession, getSessionUser } from '../auth/session.js';
import { requireSameOrigin } from '../http/origin.js';
import { audit, type RouteDeps } from './context.js';

// ログアウトと全端末ログアウト。
// C では「パスキーで登録 → ログアウト → パスキーでログイン」の E2E に要る POST /logout だけを置く。
// TODO(B): POST /logout/all（全端末ログアウト）
// TODO(D: B と統合): B の logout.ts と統合する
// ルートを登録するだけで待つ処理が無いので、async ではなく done で終わりを知らせる形にしている
export const logoutRoutes: FastifyPluginCallback<RouteDeps> = (app, deps, done) => {
  // S13: ログアウトも状態を変える要求。他サイトから勝手にログアウトさせられないよう Origin を照合する
  app.addHook('preHandler', requireSameOrigin(deps.config));

  app.post('/logout', (req, reply) => {
    const user = getSessionUser(deps.db, deps.config, req);
    destroySession(deps.db, deps.config, req, reply);
    if (user) audit(deps, req, { userId: user.id, event: 'logout' });
    return { ok: true };
  });
  done();
};
