import type { FastifyPluginCallback } from 'fastify';
import { audit } from '../auth/audit.js';
import { currentUser, endAllSessions, endSession, requireUser, clearSessionCookie } from '../auth/session.js';

// ログアウトと全端末ログアウト。
// どちらも POST にしている。GET だと、他サイトに置かれた画像タグなどから勝手にログアウトさせられるため（S13）
export const logoutRoutes: FastifyPluginCallback = (app, _opts, done) => {
  app.post('/logout', (request, reply) => {
    const user = currentUser(request);
    endSession(request, reply);
    if (user) audit(request, 'logout', user.id);
    return reply.send({ redirect: '/' });
  });

  // 端末をなくした・共用端末でログアウトし忘れた、というときに、ほかの端末のセッションもまとめて失効させる
  app.post('/logout/all', (request, reply) => {
    const user = requireUser(request, reply);
    if (!user) return reply;
    const count = endAllSessions(request, user.id, { keepCurrent: false });
    clearSessionCookie(request, reply);
    audit(request, 'logout.all', user.id, { sessions: count });
    return reply.send({ redirect: '/login' });
  });
  done();
};
