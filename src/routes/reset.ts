import type { FastifyPluginAsync } from 'fastify';

// パスワード忘れ（再設定メール → 新パスワード）。
// TODO(D): GET/POST /reset, GET/POST /reset/:token（S8, S10, S11, S13）
export const resetRoutes: FastifyPluginAsync = async () => {};
