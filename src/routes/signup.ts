import type { FastifyPluginAsync } from 'fastify';

// 新規登録（メール + パスワード、またはパスキー）。
// TODO(B/C): GET /signup, POST /signup（S2, S3, S13）。パスキーでの登録は C
export const signupRoutes: FastifyPluginAsync = async () => {};
