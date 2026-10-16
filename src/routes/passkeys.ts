import type { FastifyPluginAsync } from 'fastify';

// パスキーの追加・名前変更・削除。
// TODO(C): POST /passkeys/register/options, POST /passkeys/register/verify, PATCH/DELETE /passkeys/:id（S5, S6, S13）
export const passkeysRoutes: FastifyPluginAsync = async () => {};
