// ルートに渡す共通の部品（設定・DB・チャレンジ置き場）。
// グローバル変数にせずプラグインの引数で渡すのは、テストで部品を差し替えやすくするため。
import type { FastifyReply, FastifyRequest } from 'fastify';
import type { ChallengeStore } from '../auth/challenges.js';
import { getSessionUser } from '../auth/session.js';
import type { Config } from '../config.js';
import type { Db } from '../db/connection.js';
import { insertAuditLog, type AuditEntry, type UserRow } from '../db/repo.js';

export interface RouteDeps {
  config: Config;
  db: Db;
  challenges: ChallengeStore;
}

/** S12: 監査ログに書く。時刻と IP はここで埋め、呼び出し側の書き忘れを無くす */
export function audit(
  deps: RouteDeps,
  req: FastifyRequest,
  entry: Omit<AuditEntry, 'at' | 'ip'>,
): void {
  insertAuditLog(deps.db, { ...entry, at: Date.now(), ip: req.ip });
}

/**
 * ログインが必要なルートの入口。未ログインなら 401 を送って null を返す。
 * 呼び出し側は null のとき何もせず return reply する。
 */
export function requireUser(
  deps: RouteDeps,
  req: FastifyRequest,
  reply: FastifyReply,
): UserRow | null {
  const user = getSessionUser(deps.db, deps.config, req);
  if (!user) {
    void reply.code(401).send({ error: 'ログインしてください。' });
    return null;
  }
  return user;
}
