import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { FastifyReply } from 'fastify';

/**
 * src/web/ の HTML を読み、送り返す関数を作る。
 * 起動時に一度だけ読むのは、リクエストのたびにファイルを読むと遅く、途中でファイルが変わると
 * 画面と API の版がずれるため。
 */
export function htmlPage(name: string): (reply: FastifyReply) => FastifyReply {
  const html = readFileSync(join(import.meta.dirname, name), 'utf8');
  return (reply) => reply.type('text/html; charset=utf-8').send(html);
}
