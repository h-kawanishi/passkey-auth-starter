// reset_tokens 表（パスワード再設定）への読み書き。SQL を集める理由は src/db/repo.ts の冒頭を参照。
import type { Db } from '../connection.js';

/**
 * S10: 再設定トークンを保存する。受け取るのはトークンのハッシュだけで、生のトークンはこの層まで降りてこない。
 * トークン表がまるごと漏れても、ハッシュからリンクを作り直すことはできない。
 */
export function insertResetToken(
  db: Db,
  t: { tokenHash: Buffer; userId: number; expiresAt: number },
): void {
  db.prepare('INSERT INTO reset_tokens (token_hash, user_id, expires_at) VALUES (?, ?, ?)').run(
    t.tokenHash,
    t.userId,
    t.expiresAt,
  );
}

/**
 * S10: 未使用・期限内のトークンを「使用済み」にし、その持ち主を返す。該当が無ければ undefined。
 * 「探す → 使用済みにする」を 2 つの SQL に分けると、同じリンクを同時に 2 回送られたときに両方が通りうる。
 * 条件付きの UPDATE 1 文にすれば、SQLite が 1 件ずつ処理するので、通るのは必ず 1 回だけになる。
 */
export function consumeResetToken(db: Db, tokenHash: Buffer, now: number): number | undefined {
  return db
    .prepare(
      `UPDATE reset_tokens SET used_at = ?
       WHERE token_hash = ? AND used_at IS NULL AND expires_at > ?
       RETURNING user_id`,
    )
    .pluck()
    .get(now, tokenHash, now) as number | undefined;
}

/**
 * その利用者の未使用のトークンをすべて無効にする（使用済みとして残す）。
 * 新しいリンクを出したとき・パスワードが変わったときに、古いリンクが使える状態を残さないため。
 */
export function invalidateResetTokensOfUser(db: Db, userId: number, now: number): void {
  db.prepare('UPDATE reset_tokens SET used_at = ? WHERE user_id = ? AND used_at IS NULL').run(now, userId);
}

/** 期限切れや使用済みの行がたまり続けないよう、発行のついでに古いものを消す */
export function deleteStaleResetTokens(db: Db, before: number): void {
  db.prepare('DELETE FROM reset_tokens WHERE expires_at <= ?').run(before);
}
