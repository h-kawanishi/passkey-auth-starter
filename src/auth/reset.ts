// パスワード再設定トークンの発行・検証・使い切り（S10）。
//
// S11: 再設定は「アカウントの回復」であって「ログイン」ではない。メールに届いたリンクで本人確認を済ませて
// そのままログイン状態にする、ということはしない。リンクでできるのは新しいパスワードを決めることだけで、
// その後はふつうにログインしてもらう（routes/reset.ts）。
import { createHash, randomBytes } from 'node:crypto';
import type { Db } from '../db/connection.js';
import {
  consumeResetToken as consumeTokenRow,
  deleteStaleResetTokens,
  insertResetToken,
  invalidateResetTokensOfUser,
} from '../db/repo.js';

/** S10: リンクの有効期間。メールを開いてすぐ使うには十分で、受信箱に残ったリンクが後から悪用されにくい長さ */
export const RESET_TOKEN_TTL_MS = 15 * 60 * 1000;

// 期限切れの行を消すまでの猶予。少し残すのは「期限切れのリンクが使われた」ことを調べられるようにするため
const STALE_AFTER_MS = 24 * 60 * 60 * 1000;

/**
 * S10: DB にはトークンの SHA-256 だけを保存する。トークン表が漏れても、ハッシュからリンクは作れない。
 * トークンは 256bit の乱数なので総当たりで元に戻すことはできず、パスワードのような低速ハッシュやソルトは要らない。
 */
export function hashResetToken(rawToken: string): Buffer {
  return createHash('sha256').update(rawToken).digest();
}

/**
 * 256bit を base64url にすると 43 文字。形の違う値は DB を引く前に捨てる。
 * 形は秘密ではないので、ここで早く断っても攻撃者に手がかりは増えない。
 */
export function isWellFormedResetToken(rawToken: string): boolean {
  return /^[A-Za-z0-9_-]{43}$/.test(rawToken);
}

/**
 * 新しい再設定トークンを発行し、生のトークンを返す（呼び出し側はメールで送るだけで、保存もログ出力もしない）。
 * 同じ人のまだ使われていないトークンは無効にする。リンクを何度も頼まれたときに、有効なリンクが何本も
 * 受信箱に散らばらないようにするため（使えるのは最後に送った 1 本だけ）。
 */
export function issueResetToken(db: Db, userId: number, now: number): string {
  // S10: 256bit の乱数。推測で他人のリンクに当てることは現実的にできない
  const rawToken = randomBytes(32).toString('base64url');
  db.transaction(() => {
    invalidateResetTokensOfUser(db, userId, now);
    deleteStaleResetTokens(db, now - STALE_AFTER_MS);
    insertResetToken(db, { tokenHash: hashResetToken(rawToken), userId, expiresAt: now + RESET_TOKEN_TTL_MS });
  })();
  return rawToken;
}

/**
 * S10: トークンを使い切る。未使用・期限内なら「使用済み」にして持ち主の id を返し、そうでなければ undefined。
 * 一度通ったトークンは二度と通らない（同時に 2 回送られても、通るのは 1 回だけ。repo の条件付き UPDATE）。
 */
export function consumeResetToken(db: Db, rawToken: string, now: number): number | undefined {
  if (!isWellFormedResetToken(rawToken)) return undefined;
  return consumeTokenRow(db, hashResetToken(rawToken), now);
}

/**
 * メールに載せるリンク。トークンは URL の「#」の後ろ（フラグメント）に置く。
 * フラグメントはブラウザがサーバーへ送らないので、トークンがアクセスログやリバースプロキシのログ、
 * Referer ヘッダに残らない（S12）。画面の JavaScript が読み取り、POST の本文で送る。
 */
export function resetLink(origin: string, rawToken: string): string {
  return `${origin}/reset/new#token=${rawToken}`;
}
