// 連続失敗の記録とロック判定（S8 のアカウント側の制限、S9）。
import type { Db } from '../db/connection.js';
import { insertLoginAttempt, listLoginAttempts, setLockedUntil } from '../db/repo.js';

/** S9: この回数だけ続けて失敗したらロックする */
export const LOCKOUT_THRESHOLD = 5;
/** S9: ロックしている時間。利用者が待てる長さで、総当たりの速度は 1 時間に 20 回程度まで落ちる */
export const LOCKOUT_MS = 15 * 60 * 1000;
// 判定のために遡る範囲。ロックは 15 分で切れるので、これより古い記録は結果に影響しない
const HISTORY_MS = 24 * 60 * 60 * 1000;

/**
 * 記録された試行を古い順にたどり、「今ロック中なら、その終了時刻」を返す。
 *
 * ロック中に来た試行は記録しない（recordLoginAttempt を呼ばない）ので、記録は
 * 「ロック外で、実際にパスワードを照合した試行」だけになる。それを順に数え直せば、
 * 成功で 0 に戻り、5 回目の失敗でロックが始まり、ロックが明けると 0 から数え直す、という規則を
 * 存在しないメールにも同じように当てはめられる（ロックの有無で登録済みかどうかが分からないように）。
 */
export function lockedUntil(db: Db, email: string, now: number): number | null {
  let failures = 0;
  let until: number | null = null;
  for (const attempt of listLoginAttempts(db, email, now - HISTORY_MS)) {
    if (attempt.succeeded) {
      failures = 0;
      continue;
    }
    failures += 1;
    if (failures >= LOCKOUT_THRESHOLD) {
      until = attempt.at + LOCKOUT_MS;
      failures = 0;
    }
  }
  return until !== null && until > now ? until : null;
}

export interface AttemptResult {
  /** この試行でロックが始まったか。監査ログに残すために返す */
  lockedNow: boolean;
}

/**
 * パスワードを照合した結果を記録し、ロックが始まったかを返す。
 * 存在する利用者なら users.locked_until にも書く（S9: 解除後も「ロックされた」記録を残す）。
 */
export function recordLoginAttempt(
  db: Db,
  a: { email: string; userId: number | null; succeeded: boolean; ip: string | null; now: number },
): AttemptResult {
  const wasLocked = lockedUntil(db, a.email, a.now) !== null;
  insertLoginAttempt(db, { ...a, at: a.now });
  const until = lockedUntil(db, a.email, a.now);
  const lockedNow = !wasLocked && until !== null;
  if (lockedNow && a.userId !== null) {
    setLockedUntil(db, a.userId, until);
  }
  return { lockedNow };
}

export const LOCKED_MESSAGE =
  'ログインの失敗が続いたため、このアカウントへのログインを一時的に止めています。15 分ほど待ってからもう一度お試しください';
