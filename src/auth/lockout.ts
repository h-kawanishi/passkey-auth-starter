// 連続失敗の記録とロック判定（S8 のアカウント側の制限、S9）。
import type { Db } from '../db/connection.js';
import {
  insertLoginAttempt,
  listLoginAttempts,
  setLockedUntil,
  setLoginAttemptSucceeded,
} from '../db/repo.js';

/** S9: この回数だけ続けて失敗したらロックする */
export const LOCKOUT_THRESHOLD = 5;
/** S9: ロックしている時間。利用者が待てる長さで、総当たりの速度は 1 時間に 20 回程度まで落ちる */
export const LOCKOUT_MS = 15 * 60 * 1000;
// 判定のために遡る範囲。ロックは 15 分で切れるので、これより古い記録は結果に影響しない
const HISTORY_MS = 24 * 60 * 60 * 1000;

interface LockState {
  /** ロックの終了時刻。ロック中でなければ null */
  until: number | null;
  /** そのロックを始めた試行の id（「この試行でロックが始まったか」を見分けるため） */
  triggerId: number | null;
}

/**
 * 記録された試行を古い順にたどり、今のロックの状態を返す。
 *
 * ロック中に来た試行は記録しないので、記録は「ロック外で、照合を許した試行」だけになる。
 * それを順に数え直せば、成功で 0 に戻り、5 回目の失敗でロックが始まり、ロックが明けると 0 から数え直す、
 * という規則を存在しないメールにも同じように当てはめられる（ロックの有無で登録済みかどうかが分からないように）。
 */
function lockState(db: Db, email: string, now: number): LockState {
  let failures = 0;
  let state: LockState = { until: null, triggerId: null };
  for (const attempt of listLoginAttempts(db, email, now - HISTORY_MS)) {
    if (attempt.succeeded) {
      failures = 0;
      continue;
    }
    failures += 1;
    if (failures >= LOCKOUT_THRESHOLD) {
      state = { until: attempt.at + LOCKOUT_MS, triggerId: attempt.id };
      failures = 0;
    }
  }
  return state.until !== null && state.until > now ? state : { until: null, triggerId: null };
}

/** S9: 今ロック中なら、その終了時刻を返す */
export function lockedUntil(db: Db, email: string, now: number): number | null {
  return lockState(db, email, now).until;
}

export interface AttemptTarget {
  email: string;
  userId: number | null;
  ip: string | null;
  now: number;
}

export type GuardedResult =
  /** ロック中。照合していない（または照合したが、その間にロックが始まった）。セッションを発行してはいけない */
  | { status: 'locked' }
  /** 照合した。lockedNow はこの失敗でロックが始まったか（監査ログに残すため） */
  | { status: 'verified'; ok: boolean; lockedNow: boolean };

/**
 * S9: ロックを確かめてからパスワードを照合し、結果を記録する。ログインと /account/password の両方で使う。
 *
 * 「判定 → await で照合 → 記録」の順だと、照合を待つ間に同じメール宛ての要求が次々に判定を通り抜け、
 * 上限を超えて照合できてしまう（同時に送るだけでロックが効かない）。そこで、判定と「失敗」としての記録を
 * await を挟まない 1 つのトランザクションで先に済ませ（予約）、照合に成功したら成功に書き換える。
 * better-sqlite3 は同期なので、同時に来た要求もここで 1 件ずつ順に数えられ、上限を超えた分は照合前に止まる。
 */
export async function verifyWithLockout(
  db: Db,
  target: AttemptTarget,
  verify: () => Promise<boolean>,
): Promise<GuardedResult> {
  const attemptId = reserveAttempt(db, target);
  if (attemptId === null) return { status: 'locked' };
  const ok = await verify();
  return ok ? markSucceeded(db, target, attemptId) : settleFailure(db, target, attemptId);
}

/** ロック中なら null。そうでなければ「失敗」として 1 行を記録し、その id を返す */
function reserveAttempt(db: Db, t: AttemptTarget): number | null {
  return db.transaction(() => {
    if (lockedUntil(db, t.email, t.now) !== null) return null;
    return insertLoginAttempt(db, { ...t, succeeded: false, at: t.now });
  })();
}

/**
 * 照合に成功した行を成功に書き換える。ただし、照合を待つ間に（予約済みのほかの失敗で）ロックが
 * 始まっていたら、成功にはせず locked を返す。正しいパスワードがたまたま束に混ざっていても、
 * ロック後にセッションを発行しないため。
 */
function markSucceeded(db: Db, t: AttemptTarget, attemptId: number): GuardedResult {
  return db.transaction((): GuardedResult => {
    setLoginAttemptSucceeded(db, attemptId, true);
    if (lockedUntil(db, t.email, Date.now()) === null) {
      return { status: 'verified', ok: true, lockedNow: false };
    }
    setLoginAttemptSucceeded(db, attemptId, false);
    return { status: 'locked' };
  })();
}

/** 失敗を確定する。この行でロックが始まったなら、存在する利用者の users.locked_until にも書く（S9: 解除後も記録を残す） */
function settleFailure(db: Db, t: AttemptTarget, attemptId: number): GuardedResult {
  const state = lockState(db, t.email, Date.now());
  const lockedNow = state.triggerId === attemptId;
  if (lockedNow && state.until !== null && t.userId !== null) {
    setLockedUntil(db, t.userId, state.until);
  }
  return { status: 'verified', ok: false, lockedNow };
}

export const LOCKED_MESSAGE =
  'ログインの失敗が続いたため、このアカウントへのログインを一時的に止めています。15 分ほど待ってからもう一度お試しください';
