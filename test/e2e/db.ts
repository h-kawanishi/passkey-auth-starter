// E2E のサーバーと同じ DB ファイル（playwright.config.ts の E2E_DATABASE_PATH）を開いて、時間の経過を作る。
import Database from 'better-sqlite3';

/** 5 分の本人確認の有効時間（src/auth/session.ts の REAUTH_MAX_AGE_MS）より少し長く */
const PAST_MS = 5 * 60 * 1000 + 1000;

/** その人の全セッションの「最後に本人確認した時刻」を過去にずらし、5 分が過ぎた状態にする */
export function expireReauth(email: string): void {
  const path = process.env.E2E_DATABASE_PATH;
  if (!path) throw new Error('E2E_DATABASE_PATH がありません（playwright.config.ts が設定する）');
  const db = new Database(path);
  try {
    const changed = db
      .prepare(
        `UPDATE sessions SET reauthenticated_at = reauthenticated_at - ?
         WHERE user_id = (SELECT id FROM users WHERE email = ?)`,
      )
      .run(PAST_MS, email).changes;
    // 別のサーバー（reuseExistingServer で拾った古いもの）を相手にしていると 0 になる。黙って進めない
    if (changed === 0) throw new Error('セッションが見つかりません。E2E_PORT を変えてやり直してください');
  } finally {
    db.close();
  }
}
