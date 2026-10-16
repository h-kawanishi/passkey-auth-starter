import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import Database from 'better-sqlite3';

export type Db = Database.Database;

/**
 * SQLite を開き、このアプリが前提とする設定を必ず有効にする。
 * 接続ごとの設定なので、開く場所をここ 1 か所に集めて付け忘れを防ぐ。
 */
export function openDatabase(path: string): Db {
  if (path !== ':memory:') {
    // 初回起動で data/ が無くても動くようにする
    mkdirSync(dirname(path), { recursive: true });
  }
  const db = new Database(path);
  // SQLite は外部キー制約が既定で無効。ユーザー削除時にセッションや鍵が残らないよう有効にする
  db.pragma('foreign_keys = ON');
  // 読み書きが同時に起きてもロック待ちになりにくくする
  if (path !== ':memory:') {
    db.pragma('journal_mode = WAL');
  }
  return db;
}
