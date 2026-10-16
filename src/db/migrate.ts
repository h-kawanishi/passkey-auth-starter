import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadConfig } from '../config.js';
import { openDatabase, type Db } from './connection.js';

const MIGRATIONS_DIR = join(import.meta.dirname, 'migrations');

// 001_init.sql のように「3 桁の番号_名前.sql」だけを対象にする。番号順に一度ずつ適用する
const FILE_PATTERN = /^(\d{3})_[a-z0-9_]+\.sql$/;

export interface MigrationResult {
  applied: string[];
}

/**
 * 未適用のマイグレーションを番号順に適用する。何度実行しても同じ結果になる（適用済みは飛ばす）。
 * ORM を使わず手書きにしているのは、どんな表がどう作られるかを SQL のまま読めるようにするため（§3）。
 */
export function migrate(db: Db, dir: string = MIGRATIONS_DIR): MigrationResult {
  db.exec(`CREATE TABLE IF NOT EXISTS schema_migrations (
    name       TEXT    PRIMARY KEY,
    applied_at INTEGER NOT NULL
  )`);

  const done = new Set(
    db.prepare('SELECT name FROM schema_migrations').pluck().all() as string[],
  );
  const files = readdirSync(dir)
    .filter((f) => FILE_PATTERN.test(f))
    .sort();

  const record = db.prepare('INSERT INTO schema_migrations (name, applied_at) VALUES (?, ?)');
  const applied: string[] = [];
  for (const file of files) {
    if (done.has(file)) continue;
    const sql = readFileSync(join(dir, file), 'utf8');
    // 1 ファイルを 1 トランザクションで適用する。途中で失敗したら丸ごと無かったことになり、
    // 「半分だけ表ができた」状態で次の起動を迎えない
    db.transaction(() => {
      db.exec(sql);
      record.run(file, Date.now());
    })();
    applied.push(file);
  }
  return { applied };
}

function main(): void {
  const config = loadConfig();
  const db = openDatabase(config.databasePath);
  try {
    const { applied } = migrate(db);
    console.log(
      applied.length === 0
        ? 'マイグレーション: 適用済み（変更なし）'
        : `マイグレーション: ${applied.join(', ')} を適用しました`,
    );
  } finally {
    db.close();
  }
}

// `npm run migrate` で直接実行されたときだけ動かす。テストから import したときは動かさない
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  main();
}
