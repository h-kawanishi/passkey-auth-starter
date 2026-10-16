// Argon2id によるパスワードのハッシュ化と検証、漏えい済みパスワード一覧との照合。
// ハッシュの計算そのものは argon2 ライブラリに任せ、自前で書かない（CLAUDE.md）。
import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import argon2 from 'argon2';

// S2: NIST SP 800-63B-4 は「パスワードだけで使うなら 15 文字以上」を求める。
export const MIN_PASSWORD_LENGTH = 15;
// S2: 上限は 64 文字以上にせよ、とされる。長いパスフレーズを拒まない一方で、
// 巨大な入力でハッシュ計算に時間を使わされないよう、十分に大きい上限を置く。
export const MAX_PASSWORD_LENGTH = 256;

export type PasswordProblem = 'too_short' | 'too_long' | 'breached';

/**
 * 比較の前にパスワードを正規化する。
 * 同じ見た目の文字でも端末や入力方式によって別の符号で届くことがあり（全角・半角、合成済み文字など）、
 * そのままだと「正しいのに入れない」ことが起きる。NIST も Unicode の正規化（NFKC など）を勧めている。
 */
export function normalizePassword(password: string): string {
  return password.normalize('NFKC');
}

/** 文字数は「見た目の 1 文字」に近いコードポイント単位で数える（絵文字 1 個を 2 と数えないため） */
function lengthOf(password: string): number {
  return [...password].length;
}

let breachedList: Set<string> | undefined;

/**
 * S3: 同梱の漏えい済みパスワード一覧を読む。起動直後のリクエストを遅くしないよう最初の 1 回だけ読む。
 * 大文字小文字の違いだけの変形はよくある手口なので、小文字にそろえて比べる。
 */
function loadBreachedList(): Set<string> {
  if (!breachedList) {
    const text = readFileSync(join(import.meta.dirname, 'breached-passwords.txt'), 'utf8');
    breachedList = new Set(
      text
        .split('\n')
        .map((line) => line.trim())
        .filter((line) => line !== '' && !line.startsWith('#'))
        .map((line) => normalizePassword(line).toLowerCase()),
    );
  }
  return breachedList;
}

export function isBreachedPassword(password: string): boolean {
  return loadBreachedList().has(normalizePassword(password).toLowerCase());
}

/**
 * 新しく設定するパスワードを検査する。問題がなければ null。
 * S2: 文字種（大文字・数字・記号など）の組み合わせは求めない。NIST は文字種の強制が
 *     「Password1!」のような予測しやすい形を増やすだけだとして禁止している。
 * S4: 定期変更の強制もしない。変更を求めるのは漏えいの兆候があるときだけ（この関数は期限を見ない）。
 */
export function checkNewPassword(password: string): PasswordProblem | null {
  const length = lengthOf(normalizePassword(password));
  if (length < MIN_PASSWORD_LENGTH) return 'too_short';
  if (length > MAX_PASSWORD_LENGTH) return 'too_long';
  if (isBreachedPassword(password)) return 'breached';
  return null;
}

/** 利用者に見せる理由。S3 で拒否したときは「なぜ駄目か」を伝えないと、同じものを入れ直されるため */
export function passwordProblemMessage(problem: PasswordProblem): string {
  switch (problem) {
    case 'too_short':
      return `パスワードは ${MIN_PASSWORD_LENGTH} 文字以上にしてください（記号や数字を混ぜる必要はありません。長い文やことばの組み合わせがおすすめです）`;
    case 'too_long':
      return `パスワードは ${MAX_PASSWORD_LENGTH} 文字以内にしてください`;
    case 'breached':
      return 'このパスワードは過去の漏えい事件で流出した一覧に含まれているため使えません。別のパスワードにしてください';
  }
}

/**
 * S1: Argon2id でハッシュ化する。ソルトはライブラリが毎回ランダムに作り、結果の文字列に含める。
 * 利用者ごとにソルトが違うので、同じパスワードでも保存される値は別物になる（事前計算表が効かない）。
 * パラメータはライブラリの既定（メモリ 64MiB・反復 3・並列 4）。OWASP の推奨最低値を上回る。
 */
export async function hashPassword(password: string): Promise<string> {
  return argon2.hash(normalizePassword(password), { type: argon2.argon2id });
}

/** S1: 保存してあるハッシュと照合する。比較はライブラリ内で一定時間で行われる */
export async function verifyPassword(passwordHash: string, password: string): Promise<boolean> {
  return argon2.verify(passwordHash, normalizePassword(password));
}

/** 既定のパラメータが強化されたあとに、古いパラメータのハッシュを作り直すかどうか */
export function needsRehash(passwordHash: string): boolean {
  return argon2.needsRehash(passwordHash);
}

let dummyHash: Promise<string> | undefined;

/**
 * 存在しないメールでのログインでも、本物と同じだけハッシュ計算をする。
 * これを省くと応答が速く返り、所要時間の差から「そのメールは未登録」と分かってしまう（列挙防止）。
 * ダミーの元になる値は起動ごとの乱数で、どこにも保存しない。
 */
export async function verifyAgainstDummy(password: string): Promise<false> {
  dummyHash ??= hashPassword(randomBytes(32).toString('base64url'));
  await argon2.verify(await dummyHash, normalizePassword(password));
  return false;
}
