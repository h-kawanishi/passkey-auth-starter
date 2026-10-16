import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  checkNewPassword,
  hashPassword,
  isBreachedPassword,
  MAX_PASSWORD_LENGTH,
  passwordProblemMessage,
  verifyAgainstDummy,
  verifyPassword,
} from '../../src/auth/password.js';
import { randomPassword } from '../helpers/app.js';

// 同梱の一覧から 15 文字以上のものを取り出す。「長さは足りているのに一覧にあるから拒否」を確かめるため
function breachedLongEntry(): string {
  const text = readFileSync(
    join(import.meta.dirname, '../../src/auth/breached-passwords.txt'),
    'utf8',
  );
  const entry = text.split('\n').find((l) => !l.startsWith('#') && [...l].length >= 15);
  if (!entry) throw new Error('一覧に 15 文字以上の項目がありません');
  return entry;
}

describe('S2: パスワードの長さの規則', () => {
  it('14 文字は拒否、15 文字は受理', () => {
    expect(checkNewPassword(randomPassword(14))).toBe('too_short');
    expect(checkNewPassword(randomPassword(15))).toBeNull();
  });

  it('64 文字を超えても受理する（上限は 64 以上）', () => {
    expect(checkNewPassword(randomPassword(65))).toBeNull();
    expect(checkNewPassword(randomPassword(MAX_PASSWORD_LENGTH))).toBeNull();
    expect(checkNewPassword(randomPassword(MAX_PASSWORD_LENGTH + 1))).toBe('too_long');
  });

  it('記号や数字・大文字がなくても受理する（文字種を強制しない）', () => {
    const lowerOnly = randomPassword(40).toLowerCase().replace(/[^a-z]/g, '');
    expect(lowerOnly.length).toBeGreaterThanOrEqual(15);
    expect(checkNewPassword(lowerOnly)).toBeNull();
  });

  it('文字数は見た目の 1 文字単位で数える（日本語や絵文字の長いパスフレーズも使える）', () => {
    const kana = 'あいうえおかきくけこさしすせそ'; // 15 文字
    expect(checkNewPassword(kana)).toBeNull();
    expect(checkNewPassword(kana.slice(0, 14))).toBe('too_short');
  });
});

describe('S3: 漏えい済みパスワード一覧との照合', () => {
  it('一覧にあるパスワードは長さが足りていても拒否し、理由を示す', () => {
    const leaked = breachedLongEntry();
    expect(checkNewPassword(leaked)).toBe('breached');
    expect(passwordProblemMessage('breached')).toContain('漏えい');
  });

  it('大文字小文字を変えただけでは一覧をすり抜けられない', () => {
    expect(isBreachedPassword(breachedLongEntry().toUpperCase())).toBe(true);
  });

  it('一覧は 1,000 件程度ある', () => {
    const text = readFileSync(
      join(import.meta.dirname, '../../src/auth/breached-passwords.txt'),
      'utf8',
    );
    const entries = text.split('\n').filter((l) => l !== '' && !l.startsWith('#'));
    expect(entries.length).toBeGreaterThanOrEqual(900);
  });
});

describe('S1: Argon2id でのハッシュ化', () => {
  it('Argon2id の PHC 文字列になり、元のパスワードを含まない', async () => {
    const password = randomPassword();
    const hash = await hashPassword(password);
    expect(hash.startsWith('$argon2id$')).toBe(true);
    expect(hash).not.toContain(password);
  });

  it('同じパスワードでもソルトが違うので別の値になる', async () => {
    const password = randomPassword();
    expect(await hashPassword(password)).not.toBe(await hashPassword(password));
  });

  it('正しいパスワードだけが一致する', async () => {
    const password = randomPassword();
    const hash = await hashPassword(password);
    expect(await verifyPassword(hash, password)).toBe(true);
    expect(await verifyPassword(hash, randomPassword())).toBe(false);
  });

  it('Unicode の正規化をしてから照合する（全角英数字でも同じパスワードとして扱う）', async () => {
    const half = randomPassword(20);
    const full = half.replace(/[!-~]/g, (c) => String.fromCharCode(c.charCodeAt(0) + 0xfee0));
    const hash = await hashPassword(half);
    expect(await verifyPassword(hash, full)).toBe(true);
  });

  it('ダミー照合は常に失敗する（未登録メールでも同じ時間をかけるため）', async () => {
    expect(await verifyAgainstDummy(randomPassword())).toBe(false);
  });
});
