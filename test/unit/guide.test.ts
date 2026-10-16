// 初心者向け解説（docs/guide/）と README の書式・引用を確かめる。
//
// 解説はコードの該当行を引用している。コードを直しても解説が古いままだと、初心者は「書いてあることと
// 実物が違う」ところで迷う。そこで、引用の 1 行目に「出典: ファイル:開始行-終了行」を書く約束にし、
// その行範囲の中身と引用が一致することをテストで確かめる（ずれたら CI で気づける）。
//
// 書式の約束（各章の先頭は「# 見出し」1 つ、図は ```mermaid、コードは言語付きのフェンス）は、
// jumpstack.co.jp 側の変換スクリプト（設計書 §11）が前提にするので、ここで崩れていないかも確かめる。
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

const ROOT = join(import.meta.dirname, '..', '..');
const GUIDE_DIR = join(ROOT, 'docs', 'guide');

// 設計書 §8 の章立て。ファイル名は jumpstack.co.jp 側の URL（01.html〜10.html）の元になるので固定する
const CHAPTERS = [
  '00-読む前に.md',
  '01-ログインとは何か.md',
  '02-パスワードの正しい持ち方.md',
  '03-なぜ15文字で記号は不要なのか.md',
  '04-セッションとCookie.md',
  '05-パスキーの仕組み.md',
  '06-コードを読む-登録.md',
  '07-コードを読む-ログイン.md',
  '08-パスワード忘れと回復.md',
  '09-攻撃と防御.md',
  '10-自分のサービスに組み込む.md',
];

interface Fence {
  lang: string;
  lines: string[];
  /** 章の中での開始行（1 始まり）。失敗したときにどこを直せばよいかを示すため */
  at: number;
}

/** Markdown を「フェンスの外の行」と「フェンス」に分ける */
function parse(md: string): { prose: string[]; fences: Fence[] } {
  const prose: string[] = [];
  const fences: Fence[] = [];
  let current: Fence | undefined;
  md.split('\n').forEach((line, i) => {
    if (current) {
      if (line.startsWith('```')) {
        fences.push(current);
        current = undefined;
      } else {
        current.lines.push(line);
      }
      return;
    }
    const open = /^```(.*)$/.exec(line);
    if (open) {
      current = { lang: (open[1] ?? '').trim(), lines: [], at: i + 1 };
      return;
    }
    prose.push(line);
  });
  if (current) throw new Error(`${current.at} 行目のフェンスが閉じていません`);
  return { prose, fences };
}

// 設計書 §8 の「各章 A4 で 2〜3 枚」の目安。A4 1 枚を 1,500 字程度と見て、3 枚に収まる量にする
const MAX_CHAPTER_CHARS = 4500;
// 設計書 §8 の「絶対安全」「100%」と、jumpstack.co.jp の記事の禁止語「必ず」
const BANNED_WORDS = /絶対|必ず|100\s*[%％]|１００\s*[%％]/;

const read = (file: string): string => readFileSync(join(GUIDE_DIR, file), 'utf8');

// 引用の 1 行目。言語ごとのコメントの書き方に合わせる（// 出典: / -- 出典: / <!-- 出典: -->）
const SOURCE_MARK = /出典: (\S+?):(\d+)-(\d+)/;
// 引用の途中を省くときの行。前後の空白を除いてこの形なら「ここで何行か飛ばす」の意味
const ELISION = /^(\/\/|--|<!--) …（略）( -->)?$/;

/**
 * 引用がファイルの行範囲と一致するかを確かめ、食い違いを文字列で返す（一致なら null）。
 * 省略の行（…（略））のあとは、次に引用した行が見つかるまで読み飛ばしてよい。
 */
function mismatch(fence: Fence): string | null {
  const mark = SOURCE_MARK.exec(fence.lines[0] ?? '');
  if (!mark) return null;
  const [, path = '', startRaw = '', endRaw = ''] = mark;
  const start = Number(startRaw);
  const end = Number(endRaw);
  const source = readFileSync(join(ROOT, path), 'utf8').split('\n');
  let i = start - 1;
  let skipping = false;
  for (const line of fence.lines.slice(1)) {
    if (ELISION.test(line.trim())) {
      skipping = true;
      continue;
    }
    if (skipping) {
      while (i < end && source[i] !== line) i += 1;
      skipping = false;
    }
    if (i >= end || source[i] !== line) {
      return `${path}:${start}-${end} の ${i + 1} 行目が引用と違います\n  引用: ${line}\n  実物: ${source[i] ?? '(範囲外)'}`;
    }
    i += 1;
  }
  if (i !== end) return `${path}:${start}-${end} のうち ${i} 行目までしか引用していません（範囲を直してください）`;
  return null;
}

describe('docs/guide: 章立て（設計書 §8）', () => {
  it('00〜10 の 11 章がそろい、それ以外の章は無い', () => {
    // macOS などはファイル名の濁点を分解した形（NFD）で返すことがあるので、比べる前にそろえる
    const files = readdirSync(GUIDE_DIR)
      .map((f) => f.normalize('NFC'))
      .filter((f) => /^\d{2}-/.test(f));
    expect(files.sort()).toEqual([...CHAPTERS].sort());
  });
});

describe.each(CHAPTERS)('docs/guide/%s', (file) => {
  const md = read(file);
  const { prose, fences } = parse(md);

  it('先頭の行が「# 見出し」で、# の見出しは 1 つだけ', () => {
    expect(md.split('\n')[0]).toMatch(/^# \S/);
    expect(prose.filter((l) => /^# /.test(l))).toHaveLength(1);
  });

  it('フェンスには必ず言語（mermaid / ts / sql など）が付いている', () => {
    for (const f of fences) expect(f.lang, `${file} の ${f.at} 行目`).not.toBe('');
  });

  it('Mermaid の図は種類の宣言から始まる', () => {
    for (const f of fences.filter((x) => x.lang === 'mermaid')) {
      expect(f.lines[0], `${file} の ${f.at} 行目`).toMatch(/^(flowchart (TD|LR)|sequenceDiagram|stateDiagram-v2)$/);
    }
  });

  it('コードの引用は、出典の行範囲の中身と一致する', () => {
    const problems = fences.map(mismatch).filter((p): p is string => p !== null);
    expect(problems).toEqual([]);
  });

  it('「絶対」「100%」「必ず」を書かない（設計書 §8 の書き方の約束）', () => {
    // 「必ず」は jumpstack.co.jp 側の変換スクリプトが禁止語にしているので、ここでも先に止める
    expect(md).not.toMatch(BANNED_WORDS);
  });

  it(`A4 で 2〜3 枚に収まる（空白を除いて ${MAX_CHAPTER_CHARS} 字以内、設計書 §8）`, () => {
    // 引用や図も紙面を使うので、フェンスの中も含めて数える。空白は改行やインデントで増減するので除く
    expect(md.replace(/\s/g, '').length).toBeLessThanOrEqual(MAX_CHAPTER_CHARS);
  });
});

describe('README', () => {
  const readme = readFileSync(join(ROOT, 'README.md'), 'utf8');

  it('日本語と英語の両方に「5 分で動かす」手順がある（設計書 §9）', () => {
    expect(readme).toMatch(/## 5 分で動かす/);
    expect(readme).toMatch(/## Quick start \(5 minutes\)/);
    // 手順の中身（clone → install → .env → dev）が両方にある
    expect(readme.match(/cp \.env\.example \.env/g)?.length).toBeGreaterThanOrEqual(2);
    expect(readme.match(/npm run dev/g)?.length).toBeGreaterThanOrEqual(2);
  });

  it('解説の各章へのリンクが切れていない', () => {
    for (const file of CHAPTERS) {
      expect(readme).toContain(`docs/guide/${file}`);
    }
  });

  it('「絶対」「100%」「必ず」を書かない', () => {
    expect(readme).not.toMatch(BANNED_WORDS);
  });
});
