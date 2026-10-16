// WebAuthn の「チャレンジ」（サーバーが出す使い捨ての乱数）の一時保管。
//
// チャレンジは「この応答は今この場で署名されたものだ」と確かめるための値で、
// 1) サーバーが作ったものであること 2) 1 回しか使えないこと 3) 短時間で切れること、が要る。
// 1 回使ったら消し、期限（5 分）を過ぎたら無効にして、盗聴した古い応答の再送（リプレイ）を防ぐ。
//
// 保管場所はプロセスのメモリ。参照実装として読みやすさを優先した。複数台・複数プロセスで動かす場合は
// どのプロセスに要求が来ても引けるよう、DB や Redis などの共有の置き場に移す必要がある。
import { randomBytes } from 'node:crypto';

const TTL_MS = 5 * 60 * 1000;
// メモリを食いつぶされないよう、未使用のチャレンジの数に上限を置く（古いものから捨てる）
const MAX_ENTRIES = 10_000;

/** 登録のときに覚えておくこと。ログインのときは challenge だけ */
export interface PendingCeremony {
  kind: 'register' | 'login';
  challenge: string;
  /** 登録: 既存ユーザーへの追加なら user の id、新規登録なら null */
  userId?: number | null;
  /** 登録（新規）: 登録しようとしているメールアドレス */
  email?: string;
  expiresAt: number;
}

export class ChallengeStore {
  private readonly entries = new Map<string, PendingCeremony>();

  constructor(private readonly now: () => number = Date.now) {}

  /** 保管して、ブラウザに渡す引換券（乱数の ID）を返す。引換券は Cookie で持たせる */
  put(entry: Omit<PendingCeremony, 'expiresAt'>): string {
    this.sweep();
    const ticket = randomBytes(32).toString('base64url');
    this.entries.set(ticket, { ...entry, expiresAt: this.now() + TTL_MS });
    return ticket;
  }

  /** 取り出して消す（使い切り）。期限切れや種類違いは undefined */
  take(ticket: string | undefined, kind: PendingCeremony['kind']): PendingCeremony | undefined {
    if (!ticket) return undefined;
    const entry = this.entries.get(ticket);
    this.entries.delete(ticket);
    if (!entry || entry.kind !== kind || entry.expiresAt <= this.now()) return undefined;
    return entry;
  }

  private sweep(): void {
    const now = this.now();
    for (const [k, v] of this.entries) {
      if (v.expiresAt <= now) this.entries.delete(k);
    }
    // Map は挿入順を保つので、先頭から消せば古いものから捨てられる
    while (this.entries.size >= MAX_ENTRIES) {
      const first = this.entries.keys().next();
      if (first.done) break;
      this.entries.delete(first.value);
    }
  }
}
