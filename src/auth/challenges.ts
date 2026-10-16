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
// メモリを食いつぶされないよう、未使用のチャレンジの数に上限を置く。
// 上限に達しても他人の期限内のチャレンジは捨てない。捨てると、開始の要求を大量に送るだけで
// 他の利用者のログイン・登録を途中で失敗させられる（妨害）ため。新しい要求のほうを断る。
const DEFAULT_MAX_ENTRIES = 10_000;
// 1 つの送信元（IP）が同時に持てる未使用のチャレンジの数。超えたら、その送信元自身の古いものから捨てる。
// 普通の利用者はタブを複数開いても数個で収まる。1 か所からの大量の要求が全体の上限を埋めないための歯止め
const DEFAULT_MAX_PER_OWNER = 20;

/** 登録のときに覚えておくこと。ログインのときは challenge だけ */
export interface PendingCeremony {
  /** reauth は「ログイン中の人が既存のパスキーで本人確認する」（パスキー追加の前の再認証） */
  kind: 'register' | 'login' | 'reauth';
  challenge: string;
  /** 登録: 既存ユーザーへの追加なら user の id、新規登録なら null。再認証: 確認を始めた user の id */
  userId?: number | null;
  /** 登録（新規）: 登録しようとしているメールアドレス */
  email?: string;
  expiresAt: number;
}

interface StoredCeremony extends PendingCeremony {
  owner: string;
}

export interface ChallengeStoreOptions {
  now?: () => number;
  maxEntries?: number;
  maxPerOwner?: number;
}

export class ChallengeStore {
  private readonly entries = new Map<string, StoredCeremony>();
  /** 送信元ごとの引換券。Set も挿入順を保つので、先頭がその送信元の最も古いもの */
  private readonly byOwner = new Map<string, Set<string>>();
  private readonly now: () => number;
  private readonly maxEntries: number;
  private readonly maxPerOwner: number;

  constructor(options: ChallengeStoreOptions = {}) {
    this.now = options.now ?? Date.now;
    this.maxEntries = options.maxEntries ?? DEFAULT_MAX_ENTRIES;
    this.maxPerOwner = options.maxPerOwner ?? DEFAULT_MAX_PER_OWNER;
  }

  /**
   * 保管して、ブラウザに渡す引換券（乱数の ID）を返す。引換券は Cookie で持たせる。
   * owner は送信元（IP）。全体が満杯なら undefined を返す（呼び出し側は 503 で「後で試して」と返す）。
   */
  put(entry: Omit<PendingCeremony, 'expiresAt'>, owner: string): string | undefined {
    this.sweepExpired();
    const mine = this.byOwner.get(owner) ?? new Set<string>();
    // 同じ送信元の上限を超えるなら、その送信元自身の最も古いものを捨てる（他人のものには触れない）
    while (mine.size >= this.maxPerOwner) {
      const oldest = mine.values().next();
      if (oldest.done) break;
      this.remove(oldest.value);
    }
    if (this.entries.size >= this.maxEntries) return undefined;
    const ticket = randomBytes(32).toString('base64url');
    this.entries.set(ticket, { ...entry, owner, expiresAt: this.now() + TTL_MS });
    mine.add(ticket);
    this.byOwner.set(owner, mine);
    return ticket;
  }

  /** 取り出して消す（使い切り）。期限切れや種類違いは undefined */
  take(ticket: string | undefined, kind: PendingCeremony['kind']): PendingCeremony | undefined {
    if (!ticket) return undefined;
    const entry = this.entries.get(ticket);
    this.remove(ticket);
    if (!entry || entry.kind !== kind || entry.expiresAt <= this.now()) return undefined;
    return entry;
  }

  private remove(ticket: string): void {
    const entry = this.entries.get(ticket);
    if (!entry) return;
    this.entries.delete(ticket);
    const mine = this.byOwner.get(entry.owner);
    mine?.delete(ticket);
    if (mine?.size === 0) this.byOwner.delete(entry.owner);
  }

  private sweepExpired(): void {
    const now = this.now();
    // Map は挿入順＝期限順（TTL が一定のため）なので、先頭から期限切れを消し、期限内に当たったら止める
    for (const [k, v] of this.entries) {
      if (v.expiresAt > now) break;
      this.remove(k);
    }
  }
}
