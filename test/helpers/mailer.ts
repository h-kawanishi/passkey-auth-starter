// テスト用の Mailer。送る代わりに覚えておき、テストから中身（再設定リンク）を取り出せるようにする。
import type { Mailer } from '../../src/mail/mailer.js';

export interface SentMail {
  to: string;
  subject: string;
  body: string;
}

export class CaptureMailer implements Mailer {
  readonly sent: SentMail[] = [];
  private waiters: (() => void)[] = [];

  /** delayMs を指定すると送信に時間がかかる事業者を装う（応答時間が送信を待っていないかを確かめるため） */
  constructor(private readonly delayMs = 0) {}

  async send(to: string, subject: string, body: string): Promise<void> {
    if (this.delayMs > 0) await new Promise((r) => setTimeout(r, this.delayMs));
    this.sent.push({ to, subject, body });
    for (const w of this.waiters.splice(0)) w();
  }

  /** count 通目が届くまで待つ。送信は応答の後に回るので、テストは応答を受けてからこれで待つ */
  async waitFor(count: number, timeoutMs = 5_000): Promise<SentMail> {
    const deadline = Date.now() + timeoutMs;
    while (this.sent.length < count) {
      if (Date.now() > deadline) throw new Error(`メールが ${count} 通届きませんでした`);
      await new Promise<void>((resolve) => {
        this.waiters.push(resolve);
        setTimeout(resolve, 50);
      });
    }
    return this.sent[count - 1]!;
  }
}

/** メール本文の再設定リンクから、# の後ろのトークンを取り出す */
export function tokenFromMail(mail: SentMail): string {
  const m = /\/reset\/new#token=([A-Za-z0-9_-]+)/.exec(mail.body);
  if (!m?.[1]) throw new Error('再設定リンクが見つかりません');
  return m[1];
}
