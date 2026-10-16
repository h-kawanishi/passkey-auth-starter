// 開発用の Mailer。送信する代わりに、メールの中身を標準出力へ書く。
import type { Config } from '../config.js';
import type { Mailer } from './mailer.js';

/**
 * 開発中に再設定の流れを試すための Mailer。届くはずのメール（再設定リンクを含む）を標準出力にそのまま出す。
 *
 * リンクには再設定トークンの生値が入る。ここで出すのは「利用者の受信箱」の代わりだからで、
 * アプリのログ（Fastify の logger）には流さない（S12: ログにトークンの生値を書かない）。
 * 本番でこれを使うと、受信箱に届くべき秘密がサーバーの出力に残ってしまうので、本番では作れないようにしている。
 */
export class ConsoleMailer implements Mailer {
  constructor(
    nodeEnv: Config['nodeEnv'],
    private readonly out: NodeJS.WritableStream = process.stdout,
  ) {
    if (nodeEnv === 'production') {
      throw new Error('ConsoleMailer は開発用です。本番では送信事業者につながる Mailer を使ってください');
    }
  }

  send(to: string, subject: string, body: string): Promise<void> {
    const line = '-'.repeat(60);
    this.out.write(`\n${line}\n[開発用メール] 宛先: ${to}\n件名: ${subject}\n\n${body}\n${line}\n`);
    return Promise.resolve();
  }
}
