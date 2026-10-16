import { PassThrough } from 'node:stream';
import { describe, expect, it } from 'vitest';
import { ConsoleMailer } from '../../src/mail/console-mailer.js';

describe('ConsoleMailer（開発用）', () => {
  it('メールの中身を出力先に書く', async () => {
    const out = new PassThrough();
    const chunks: string[] = [];
    out.on('data', (c: Buffer) => chunks.push(c.toString('utf8')));
    await new ConsoleMailer('development', out).send('a@example.com', '件名', '本文です');
    const text = chunks.join('');
    expect(text).toContain('a@example.com');
    expect(text).toContain('本文です');
  });

  it('本番では作れない（受信箱に届くべき秘密をサーバーの出力に残さないため）', () => {
    expect(() => new ConsoleMailer('production')).toThrow(/開発用/);
  });
});
