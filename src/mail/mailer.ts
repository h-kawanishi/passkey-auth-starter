/**
 * メール送信の窓口。送信事業者との接続は本実装の範囲外（§2）なので、
 * 利用者が自分の事業者向けにこの型を実装して差し替えられるようにしておく。
 * メールはパスワード再設定（回復）にだけ使い、認証の要素には使わない（S11）。
 */
export interface Mailer {
  send(to: string, subject: string, body: string): Promise<void>;
}
