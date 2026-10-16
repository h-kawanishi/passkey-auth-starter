// メールアドレスの正規化と、形の確認。

// RFC 5321 のアドレス長の上限。これを超える値は DB に入れない
const MAX_EMAIL_LENGTH = 254;

/**
 * 前後の空白を除き、小文字にそろえる。
 * 「User@Example.com」と「user@example.com」が別アカウントになると、
 * 本人が登録済みのアカウントに入れなかったり、同じ人のアカウントが二重にできたりするため。
 */
export function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}

/**
 * ゆるい形の確認だけをする（@ の前後に文字があり、空白を含まない）。
 * 厳密な検査は、実際に届くかどうか（D の再設定メール）でしか確かめられないので、ここでは誤入力を拾う程度にとどめる。
 */
export function isPlausibleEmail(email: string): boolean {
  return email.length <= MAX_EMAIL_LENGTH && /^[^\s@]+@[^\s@]+$/.test(email);
}
