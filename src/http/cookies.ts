// Cookie ヘッダの読み取りと Set-Cookie の組み立て。
// 依存を増やさないための最小実装。値の暗号化や署名はしない（入れるのは乱数の ID だけで、
// 中身の正しさは DB 側のハッシュ照合で確かめるため、署名は不要）。
// TODO(D: B と統合): B が @fastify/cookie を入れた場合はそちらに寄せる。

/** Cookie ヘッダを名前→値の表にする。壊れた要素は黙って飛ばす（攻撃者が送る値なので例外にしない） */
export function parseCookies(header: string | undefined): Map<string, string> {
  const out = new Map<string, string>();
  if (!header) return out;
  for (const part of header.split(';')) {
    const eq = part.indexOf('=');
    if (eq <= 0) continue;
    const name = part.slice(0, eq).trim();
    const value = part.slice(eq + 1).trim();
    // 同名が複数あれば先頭を使う（ブラウザはより具体的なパスのものを先に送るため）
    if (!out.has(name)) out.set(name, value);
  }
  return out;
}

export interface CookieOptions {
  /** 秒。0 なら即時に消す */
  maxAge: number;
  secure: boolean;
  path?: string;
}

/**
 * S7: HttpOnly（JavaScript から読めない＝XSS で盗まれにくい）と SameSite=Lax（他サイトからの
 * POST に Cookie を付けない）を常に付ける。Secure は本番（https）だけ。
 */
export function serializeCookie(name: string, value: string, opts: CookieOptions): string {
  const parts = [
    `${name}=${value}`,
    `Path=${opts.path ?? '/'}`,
    `Max-Age=${opts.maxAge}`,
    'HttpOnly', // S7: HttpOnly
    'SameSite=Lax', // S7: SameSite=Lax
  ];
  if (opts.secure) parts.push('Secure'); // S7: 本番は Secure
  return parts.join('; ');
}
