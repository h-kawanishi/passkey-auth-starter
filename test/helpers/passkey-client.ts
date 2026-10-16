// 結合テスト用の「ブラウザ役」。Cookie を覚え、Origin を付けて app.inject() で要求する。
import type { FastifyInstance, LightMyRequestResponse } from 'fastify';
import type {
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
} from '@simplewebauthn/server';
import type { SoftAuthenticator } from './soft-authenticator.js';

export class TestBrowser {
  readonly cookies = new Map<string, string>();

  constructor(
    private readonly app: FastifyInstance,
    readonly origin: string,
  ) {}

  /** Set-Cookie を Cookie 置き場に反映する（Max-Age=0 は削除） */
  private remember(res: LightMyRequestResponse): void {
    const raw = res.headers['set-cookie'];
    const list = raw === undefined ? [] : Array.isArray(raw) ? raw : [raw];
    for (const line of list) {
      const [pair = ''] = line.split(';');
      const eq = pair.indexOf('=');
      const name = pair.slice(0, eq);
      const value = pair.slice(eq + 1);
      if (/Max-Age=0/i.test(line)) this.cookies.delete(name);
      else this.cookies.set(name, value);
    }
  }

  async request(
    method: 'GET' | 'POST' | 'PATCH' | 'DELETE',
    url: string,
    body?: unknown,
    headers: Record<string, string> = {},
  ): Promise<LightMyRequestResponse> {
    const cookie = [...this.cookies].map(([k, v]) => `${k}=${v}`).join('; ');
    const res = await this.app.inject({
      method,
      url,
      headers: { origin: this.origin, ...(cookie ? { cookie } : {}), ...headers },
      ...(body === undefined ? {} : { payload: body as Record<string, unknown> }),
    });
    this.remember(res);
    return res;
  }

  /** 「パスキーで新規登録」を最後まで行う */
  async signup(auth: SoftAuthenticator, email: string): Promise<LightMyRequestResponse> {
    const opt = await this.request('POST', '/passkeys/register/options', { email });
    if (opt.statusCode !== 200) return opt;
    const response = auth.register(opt.json<PublicKeyCredentialCreationOptionsJSON>());
    return this.request('POST', '/passkeys/register/verify', { response });
  }

  /** 「パスキーでログイン」。forge で応答を細工できる */
  async login(
    auth: SoftAuthenticator,
    forge: Parameters<SoftAuthenticator['authenticate']>[1] = {},
  ): Promise<LightMyRequestResponse> {
    const opt = await this.request('POST', '/passkeys/login/options', {});
    auth.counter += 1; // 実物の認証器と同じく、使うたびにカウンタを進める
    const response = auth.authenticate(opt.json<PublicKeyCredentialRequestOptionsJSON>(), forge);
    return this.request('POST', '/passkeys/login/verify', { response });
  }
}
