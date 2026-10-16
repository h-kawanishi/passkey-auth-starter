// テスト専用の「ソフトウェア認証器」。実物の認証器（指紋センサーやセキュリティキー）の代わりに、
// WebAuthn の登録応答・認証応答を Node の中で組み立てる。
//
// これはアプリの認証処理ではなく、検証側（@simplewebauthn/server）に渡す「入力」を作るための道具。
// わざと壊した応答（カウンタの巻き戻り、他人の credential ID）を作れるのが、ブラウザの仮想認証器では
// 難しい単体・結合テストのために自前で持つ理由。鍵の生成と署名は node:crypto に任せている。
import { createHash, generateKeyPairSync, randomBytes, sign, type KeyObject } from 'node:crypto';
import type {
  AuthenticationResponseJSON,
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
  RegistrationResponseJSON,
} from '@simplewebauthn/server';
import { isoBase64URL, isoCBOR } from '@simplewebauthn/server/helpers';

const sha256 = (data: Uint8Array | string): Buffer => createHash('sha256').update(data).digest();
const b64u = (buf: Uint8Array): string => Buffer.from(buf).toString('base64url');

// authenticatorData の flags。UP=利用者がそこにいる、UV=本人確認済み、AT=公開鍵を含む
const UP = 0x01;
const UV = 0x04;
const AT = 0x40;

function u32(n: number): Buffer {
  const b = Buffer.alloc(4);
  b.writeUInt32BE(n);
  return b;
}

export class SoftAuthenticator {
  readonly credentialId: Buffer = randomBytes(16);
  private readonly privateKey: KeyObject;
  private readonly publicKey: KeyObject;
  /** 次の認証応答に載せる署名カウンタ。巻き戻りのテストでは外から書き換える */
  counter = 0;
  userHandle = '';

  constructor(private readonly origin: string) {
    const pair = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    this.privateKey = pair.privateKey;
    this.publicKey = pair.publicKey;
  }

  /** 公開鍵を COSE 形式（WebAuthn が使う鍵の書式）にする。ES256 = 楕円曲線 P-256 + SHA-256 */
  private cosePublicKey(): Uint8Array {
    const jwk = this.publicKey.export({ format: 'jwk' });
    const key = new Map<number, number | Uint8Array>([
      [1, 2], // kty: EC2
      [3, -7], // alg: ES256
      [-1, 1], // crv: P-256
      [-2, Buffer.from(jwk.x ?? '', 'base64url')],
      [-3, Buffer.from(jwk.y ?? '', 'base64url')],
    ]);
    return isoCBOR.encode(key);
  }

  private clientData(type: string, challenge: string, origin = this.origin): Buffer {
    return Buffer.from(JSON.stringify({ type, challenge, origin, crossOrigin: false }));
  }

  /** navigator.credentials.create の代わり */
  register(options: PublicKeyCredentialCreationOptionsJSON): RegistrationResponseJSON {
    this.userHandle = options.user.id;
    const credIdLen = Buffer.alloc(2);
    credIdLen.writeUInt16BE(this.credentialId.length);
    const authData = Buffer.concat([
      sha256(options.rp.id ?? ''),
      Buffer.from([UP | UV | AT]),
      u32(this.counter),
      Buffer.alloc(16), // AAGUID（機種の識別子）。attestation=none なので 0 埋めでよい
      credIdLen,
      this.credentialId,
      Buffer.from(this.cosePublicKey()),
    ]);
    const attestationObject = isoCBOR.encode(
      new Map<string, string | Uint8Array | Map<string, string>>([
        ['fmt', 'none'],
        ['attStmt', new Map<string, string>()],
        ['authData', authData],
      ]),
    );
    const id = isoBase64URL.fromBuffer(new Uint8Array(this.credentialId));
    return {
      id,
      rawId: id,
      type: 'public-key',
      response: {
        clientDataJSON: b64u(this.clientData('webauthn.create', options.challenge)),
        attestationObject: b64u(attestationObject),
        transports: ['internal'],
      },
      clientExtensionResults: {},
      authenticatorAttachment: 'platform',
    };
  }

  /**
   * navigator.credentials.get の代わり。
   * claimCredentialId を渡すと「自分の鍵で署名しつつ、別の credential ID を名乗る」不正な応答を作る。
   */
  authenticate(
    options: PublicKeyCredentialRequestOptionsJSON,
    opts: { claimCredentialId?: Buffer; origin?: string } = {},
  ): AuthenticationResponseJSON {
    const authData = Buffer.concat([sha256(options.rpId ?? ''), Buffer.from([UP | UV]), u32(this.counter)]);
    const clientDataJSON = this.clientData('webauthn.get', options.challenge, opts.origin);
    // WebAuthn の署名対象は authenticatorData と clientDataJSON のハッシュを連結したもの
    const signature = sign('sha256', Buffer.concat([authData, sha256(clientDataJSON)]), this.privateKey);
    const id = isoBase64URL.fromBuffer(new Uint8Array(opts.claimCredentialId ?? this.credentialId));
    return {
      id,
      rawId: id,
      type: 'public-key',
      response: {
        clientDataJSON: b64u(clientDataJSON),
        authenticatorData: b64u(authData),
        signature: b64u(signature),
        userHandle: this.userHandle,
      },
      clientExtensionResults: {},
      authenticatorAttachment: 'platform',
    };
  }
}
