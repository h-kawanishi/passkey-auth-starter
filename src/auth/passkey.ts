// パスキーの登録・認証のオプション生成と検証。
// 暗号処理（署名の検証、公開鍵の取り出し、CBOR の解読）は @simplewebauthn/server に任せ、自前で書かない。
// このファイルの役目は「このアプリの方針（S5, S6）をライブラリの引数に落とすこと」と、
// ライブラリの例外を「成功 / 失敗」の結果に包んで、ルート側でエラーを取りこぼさないようにすること。
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
  type AuthenticationResponseJSON,
  type PublicKeyCredentialCreationOptionsJSON,
  type PublicKeyCredentialRequestOptionsJSON,
  type RegistrationResponseJSON,
} from '@simplewebauthn/server';
import { isoBase64URL } from '@simplewebauthn/server/helpers';
import { randomBytes } from 'node:crypto';
import type { Config } from '../config.js';
import type { CredentialRow } from '../db/repo.js';

/** 検証の結果。reason は監査ログと開発者向け。利用者には見せない（失敗理由の詳細は攻撃者の手がかりになる） */
export type Result<T> = ({ ok: true } & T) | { ok: false; reason: string };

function failure(err: unknown): { ok: false; reason: string } {
  return { ok: false, reason: err instanceof Error ? err.message : String(err) };
}

/**
 * 登録（navigator.credentials.create）に渡すオプションを作る。
 * excludeCredentials に登録済みの鍵を並べるのは、同じ端末で同じアカウントの鍵を二重に作らせないため。
 */
export async function createRegistrationOptions(
  config: Config,
  user: { email: string; existing: Pick<CredentialRow, 'credentialId' | 'transports'>[] },
): Promise<PublicKeyCredentialCreationOptionsJSON> {
  return generateRegistrationOptions({
    rpName: config.rpName,
    // S5: RP ID は設定から固定。パスキーはこのドメインにしか使えないので、偽サイトでは働かない
    rpID: config.rpId,
    userName: user.email,
    // WebAuthn の user.id（ユーザーハンドル）には個人情報を入れないよう求められているため、乱数にする。
    // 照合はユーザーハンドルではなく credential ID で行うので、保存しなくてよい
    userID: new Uint8Array(randomBytes(32)),
    // 署名の正しさは公開鍵で確かめられるため、認証器のメーカー証明（attestation）は求めない。
    // 求めると端末の機種が分かる情報を受け取ることになり、プライバシー上の負担が増える
    attestationType: 'none',
    excludeCredentials: user.existing.map((c) => ({
      id: isoBase64URL.fromBuffer(new Uint8Array(c.credentialId)),
      transports: c.transports,
    })),
    authenticatorSelection: {
      // S5: Discoverable Credential（端末側にユーザー情報を持つ鍵）。メールを打たずに選ぶだけでログインできる
      residentKey: 'required',
      // S5: user verification = preferred。指紋や PIN が使える端末では使い、無い鍵でも登録できるようにする
      userVerification: 'preferred',
    },
  });
}

export interface VerifiedRegistration {
  credentialId: Uint8Array;
  publicKey: Uint8Array;
  counter: number;
  transports: string[];
}

/** 登録応答を検証する。チャレンジ・オリジン・RP ID が一致し、署名が正しいときだけ ok */
export async function verifyRegistration(
  config: Config,
  response: RegistrationResponseJSON,
  expectedChallenge: string,
): Promise<Result<VerifiedRegistration>> {
  try {
    const v = await verifyRegistrationResponse({
      response,
      expectedChallenge,
      expectedOrigin: config.origin,
      expectedRPID: config.rpId,
      // S5: preferred なので、指紋や PIN の確認が無い認証器も受け入れる（本人のタッチ＝存在確認は必須のまま）
      requireUserVerification: false,
    });
    if (!v.verified) return { ok: false, reason: 'registration not verified' };
    const { credential } = v.registrationInfo;
    return {
      ok: true,
      credentialId: isoBase64URL.toBuffer(credential.id),
      publicKey: credential.publicKey,
      counter: credential.counter,
      transports: credential.transports ?? [],
    };
  } catch (err) {
    return failure(err);
  }
}

/**
 * ログイン（navigator.credentials.get）に渡すオプションを作る。
 * allowCredentials を空にするのは Discoverable Credential を使うため（S5）。
 * 「このメールの人の鍵はこれ」と返さないので、メールアドレスの存在が漏れない（列挙防止）。
 */
export async function createAuthenticationOptions(
  config: Config,
): Promise<PublicKeyCredentialRequestOptionsJSON> {
  return generateAuthenticationOptions({
    rpID: config.rpId, // S5
    userVerification: 'preferred', // S5
    allowCredentials: [],
  });
}

/**
 * ログイン応答を、DB に保存してある公開鍵とカウンタで検証する。
 * S6: 応答の署名カウンタが保存値以下（巻き戻り）なら失敗にする。鍵が複製された兆候だからである。
 * 判定自体は SimpleWebAuthn が行い（例外を投げる）、ここでは失敗として受け取る。
 */
export async function verifyAuthentication(
  config: Config,
  response: AuthenticationResponseJSON,
  expectedChallenge: string,
  stored: Pick<CredentialRow, 'credentialId' | 'publicKey' | 'counter' | 'transports'>,
): Promise<Result<{ newCounter: number }>> {
  try {
    const v = await verifyAuthenticationResponse({
      response,
      expectedChallenge,
      expectedOrigin: config.origin,
      expectedRPID: config.rpId,
      credential: {
        id: isoBase64URL.fromBuffer(new Uint8Array(stored.credentialId)),
        publicKey: new Uint8Array(stored.publicKey),
        counter: stored.counter, // S6
        transports: stored.transports,
      },
      requireUserVerification: false, // S5: preferred
    });
    if (!v.verified) return { ok: false, reason: 'authentication not verified' };
    return { ok: true, newCounter: v.authenticationInfo.newCounter };
  } catch (err) {
    return failure(err);
  }
}

/** 応答の id（base64url 文字列）を DB 照合用のバイト列にする。形式が壊れていれば undefined */
export function credentialIdFromResponse(id: unknown): Uint8Array | undefined {
  if (typeof id !== 'string' || id === '' || !isoBase64URL.isBase64URL(id)) return undefined;
  return isoBase64URL.toBuffer(id);
}
