// パスキーの登録（新規登録・既存アカウントへの追加）と、一覧・名前変更・削除。
// ログイン（認証）のルートは passkey-login.ts にある。
//
// S8: 登録の開始・完了には IP ごとのレート制限（app.passkeyRateLimit、@fastify/rate-limit）を掛けている。
// S13: Origin の検証は server.ts の onRequest フック（auth/origin.ts）が全ルートに掛けている。
import type { RegistrationResponseJSON } from '@simplewebauthn/server';
import type { FastifyPluginCallback } from 'fastify';
import { createRegistrationOptions, verifyRegistration } from '../auth/passkey.js';
import { audit } from '../auth/audit.js';
import { isPlausibleEmail, normalizeEmail } from '../auth/email.js';
import { currentUser, requireUser, startSession } from '../auth/session.js';
import {
  countCredentialsByUser,
  createUser,
  deleteCredential,
  findUserByEmail,
  insertCredential,
  listCredentialsByUser,
  renameCredential,
} from '../db/repo.js';
import { clearCeremonyCookie, issueCeremony, readCeremonyTicket } from './passkey-ceremony.js';

const DEVICE_NAME_MAX = 64;
const DEFAULT_DEVICE_NAME = 'パスキー';

/** 端末名は利用者が付ける表示用の名前。空なら既定名、長すぎれば切る（画面とDBを壊さないため） */
function cleanDeviceName(raw: unknown): string {
  if (typeof raw !== 'string') return DEFAULT_DEVICE_NAME;
  const name = raw.trim().slice(0, DEVICE_NAME_MAX);
  return name === '' ? DEFAULT_DEVICE_NAME : name;
}

// 同じ文言を 2 か所（開始と完了）で返すので定数にする
const EMAIL_TAKEN = {
  message: 'このメールアドレスでは登録できません。登録済みならログインしてください。',
};

// ルートを登録するだけで待つ処理が無いので、async ではなく done で終わりを知らせる形にしている
export const passkeysRoutes: FastifyPluginCallback = (app, _opts, done) => {
  const { config, db, challenges } = app;

  // 登録の開始。ログイン中なら「このアカウントに追加」、未ログインなら「パスキーで新規登録」
  app.post<{ Body: { email?: string } }>(
    '/passkeys/register/options',
    {
      config: { rateLimit: app.passkeyRateLimit }, // S8: 未ログインでも呼べるため
      schema: { body: { type: 'object', properties: { email: { type: 'string', maxLength: 1024 } } } },
    },
    async (req, reply) => {
      const user = currentUser(req);
      if (user) {
        const existing = listCredentialsByUser(db, user.id);
        const options = await createRegistrationOptions(config, { email: user.email, existing });
        const entry = { kind: 'register', challenge: options.challenge, userId: user.id } as const;
        if (!issueCeremony(req, reply, entry)) return reply;
        return options;
      }

      // メールの正規化と形の確認はパスワードの登録（signup.ts）と同じ関数を使う。
      // 片方だけ大文字小文字を区別すると、同じ人のアカウントが二重にできるため
      const email = normalizeEmail(req.body?.email ?? '');
      if (!isPlausibleEmail(email)) return reply.code(400).send({ message: 'メールアドレスの形が正しくありません' });
      // 登録済みのメールは新規登録できない。この応答で「登録済み」が分かってしまう点は
      // パスワードの新規登録（signup.ts）と同じ扱いで、速度はレート制限（S8）で抑える。
      // 確認メールを挟んで列挙を防ぐかは未決（PR の「人間の判断が必要な点」）
      if (findUserByEmail(db, email)) return reply.code(409).send(EMAIL_TAKEN);
      const options = await createRegistrationOptions(config, { email, existing: [] });
      const entry = { kind: 'register', challenge: options.challenge, userId: null, email } as const;
      if (!issueCeremony(req, reply, entry)) return reply;
      return options;
    },
  );

  // 登録の完了。認証器が作った公開鍵を検証して保存する（秘密鍵は端末から出てこない）
  app.post<{ Body: { response: RegistrationResponseJSON; deviceName?: string } }>(
    '/passkeys/register/verify',
    {
      config: { rateLimit: app.passkeyRateLimit }, // S8
      schema: {
        body: {
          type: 'object',
          required: ['response'],
          properties: { response: { type: 'object' }, deviceName: { type: 'string' } },
        },
      },
    },
    async (req, reply) => {
      // 使い切り: 取り出した時点で消える。同じ応答をもう一度送っても通らない
      const pending = challenges.take(readCeremonyTicket(req), 'register');
      clearCeremonyCookie(req, reply);
      if (!pending) return reply.code(400).send({ message: '時間が経ちすぎました。もう一度お試しください。' });

      // 追加の場合は、開始したときと同じ人がまだログインしているかを確かめる
      const current = currentUser(req);
      if (pending.userId != null && current?.id !== pending.userId) {
        return reply.code(401).send({ message: 'ログインしてください' });
      }

      const result = await verifyRegistration(config, req.body.response, pending.challenge);
      if (!result.ok) {
        audit(req, 'passkey.register.failure', pending.userId ?? null);
        return reply.code(400).send({ message: 'パスキーを登録できませんでした。' });
      }

      const now = Date.now();
      const deviceName = cleanDeviceName(req.body.deviceName);
      // ユーザー作成と鍵の保存を 1 トランザクションにする。片方だけ成功した「鍵の無いユーザー」を残さないため
      const saved = db.transaction(() => {
        let userId = pending.userId ?? null;
        if (userId == null) {
          // パスワードを持たない「パスキーのみ」のユーザーとして作る（§5）。開始から完了までの間に同じメールで
          // 登録された場合は、UNIQUE 制約で null が返る
          if (!pending.email) return undefined;
          userId = createUser(db, { email: pending.email, passwordHash: null, now });
          if (userId === null) return undefined;
        }
        const credentialRowId = insertCredential(db, {
          userId,
          credentialId: result.credentialId,
          publicKey: result.publicKey,
          counter: result.counter,
          transports: result.transports,
          deviceName,
          createdAt: now,
        });
        return { userId, credentialRowId, isNewUser: pending.userId == null };
      });

      let out: ReturnType<typeof saved>;
      try {
        out = saved();
      } catch (err) {
        // credential_id の重複（同じ鍵の二重登録）は利用者の操作で起こりうるので 409 にする。それ以外は投げ直す
        if (err instanceof Error && /UNIQUE constraint failed: credentials/.test(err.message)) {
          return reply.code(409).send({ message: 'このパスキーは登録済みです。' });
        }
        throw err;
      }
      if (!out) return reply.code(409).send(EMAIL_TAKEN);

      if (out.isNewUser) {
        audit(req, 'signup', out.userId, { method: 'passkey' });
        startSession(req, reply, out.userId);
      }
      // S12: 記録するのは DB の行番号と表示名だけ。公開鍵や credential ID のバイト列は載せない
      audit(req, 'passkey.register', out.userId, { credential: out.credentialRowId, deviceName });
      return { ok: true };
    },
  );

  // 一覧。アカウント設定画面が使う。公開鍵や credential ID は返さない（画面に要らない情報は出さない）
  app.get('/passkeys', (req, reply) => {
    const user = requireUser(req, reply);
    if (!user) return reply;
    const passkeys = listCredentialsByUser(db, user.id).map((c) => ({
      id: c.id,
      deviceName: c.deviceName,
      createdAt: c.createdAt,
      lastUsedAt: c.lastUsedAt,
    }));
    return { email: user.email, hasPassword: user.hasPassword, passkeys };
  });

  const idParams = {
    type: 'object',
    required: ['id'],
    properties: { id: { type: 'integer', minimum: 1 } },
  } as const;

  app.patch<{ Params: { id: number }; Body: { deviceName: string } }>(
    '/passkeys/:id',
    {
      schema: {
        params: idParams,
        body: {
          type: 'object',
          required: ['deviceName'],
          properties: { deviceName: { type: 'string' } },
        },
      },
    },
    (req, reply) => {
      const user = requireUser(req, reply);
      if (!user) return reply;
      const deviceName = cleanDeviceName(req.body.deviceName);
      // 他人のパスキーの番号を指定されても、自分のものでなければ「見つからない」と同じ応答にする
      if (!renameCredential(db, user.id, req.params.id, deviceName)) {
        return reply.code(404).send({ message: 'パスキーが見つかりません。' });
      }
      audit(req, 'passkey.rename', user.id, { credential: req.params.id, deviceName });
      return { ok: true };
    },
  );

  app.delete<{ Params: { id: number } }>(
    '/passkeys/:id',
    { schema: { params: idParams } },
    (req, reply) => {
      const user = requireUser(req, reply);
      if (!user) return reply;
      // パスワードを持たない人が最後のパスキーを消すと、二度とログインできなくなる。それを防ぐ
      const owned = listCredentialsByUser(db, user.id).some((c) => c.id === req.params.id);
      if (owned && countCredentialsByUser(db, user.id) <= 1 && !user.hasPassword) {
        return reply.code(409).send({
          message: '最後のパスキーは削除できません。先に別のパスキーかパスワードを追加してください。',
        });
      }
      if (!deleteCredential(db, user.id, req.params.id)) {
        return reply.code(404).send({ message: 'パスキーが見つかりません。' });
      }
      audit(req, 'passkey.delete', user.id, { credential: req.params.id });
      return { ok: true };
    },
  );
  done();
};
