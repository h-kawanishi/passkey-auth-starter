// パスワード忘れ: 再設定メールの依頼（POST /reset）と、新しいパスワードの設定（POST /reset/confirm）。
// 画面（GET /reset, GET /reset/new）は routes/pages.ts にある。
//
// S10: 再設定トークンは使い切り・15 分・ハッシュ保存で、メールでのみ利用者に知らせる（auth/reset.ts）。
// S11: メールは回復の手段で、認証の手段ではない。再設定が済んでもログイン状態にはしない。
// S8: IP ごとのレート制限（app.authRateLimit）と、利用者ごとのメール送信回数の上限を掛ける。
// S13: Origin の検証は server.ts の onRequest フック（auth/origin.ts）が全ルートに掛けている。
import type { FastifyPluginCallback, FastifyRequest } from 'fastify';
import { audit } from '../auth/audit.js';
import { isPlausibleEmail, normalizeEmail } from '../auth/email.js';
import { checkNewPassword, hashPassword, passwordProblemMessage } from '../auth/password.js';
import {
  RESET_TOKEN_TTL_MS,
  consumeResetToken,
  isWellFormedResetToken,
  issueResetToken,
  resetLink,
} from '../auth/reset.js';
import {
  countAuditEvents,
  deleteSessionsOfUser,
  findUserByEmail,
  invalidateResetTokensOfUser,
  updatePasswordHash,
} from '../db/repo.js';

/** S8: 同じ利用者に送る再設定メールの上限（15 分あたり）。第三者が他人の受信箱をメールで埋める妨害を抑える */
export const RESET_MAILS_PER_WINDOW = 3;
const RESET_MAIL_WINDOW_MS = 15 * 60 * 1000;

// 列挙防止: 登録の有無・上限に達したかどうかにかかわらず、同じ状態コードと同じ文言を返す
const ACCEPTED_MESSAGE =
  '入力されたメールアドレスが登録されていれば、パスワード再設定用のリンクを送りました。リンクの有効期限は 15 分で、1 回だけ使えます';
const INVALID_LINK_MESSAGE =
  'このリンクは使えません。有効期限（15 分）が過ぎたか、すでに使われています。もう一度、再設定のメールを送ってください';

function mailBody(link: string): string {
  return [
    'パスワード再設定のご依頼を受け付けました。',
    '',
    '次のリンクを開き、新しいパスワードを決めてください。',
    `リンクの有効期限は ${RESET_TOKEN_TTL_MS / 60000} 分で、1 回だけ使えます。`,
    '',
    link,
    '',
    'このメールに心当たりがない場合は、何もしなくてかまいません。パスワードは変わりません。',
    'このリンクを他の人に教えないでください。',
  ].join('\n');
}

/**
 * メールの送信は応答を返した後に回し、完了を待たない。
 * 送信を待つと、登録済みのメール（送信あり）と未登録のメール（送信なし）で応答までの時間が変わり、
 * 時間を測るだけで登録の有無が分かってしまうため（列挙防止）。
 * 失敗は握りつぶさずにログへ残す。ただし例外の文には本文（＝トークン入りのリンク）が含まれうるので、
 * 例外の種類だけを書く（S12）。
 *
 * Mailer は利用者が差し替える前提なので、Promise を返す前に同期で例外を投げる実装もありうる。
 * そのまま .send(...).catch(...) と書くと同期の例外は .catch に届かず、プロセスが落ちる
 * （未ログインの誰でも /reset を 1 回送るだけでサーバーを止められる）うえ、例外の文が標準エラーにそのまま出る。
 * Promise.resolve().then(...) の中で呼び、同期の例外も同じ .catch に流す。
 */
function sendLater(request: FastifyRequest, to: string, link: string): void {
  setImmediate(() => {
    Promise.resolve()
      .then(() => request.server.mailer.send(to, 'パスワード再設定のご案内', mailBody(link)))
      .catch((err: unknown) => {
        request.log.error(
          { errName: err instanceof Error ? err.name : typeof err },
          '再設定メールを送れませんでした（詳細はメール送信側のログを確認してください）',
        );
      });
  });
}

export const resetRoutes: FastifyPluginCallback = (app, _opts, done) => {
  app.post<{ Body: { email: string } }>(
    '/reset',
    {
      config: { rateLimit: app.authRateLimit }, // S8
      schema: {
        body: {
          type: 'object',
          required: ['email'],
          properties: { email: { type: 'string', maxLength: 1024 } },
        },
      },
    },
    (request, reply) => {
      const email = normalizeEmail(request.body.email);
      // 形の確認は登録の有無と関係ないので、ここで 400 を返しても列挙にはならない
      if (!isPlausibleEmail(email)) {
        return reply.code(400).send({ message: 'メールアドレスの形が正しくありません' });
      }
      const now = Date.now();
      const user = findUserByEmail(app.db, email);
      if (!user) {
        // 未登録のメールへの依頼も残す（登録の有無を探る試みを、運用者が後から見つけられるように）
        audit(request, 'password.reset.request', null, { sent: false });
        return reply.send({ message: ACCEPTED_MESSAGE });
      }
      const recent = countAuditEvents(app.db, user.id, 'password.reset.request', now - RESET_MAIL_WINDOW_MS);
      if (recent >= RESET_MAILS_PER_WINDOW) {
        audit(request, 'password.reset.failure', user.id, { reason: 'too_many_requests' });
        return reply.send({ message: ACCEPTED_MESSAGE });
      }
      // パスキーのみのユーザー（password_hash が NULL）にも送る。パスキーを失くしたときの回復手段がこれしかないため（§7-5）
      const rawToken = issueResetToken(app.db, user.id, now);
      audit(request, 'password.reset.request', user.id, { sent: true });
      sendLater(request, user.email, resetLink(app.config.origin, rawToken));
      return reply.send({ message: ACCEPTED_MESSAGE });
    },
  );

  app.post<{ Body: { token: string; password: string } }>(
    '/reset/confirm',
    {
      config: { rateLimit: app.authRateLimit }, // S8
      schema: {
        body: {
          type: 'object',
          required: ['token', 'password'],
          properties: {
            token: { type: 'string', maxLength: 128 },
            password: { type: 'string', maxLength: 4096 },
          },
        },
      },
    },
    async (request, reply) => {
      // S2 / S3: 新しいパスワードの規則は登録時と同じ。トークンを使い切る前に調べ、言い直しができるようにする
      const problem = checkNewPassword(request.body.password);
      if (problem) {
        return reply.code(400).send({ message: passwordProblemMessage(problem), reason: problem });
      }
      // 明らかに形の違うトークンには、重いハッシュ計算をする前に断る（でたらめな要求で CPU を使わせない）
      if (!isWellFormedResetToken(request.body.token)) {
        audit(request, 'password.reset.failure', null, { reason: 'invalid_or_expired_token' });
        return reply.code(400).send({ message: INVALID_LINK_MESSAGE });
      }
      // S1: ハッシュ化（時間がかかる）を先に済ませ、トークンの消費からパスワードの更新までを
      // 1 つのトランザクションにする。途中で失敗して「トークンだけ使われた」状態を残さないため
      const passwordHash = await hashPassword(request.body.password);
      const now = Date.now();
      const outcome = app.db.transaction(() => {
        const userId = consumeResetToken(app.db, request.body.token, now); // S10: 使い切り・期限
        if (userId === undefined) return undefined;
        updatePasswordHash(app.db, userId, passwordHash);
        // 同じ人に送った他のリンクも使えなくする
        invalidateResetTokensOfUser(app.db, userId, now);
        // パスワードを知った第三者がすでに入っていたかもしれないので、全端末をログアウトさせる。
        // ただしパスキー（credentials）には触れない。パスキーの追加には直近 5 分以内の本人確認を求めているので
        // （人間の判断 2）、盗んだ Cookie だけで攻撃者がパスキーを足すことはしにくい。それでも本人確認の直後の
        // Cookie を盗まれた場合などに足されたパスキーは残る（threat-model.md §4 の「残るリスク」）
        const sessionsEnded = deleteSessionsOfUser(app.db, userId);
        return { userId, sessionsEnded };
      })();
      if (!outcome) {
        audit(request, 'password.reset.failure', null, { reason: 'invalid_or_expired_token' });
        return reply.code(400).send({ message: INVALID_LINK_MESSAGE });
      }
      audit(request, 'password.reset.complete', outcome.userId, { sessionsEnded: outcome.sessionsEnded });
      // S11: ここでログイン状態にはしない。新しいパスワード（かパスキー）で、あらためてログインしてもらう
      return reply.send({
        message: 'パスワードを再設定しました。新しいパスワードでログインしてください',
      });
    },
  );
  done();
};
