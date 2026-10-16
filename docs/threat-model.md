# 脅威モデル（threat-model.md）

作成: セッション D / 対象: v1.0 の実装（このファイルと同じコミットのコード）

この文書は「どんな攻撃を想定し、それぞれをどの仕組み・どのコードが防いでいるか」をまとめたものです。
設計書（`docs/design.md`）§6 のセキュリティ要件 S1〜S13 と対応させています。

- 行番号はこの文書を書いた時点のものです。コードを直したら、ここも合わせて直してください。
- 「防ぐ」は「成功しにくくする」という意味です。どの対策にも限界があり、限界は各節の「残るリスク」に書きました。

## 0. 前提

| 項目 | 前提 |
|---|---|
| 守るもの | 利用者のアカウント（なりすまされないこと）、パスワード・セッション・再設定リンク（漏れても使えないこと） |
| 攻撃者ができること | インターネットから任意の HTTP 要求を送れる。偽サイトを作れる。どこかで漏えいしたメールとパスワードの組を持っている。DB のコピーを盗み出せる場合もある |
| 攻撃者ができないこと（範囲外） | サーバーの OS や Node.js の乗っ取り、`SESSION_SECRET` の窃取、利用者の端末の乗っ取り、利用者のメール受信箱の乗っ取り（→ §5 の残るリスク） |
| 置き方 | 1 台・1 プロセス。https で配信し、`ORIGIN` と `RP_ID` を本番のドメインに合わせる。リバースプロキシの後ろに置く場合は `trustProxy` の設定が要る（§9） |

## 1. 総当たり（オンラインでのパスワード推測）

**攻撃**: 1 つのアカウントに対して、パスワードを次々に試す。

| 対策 | 要件 | 場所 |
|---|---|---|
| IP ごとのレート制限（15 分あたり 30 回）。ログイン・登録・パスワード変更・再設定に掛ける | S8 | `src/server.ts:66-78`（`@fastify/rate-limit`）、各ルートの `config: { rateLimit: app.authRateLimit }`（`src/routes/login.ts:18`, `src/routes/account.ts:26`, `src/routes/reset.ts:80`, `:118`） |
| アカウント単位のロック: 5 回続けて失敗すると 15 分止める。ロック中は正しいパスワードでも照合しない | S8, S9 | `src/auth/lockout.ts:11-13`（回数と時間）、`:74`（`verifyWithLockout`） |
| 判定と記録を 1 つのトランザクションで先に行う（同時に大量に送っても、上限を超えて照合しない） | S9 | `src/auth/lockout.ts:86`（`reserveAttempt`）、`:98`（`markSucceeded`） |
| パスワードとパスキーの失敗を同じ回数で数える（経路を変えて試し続けられない） | S9 | `src/routes/login.ts:40`、`src/routes/passkey-login.ts:80` |
| 「現在のパスワード」の照合（パスワード変更）も同じ回数に数える（盗んだセッションからの総当たりを防ぐ） | S9 | `src/routes/account.ts:51` |
| 15 文字以上を求める（推測に必要な回数を大きくする） | S2 | `src/auth/password.ts:9`, `:60-64` |

テスト: `test/integration/security.test.ts`（S8 / S9、同時要求）、`test/integration/passkey-lockout.test.ts`、`test/unit/lockout.test.ts`

**残るリスク**: ロックはメールアドレスを知っている第三者でも起こせる（利用者を 15 分ずつ締め出す妨害）。
パスキーのログインも同じロックで止まる（§10 の「判断が必要な点」）。多数の IP を使う分散型の総当たりは、
IP の制限では止まらず、アカウント単位のロック（1 時間に 20 回程度まで）で速度を落とすだけになる。

## 2. 資格情報の使い回し（クレデンシャルスタッフィング）

**攻撃**: 他のサービスから漏れた「メール + パスワード」の組を、そのまま試す。

| 対策 | 要件 | 場所 |
|---|---|---|
| 登録・変更・再設定のとき、漏えい済みパスワード一覧と照合して拒否する | S3 | `src/auth/password.ts:50`（`isBreachedPassword`）、`:64`。一覧は `src/auth/breached-passwords.txt` |
| パスキーを最初から選べる（パスキーには「使い回せる秘密」が無い） | S5 | `src/routes/passkeys.ts`、`src/web/signup.html` |
| §1 のレート制限とロック | S8, S9 | §1 と同じ |
| 文字種の強制や定期変更の強制をしない（覚えられない規則は使い回しを増やすため） | S2, S4 | `src/auth/password.ts:60-64`（長さと漏えい一覧だけを調べる） |

テスト: `test/integration/security.test.ts`（S3）、`test/unit/password.test.ts`

**残るリスク**: 同梱の一覧は 1,000 件と小さい。HIBP などの大きな一覧との照合は任意（設計書 S3）。

## 3. フィッシング（偽サイトに入力させる）

**攻撃**: 本物そっくりのサイトに誘導し、パスワードやワンタイムコードを入力させて盗む。

| 対策 | 要件 | 場所 |
|---|---|---|
| パスキーの RP ID をドメインに固定する。認証器は別ドメインの偽サイトでは署名しない | S5 | `src/auth/passkey.ts:38`, `:104` |
| 応答に記録されたオリジン（どのサイトで署名したか）を検証する。偽サイト経由の応答は通らない | S5 | `src/auth/passkey.ts:76`, `:127`（`expectedOrigin`） |
| チャレンジは使い切り・5 分。盗み見た応答を後から使い回せない | S5 | `src/auth/challenges.ts:11`, `:77`（`take`） |
| メールや SMS のコードをログインの要素にしない（コードは偽サイトに中継できる） | S11 | `src/mail/mailer.ts`（コメント）、`src/routes/reset.ts:162`（再設定後もログイン状態にしない） |

テスト: `test/unit/passkey.test.ts`（偽オリジンの拒否）、`test/integration/audit.test.ts`（偽サイトで作った登録応答が `passkey.register.failure` になる）

**残るリスク**: パスワードはフィッシングに弱いまま（NIST はパスワードを「フィッシング耐性なし」と分類する）。
利用者がパスワードしか登録していなければ、偽サイトに入力した時点で盗まれる。パスキーへの移行を促すのが根本対策。

## 4. セッション奪取

**攻撃**: ログイン状態の Cookie（セッション ID）を盗む・推測する・仕込む・他サイトから使わせる。

| 攻撃の形 | 対策 | 要件 | 場所 |
|---|---|---|---|
| 推測 | セッション ID は 256bit の乱数 | S7 | `src/auth/session.ts:51` |
| XSS で Cookie を読む | HttpOnly（JavaScript から読めない）。利用者が付けた名前は `textContent` で表示 | S7 | `src/auth/session.ts:68`、`src/web/app.js:134` |
| 通信の盗聴 | 本番は Secure（https でしか送らない）と `__Host-` 接頭辞 | S7 | `src/auth/session.ts:25`, `:72` |
| DB の漏えい | DB には ID の HMAC-SHA256 だけを保存（鍵は `SESSION_SECRET`） | S7 | `src/auth/session.ts:33` |
| セッション固定（事前に仕込んだ ID でログインさせる） | ログインのたびに新しい ID を発行し、古い ID は消す | S7 | `src/auth/session.ts:51-55` |
| 盗まれた Cookie を使い続けられる | 有効期間 24 時間。パスワード変更・再設定・全端末ログアウトで全セッションを消す。**ただしセッションは消えるが、盗んだセッションの間に攻撃者が追加したパスキーは残る**（下の「残るリスク」） | S7 | `src/auth/session.ts:17`、`src/routes/account.ts:78`、`src/routes/reset.ts:154`、`src/routes/logout.ts:19` |
| CSRF（他サイトから要求を送らせる） | SameSite=Lax と、状態を変える要求の Origin 検証（全ルートに 1 か所で掛ける） | S13 | `src/auth/session.ts:70`、`src/auth/origin.ts:15-16`、`src/server.ts:80` |
| ログから Cookie を拾う | ログの Cookie / Set-Cookie ヘッダを伏せる | S12 | `src/server.ts:47` |

テスト: `test/integration/security.test.ts`（S7 / S13）、`test/integration/password-auth.test.ts`（ID の作り直し）、`test/integration/passkey-hardening.test.ts`（本番の Cookie 属性）

**残るリスク**: 有効期間中に端末そのものを奪われた場合は防げない（「すべての端末でログアウト」で利用者が切れる）。

**残るリスク（未対応・§10 で判断待ち）**: 既存アカウントへのパスキーの追加（`POST /passkeys/register/options` と `/passkeys/register/verify`、
`src/routes/passkeys.ts:43`）は、ログイン中であること（セッション Cookie）しか確かめず、再認証を求めない。
そのため、Cookie を盗んだ攻撃者は自分の認証器をパスキーとして登録できる。
利用者がパスワード変更・再設定・全端末ログアウトをしても、消えるのはセッションだけで、
パスキー（`credentials` 表）は残る（`src/routes/reset.ts:145-155`）。攻撃者はそのパスキーで入り直せる。
利用者は、アカウント設定のパスキー一覧で見覚えのないものを削除すれば締め出せるが、気づけなければ残り続ける。

## 5. 再設定トークンの再利用・横取り

**攻撃**: パスワード再設定のリンク（トークン）を盗む・推測する・使い回す。

| 攻撃の形 | 対策 | 要件 | 場所 |
|---|---|---|---|
| 推測 | トークンは 256bit の乱数 | S10 | `src/auth/reset.ts:44` |
| 使い回し | 使い切り。未使用・期限内の行だけを 1 文の UPDATE で使用済みにする（同時に 2 回送っても通るのは 1 回） | S10 | `src/db/repo/reset-tokens.ts:27-29`、`src/routes/reset.ts:146` |
| 古いリンクが受信箱に残る | 15 分で無効。新しいリンクを送ると古いものは無効。パスワードを変えたら未使用のリンクも無効 | S10 | `src/auth/reset.ts:15`（期間）, `:46`、`src/routes/account.ts:74` |
| DB の漏えい | DB にはトークンの SHA-256 だけを保存 | S10 | `src/auth/reset.ts:26` |
| ログ・Referer への漏れ | トークンは URL の `#` の後ろに置く（ブラウザはサーバーへ送らない）。画面は読み取った後に URL から消し、`no-referrer` を指定。メール送信の失敗ログには例外の種類だけを書く | S10, S12 | `src/auth/reset.ts:68`、`src/web/app.js`（`initResetNew`）、`src/web/reset-new.html:7`、`src/routes/reset.ts:63-73` |
| 開発用の出力が本番に残る | コンソールへ書く Mailer は本番では作れない。本番で Mailer を渡さないと起動しない | S10 | `src/mail/console-mailer.ts:17`、`src/server.ts:27` |
| 再設定をログインの抜け道にする | 再設定が済んでもログイン状態にしない（メールは回復の手段で、認証の手段ではない） | S11 | `src/routes/reset.ts:162` |

テスト: `test/unit/reset.test.ts`（使い切り・15 分・ハッシュのみ）、`test/integration/reset.test.ts`（同時の二重使用、パスワード変更での無効化、全端末ログアウト）、`test/e2e/reset.spec.ts`（URL からの消去）

**残るリスク**: 利用者のメール受信箱が乗っ取られていれば、再設定でアカウントを取られる。
これはメールを回復に使う以上避けられない（設計書 S11）。パスキーのみのユーザーも、メールでパスワードを足せる（§7-5 の回復手段）。
また、再設定は乗っ取りからの回復を完全には保証しない。乗っ取られている間に追加されたパスキーは再設定の後も残り、
攻撃者はそれで入り直せる（§4 の「残るリスク」。対策は §10 で判断待ち）。

## 6. 列挙（登録済みのメールアドレスを探る）

**攻撃**: 応答の違いや時間の違いから、あるメールアドレスが登録済みかを調べる（その後の標的型攻撃に使う）。

| 経路 | 対策 | 場所 |
|---|---|---|
| ログイン | 「存在しないメール」と「パスワード違い」で状態コード・本文・Cookie を同じにする。未登録でもダミーのハッシュと照合して時間をそろえる | `src/routes/login.ts:10`, `:46`、`src/auth/password.ts:106` |
| ロック | 未登録のメールにも同じ規則でロックを掛ける（ロックの有無で分からないように） | `src/auth/lockout.ts`（メールアドレス単位で数える） |
| パスワード再設定 | 登録の有無・送信上限の到達にかかわらず同じ応答。メール送信は応答の後に回し、時間でも分からないようにする | `src/routes/reset.ts:32`, `:63`, `:96-111` |
| パスキーのログイン | 開始時に「このメールの鍵」を返さない（Discoverable Credential）。失敗の応答はどの段階でも同じ | `src/auth/passkey.ts:106`、`src/routes/passkey-login.ts:24` |

テスト: `test/integration/security.test.ts`（ログイン・ロック）、`test/integration/reset.test.ts`（再設定の応答と所要時間）

**残るリスク**: 新規登録（パスワード・パスキーとも）は、登録済みのメールに 409 を返すので列挙できる
（`src/routes/signup.ts:44`、`src/routes/passkeys.ts:66`）。速度はレート制限で抑えている。
完全に防ぐには、確認メールを挟む登録フローが要る（§10）。

## 7. DB の漏えい（オフラインでの解析）

**攻撃**: DB ファイルを盗み、中身からパスワードや有効なセッションを取り出す。

| 値 | 保存の仕方 | 要件 | 場所 |
|---|---|---|---|
| パスワード | Argon2id + 固有のソルト（元に戻せない・総当たりに時間がかかる） | S1 | `src/auth/password.ts:86` |
| セッション ID | HMAC-SHA256（鍵は DB の外） | S7 | `src/auth/session.ts:33` |
| 再設定トークン | SHA-256 | S10 | `src/auth/reset.ts:26` |
| パスキー | 公開鍵だけ（秘密鍵は利用者の端末にある） | S5 | `src/db/migrations/001_init.sql`（credentials） |

テスト: `test/integration/security.test.ts`（S1）、`test/integration/audit.test.ts`（全テーブルに生値が無い）

## 8. 認証器の複製・他人の鍵の利用（パスキー）

| 攻撃 | 対策 | 要件 | 場所 |
|---|---|---|---|
| 鍵を複製した認証器 | 署名カウンタの巻き戻りを拒否し、監査ログに `counter_rollback` を残す（署名が本物のときだけ） | S6 | `src/auth/passkey.ts:114`, `:160`、`src/db/repo/credentials.ts:98` |
| 他人の credential ID を名乗る | 名乗った ID の持ち主の公開鍵で署名を検証する | S5 | `src/routes/passkey-login.ts:80-99` |
| 他人のパスキーの変更・削除（IDOR） | SQL の WHERE に必ず user_id を入れる | — | `src/db/repo/credentials.ts:108`, `:114` |
| チャレンジ置き場を埋める妨害 | 満杯なら新しい要求を断る（他人のものは押し出さない）。IP ごとの上限 | S8 | `src/auth/challenges.ts`、`src/routes/passkey-ceremony.ts` |

テスト: `test/unit/passkey.test.ts`、`test/integration/passkey-login.test.ts`、`test/integration/passkey-hardening.test.ts`、`test/integration/passkey-manage.test.ts`

## 9. ログからの漏えいと、事後の調査（S12）

- 監査ログに残すイベントは `src/auth/audit.ts` の `AUDIT_EVENTS` に集めている。`detail` は型で短いスカラー値に絞り（`src/db/repo/audit-log.ts:8`）、
  パスワード・セッション ID・トークンを入れられる形にしていない。
- テストで、すべての流れを通したあとに「定義したイベントがすべて記録される」ことと、
  「trace レベルのログ・監査ログ・DB に生値が無い」ことを確かめている（`test/integration/audit.test.ts`）。
- **残るリスク**: リバースプロキシの後ろに置くと、`trustProxy` を設定しない限り、監査ログ・レート制限・ロックの IP がプロキシの IP になる。
  レート制限のカウンタとチャレンジ置き場はプロセスのメモリにあるので、複数台・複数プロセスでは共有の置き場（Redis など）に移す必要がある。

## 10. 判断が必要な点（未決）

- 盗んだセッションで追加されたパスキーが、パスワード変更・再設定の後も残る（§4, §5）。対策の案は 2 つ。
  (a) 既存アカウントへのパスキー追加の前に再認証を求める（現在のパスワード、既存のパスキー、または直近数分以内のログイン）。
  パスワード変更が現在のパスワードを求めるのと同じ扱いにする。
  (b) 再設定が済んだら登録済みのパスキーの一覧をメールで知らせ、次のログインでアカウント設定の確認を促す。

- 新規登録での列挙（§6）。確認メールを挟む登録フローにするか。
- パスキーのログインにもアカウント単位のロックを掛けている（§1）。パスキーは推測できないので、ロックによる妨害（締め出し）のほうが害が大きいという考え方もある。
- `login_attempts` と `audit_log` の保存期間。今は消さずに増え続ける。
- 監査ログを改ざんから守る仕組み（追記専用の外部保存など）は v1.0 の範囲外。
