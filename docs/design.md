# passkey-auth-starter 設計書

作成日: 2026-10-16 / 状態: 初版（実装前）/ 監修: 川西 秀忠

## 1. 目的

パスワード認証を「正しく」実装し、パスキー（WebAuthn）を最初から選べるログイン機能の
**参照実装**を公開する。受託案件の土台としてそのまま使えること、そして
プログラム初心者が読んで「認証とは何をしているのか」を理解できることの両方を狙う。

背景: 2026年のKDDI事案では761万件のパスワードが平文で保存されていた（個人情報保護委員会 2026-08-19）。
NIST SP 800-63B-4 はソルト付きハッシュを義務とし、パスワードとOTPを「フィッシング耐性なし」と分類している。
本実装は「漏れても使えないものだけを持つ」を設計原則にする。

## 2. スコープ

### やること（v1.0）
- メールアドレス + パスワードでの登録・ログイン
- パスキーでの登録・ログイン（Discoverable Credential／条件付きUI＝自動入力対応）
- アカウント設定画面: パスキーの追加・名前変更・削除、パスワードの変更
- パスワード忘れ: メールで届く使い切りリンクによる再設定（メール送信はインターフェースで抽象化、開発時はコンソール出力）
- セッション管理: サーバー側セッション、HttpOnly/SameSite=Lax/Secure Cookie、ログアウト、全端末ログアウト
- 総当たり対策: ログイン・再設定・パスキー検証のレート制限と、連続失敗でのアカウント一時ロック
- 監査ログ: 登録・ログイン成功/失敗・パスキー追加/削除・再設定の各イベントを記録
- 初心者向け解説（docs/guide/、日本語）

### やらないこと
- SNSログイン（OAuth/OIDC）、SAML、多テナント、管理画面
- メール配信事業者との接続（インターフェースのみ）
- UIフレームワーク（素のHTML + 最小限のJS。見た目は二の次）
- 電話番号・SMS（NIST が「制限付き」とする手段は採用しない）

## 3. 技術スタック

| 役割 | 採用 | 理由 |
|---|---|---|
| 言語・実行環境 | TypeScript / Node.js 22 LTS | WebAuthn ライブラリが最も成熟している領域 |
| Webフレームワーク | Fastify | 型付き・軽量・プラグイン構成が読みやすい |
| パスキー | @simplewebauthn/server, @simplewebauthn/browser | WebAuthn の事実上の標準ライブラリ |
| パスワードハッシュ | argon2（Argon2id） | OWASP / NIST 推奨。メモリハード |
| DB | SQLite（better-sqlite3）+ 手書きマイグレーション | 外部サービス不要。参照実装として追いやすい |
| セッション | @fastify/session 相当を自前最小実装（SQLite 保存） | 仕組みを読めるようにするため |
| レート制限 | @fastify/rate-limit | 実績 |
| テスト | Vitest（単体・結合）、Playwright（E2E。WebAuthn 仮想認証器を使う） | パスキーをCIで自動テストするため |
| 静的解析 | ESLint + typescript-eslint、tsc --noEmit | |
| CI | GitHub Actions | push / PR ごとに lint・型検査・テスト |

## 4. 構成

```
src/
  server.ts            起動。プラグイン登録とルーティング
  config.ts            環境変数の読み込みと検証（RP_ID, ORIGIN, SESSION_SECRET 等）
  db/
    migrate.ts         マイグレーション実行
    migrations/        001_init.sql ...
    repo.ts            users / credentials / sessions / reset_tokens / audit_log への読み書き
  auth/
    password.ts        Argon2id によるハッシュ化と検証、漏えいリスト照合
    passkey.ts         登録・認証のオプション生成と検証（SimpleWebAuthn をラップ）
    session.ts         セッション発行・検証・失効
    reset.ts           再設定トークンの発行・検証・使い切り
    lockout.ts         連続失敗の記録とロック判定
  routes/
    signup.ts login.ts logout.ts passkeys.ts account.ts reset.ts
  mail/
    mailer.ts          interface Mailer { send(to, subject, body) }
    console-mailer.ts  開発用: コンソールへ出力
  web/
    *.html, app.js     素の画面。パスキー呼び出しは @simplewebauthn/browser
test/
  unit/                password, session, reset, lockout
  integration/         各ルートをアプリごと起動して検証
  e2e/                 Playwright + 仮想認証器でパスキー登録→ログイン
docs/
  design.md            本書
  threat-model.md      想定する攻撃と、それぞれをどの仕組みで防ぐか
  guide/               初心者向け解説（§8）
```

## 5. データモデル

```
users          id, email(unique), password_hash(nullable), created_at, locked_until(nullable)
credentials    id, user_id, credential_id(unique, bytes), public_key(bytes), counter, transports,
               device_name, created_at, last_used_at
sessions       id(random 256bit), user_id, created_at, expires_at, ip, user_agent
reset_tokens   token_hash(unique), user_id, expires_at, used_at(nullable)
login_attempts user_id or email, succeeded, at, ip
audit_log      id, user_id(nullable), event, detail(json), at, ip
```

決めごと:
- `password_hash` が NULL のユーザーは「パスキーのみ」。パスワードを後から足せる。
- 再設定トークンは**ハッシュ化して保存**する（トークン表そのものが漏れても使えない）。
- `credentials.public_key` は公開鍵。これが漏れてもログインには使えない（秘密鍵は端末にある）。

## 6. セキュリティ要件（検査可能な形で書く）

| # | 要件 | 根拠 | 検査方法 |
|---|---|---|---|
| S1 | パスワードは Argon2id + 固有ソルトで保存。平文・可逆暗号は禁止 | NIST 800-63B-4 §3.1.1.2 | DB の全列をダンプし、登録時のパスワード文字列が含まれないことをテスト |
| S2 | パスワードは15文字以上、上限64以上、文字種の強制なし、貼り付け可 | NIST §3.1.1.1 | 単体テスト |
| S3 | 設定・変更時に漏えい済みパスワード一覧と照合して拒否 | NIST §3.1.1.1 | 同梱の小リストで単体テスト。HIBP 連携は任意 |
| S4 | 定期変更を強制しない。漏えい兆候時のみ強制 | NIST §3.1.1.2 | 仕様として明記 |
| S5 | パスキーは Discoverable、user verification = preferred、RP ID はドメイン固定 | WebAuthn Level 3 | E2E（仮想認証器） |
| S6 | 認証器の署名カウンタを検証し、巻き戻りを拒否 | SimpleWebAuthn 既定 | 単体テスト |
| S7 | セッションIDは 256bit 乱数、Cookie は HttpOnly + SameSite=Lax + Secure（本番） | OWASP | 結合テストでヘッダ検査 |
| S8 | ログイン・再設定・パスキー検証に IP とアカウント双方のレート制限 | NIST §3.2.2 | 結合テスト |
| S9 | 連続失敗 N 回でアカウントを一定時間ロック、解除後も記録 | | 結合テスト |
| S10 | 再設定トークンは使い切り・短期（15分）・ハッシュ保存・メールでのみ通知 | | 単体・結合 |
| S11 | メールを「認証」には使わない（再設定＝アカウント回復として扱う） | NIST §3.1.3.1 | 仕様として明記 |
| S12 | 全イベントを監査ログに残す。ログにパスワード・トークンの生値を書かない | | ログ出力をテストで検査 |
| S13 | CSRF: 状態を変える要求は SameSite=Lax に加え Origin ヘッダ検証 | | 結合テスト |

## 7. 画面と流れ

1. **登録**: メール + パスワード（S2/S3 を満たす）か、「パスキーで登録」のどちらか。
2. **ログイン**: メール欄に条件付きUI（autocomplete="username webauthn"）。パスキーがあれば自動入力から1タップ。無ければパスワード。
3. **アカウント設定**: パスキー一覧（端末名・作成日・最終利用）、追加、削除、パスワード変更、他端末からログアウト。
4. **パスワード忘れ**: メール入力 → 存在の有無にかかわらず同じ応答 → 届いたリンク（15分有効・1回限り）→ 新パスワード。
5. **パスキーを失くした**: パスワードがあればそれで入り、新しいパスキーを登録。両方失くした場合は再設定メール経由（S11 の注意を guide に明記）。

## 8. 初心者向け解説（docs/guide/）— 必須成果物

対象は「プログラムを書き始めたばかりの人」「発注側で中身を理解したい人」。
各章は A4 で 2〜3 枚。コードの抜粋は短く、図は Mermaid で。

```
guide/
  00-読む前に.md          この解説の読み方。用語は初出で必ず説明する
  01-ログインとは何か.md   「本人であることを確かめる」をどう機械にやらせるか
  02-パスワードの正しい持ち方.md  平文・暗号化・ハッシュの違い。塩とは。なぜ戻せない形にするか（KDDI事案を例に）
  03-なぜ15文字で記号は不要なのか.md  NIST の考え方。漏えいリスト照合
  04-セッションとCookie.md  ログイン状態をどう覚えるか。HttpOnly/SameSite の意味
  05-パスキーの仕組み.md    鍵の組、端末に残る秘密、サーバーが持つのは公開鍵だけ、偽サイトで効かない理由
  06-コードを読む-登録.md   signup ルートを上から順に読む
  07-コードを読む-ログイン.md  password / passkey の2経路を読む
  08-パスワード忘れと回復.md   使い切りトークン、なぜメールは認証ではなく回復か
  09-攻撃と防御.md          総当たり、フィッシング、セッション奪取。それぞれどの行が防いでいるか
  10-自分のサービスに組み込む.md  何を変え、何を変えてはいけないか
```

書き方の約束:
- 専門用語は初出で一文で説明する（例: 「ハッシュ（元に戻せない変換）」）
- 「なぜそうするか」を先に、「どうやるか」を後に
- コード中のコメントは日本語で、**何をしているかではなく、なぜそうしているか**を書く
- 「絶対安全」「100%」は書かない

## 9. 受け入れ条件（v1.0 完了の定義）

- `npm run lint && npm run typecheck && npm test && npm run e2e` が CI で緑
- §6 の S1〜S13 すべてにテストまたは明記がある
- `docs/guide/` 00〜10 が揃い、初出の用語がすべて説明されている
- README（日本語・英語）に 5 分で動かす手順がある
- `docs/threat-model.md` がある

## 10. 進め方（クラウドセッション）

| 回 | 内容 | 依存 |
|---|---|---|
| A | 雛形: package.json, tsconfig, ESLint, Vitest, Playwright, CI, マイグレーション, 空のルート。CI を緑にする | なし |
| B | パスワード認証: S1〜S4, S7〜S9, S12, S13 と単体・結合テスト | A |
| C | パスキー: S5, S6 と E2E（仮想認証器）、アカウント設定画面 | A（B と並列可） |
| D | 回復: S10, S11、監査ログの仕上げ、threat-model.md | B, C |
| E | 初心者向け解説 guide/ 00〜10 と README | D |

各回は PR で止まり、人間がレビューしてマージする。

## 11. jumpstack.co.jp での公開

コードは GitHub（公開・MIT）に置き、**解説と入口は jumpstack.co.jp 側に持つ**。

- `https://jumpstack.co.jp/passkey-auth-starter/` — 紹介ページ。何ができるか、なぜ作ったか、5分で動かす手順、GitHub へのリンク、解説の目次
- `https://jumpstack.co.jp/passkey-auth-starter/guide/01.html` 〜 `10.html` — 初心者向け解説を HTML 化したもの。
  原本は本リポジトリの `docs/guide/*.md`。JumpStack-LP 側の生成スクリプト（`build/gen_guide.py`、新規）が
  Markdown を LP のデザインで HTML に変換する。**手で HTML を編集しない**（LP の既存ルールと同じ）
- セキュリティ関連コラム（委託先・メールアドレス・会員アプリ・パスキー）から紹介ページへリンクする
- 動くデモの常時公開はしない（サーバー費用と攻撃面を増やさない）。
  動作確認は `git clone` → `npm install` → `npm run dev` の手順を解説で示す
- `llms.txt` と `sitemap.xml` に紹介ページと解説を載せる（sitemap は gen_blog.py の entries に追加）
