# 実装計画と各セッションの指示文

この計画は Claude Code（クラウドセッション）で順に実行する。各セッションは **1 つの PR で止まり、人間がレビューしてマージ**する。
次のセッションは前の PR がマージされた `main` から始める。依存のないものは並列で走らせてよい。

| 回 | 内容 | 依存 | 並列 |
|---|---|---|---|
| A | 雛形と CI | なし | — |
| B | パスワード認証 | A | C と並列可 |
| C | パスキー | A | B と並列可 |
| D | 回復・監査ログ・脅威モデル | B, C | — |
| E | 初心者向け解説と README | D | — |
| F | jumpstack.co.jp 側の紹介ページと解説 HTML（別リポジトリ JumpStack-LP） | E | — |

各セッションの冒頭に共通で付ける一文:
`CLAUDE.md と docs/design.md を先に読んでください。この指示は docs/plan.md の「セッション X」です。`

---

## セッション A — 雛形と CI

やること（設計書 §10 の A）:
- package.json（Node 22、scripts: dev / lint / typecheck / test / e2e / migrate）、tsconfig、ESLint（typescript-eslint）、Vitest、Playwright の設定
- 設計書 §4 のディレクトリ構成を作り、§5 のマイグレーション 001_init.sql と migrate.ts を実装
- src/config.ts（環境変数の読み込みと検証）と .env.example
- Fastify を起動して / と /healthz を返す最小の server.ts
- 単体テストと E2E テストが「1 件ずつ通る」状態にする（E2E は Playwright で / を開くだけでよい）
- .github/workflows/ci.yml がそのまま緑になること

やらないこと:
- 認証ロジック（パスワード、パスキー、セッション、回復）はまだ実装しない。空のルートと TODO コメントまで
- 依存は設計書 §3 のものに限る。追加するなら理由を PR に書く

終わったら:
1. npm run lint / typecheck / test / e2e の 4 つを実行し、出力を PR の説明に貼る
2. 作ったファイル一覧と、設計書と違う判断をした点（あれば）を PR に書いて、PR を作成して止まる。マージはしない

---

## セッション B — パスワード認証

やること（設計書 §6 の S1, S2, S3, S4, S7, S8, S9, S12, S13）:
- src/auth/password.ts: Argon2id でのハッシュ化と検証。同梱の漏えい済みパスワード小リスト（test 用に 1,000 件程度）との照合
- src/auth/session.ts: 256bit 乱数のセッション ID、SQLite 保存、Cookie は HttpOnly + SameSite=Lax、本番では Secure
- src/auth/lockout.ts: 連続失敗の記録と一定時間のロック
- src/routes/signup.ts, login.ts, logout.ts, account.ts（パスワード変更、全端末ログアウト）
- レート制限（IP とアカウントの両方）、Origin ヘッダ検証
- 監査ログへの記録（生値を書かない）
- web/: 登録・ログイン・アカウント設定の素の HTML

テスト（必須）:
- S1: 登録後に DB の全テーブル・全列をダンプし、登録に使ったパスワード文字列が含まれないこと
- S2: 14 文字は拒否、15 文字は受理、64 文字超も受理、記号なしでも受理
- S3: 漏えいリストにあるパスワードは拒否され、理由が利用者に示される
- S7: Set-Cookie に HttpOnly と SameSite=Lax があること
- S8/S9: 連続失敗でロックされ、ロック中は正しいパスワードでも入れないこと
- S13: Origin が異なる POST は拒否されること
- 「存在しないメール」と「パスワード違い」で応答が同じであること

終わったら: 4 つの検証を実行して出力を PR に貼り、PR を作成して止まる。マージはしない

---

## セッション C — パスキー

やること（設計書 §6 の S5, S6）:
- src/auth/passkey.ts: @simplewebauthn/server で登録オプション生成・検証、認証オプション生成・検証。Discoverable Credential、userVerification=preferred、RP ID は config から
- src/routes/passkeys.ts: 登録開始/完了、認証開始/完了、一覧、名前変更、削除
- web/: ログイン画面に条件付き UI（autocomplete="username webauthn"）、アカウント設定にパスキー一覧
- 署名カウンタの検証（巻き戻りを拒否）
- 監査ログへの記録

テスト（必須）:
- E2E: Playwright の CDP で WebAuthn 仮想認証器を有効にし、「パスキーで登録 → ログアウト → パスキーでログイン」が通ること
- S6: カウンタが巻き戻った認証応答を拒否すること（単体）
- 他人の credential_id では認証できないこと

終わったら: 4 つの検証を実行して出力を PR に貼り、PR を作成して止まる。マージはしない

---

## セッション D — 回復・監査ログ・脅威モデル

やること（設計書 §6 の S10, S11, S12）:
- src/auth/reset.ts と src/routes/reset.ts: 使い切り・15 分・ハッシュ保存の再設定トークン。メール存在の有無で応答を変えない
- src/mail/mailer.ts（interface）と console-mailer.ts
- 監査ログの仕上げ: 全イベントの網羅、ログに生値が出ないことのテスト
- docs/threat-model.md: 想定する攻撃（総当たり、資格情報の使い回し、フィッシング、セッション奪取、トークン再利用、列挙）と、それぞれをどの仕組み・どの行が防ぐか

テスト（必須）:
- トークンは 1 回使うと無効、15 分で無効、DB にはハッシュしか無い
- 存在しないメールでも応答と所要時間が同等

終わったら: 4 つの検証を実行して出力を PR に貼り、PR を作成して止まる。マージはしない

---

## セッション E — 初心者向け解説と README

やること（設計書 §8）:
- docs/guide/00〜10 を書く。各章 A4 で 2〜3 枚、図は Mermaid。実際のコードの該当行を引用する
- 書き方の約束（§8）を守る: 用語は初出で一文で説明、なぜを先に、「絶対」「100%」を書かない
- README を日本語・英語の 2 言語で整える（5 分で動かす手順を実際に試す）
- コード中のコメントを見直し、「何をしているか」しか書いていないものを「なぜそうしているか」に書き換える

終わったら: 4 つの検証を実行して出力を PR に貼り、変更ファイル一覧を書いて PR を作成して止まる。マージはしない

---

## セッション F — jumpstack.co.jp 側（リポジトリ JumpStack-LP で実行）

JumpStack-LP の CLAUDE.md を先に読むこと。

やること（本リポジトリ設計書 §11）:
- build/gen_guide.py を新規作成: passkey-auth-starter の docs/guide/*.md を取り込み（git submodule ではなく、実行時に GitHub から取得するか、引数でパスを受ける）、LP のデザイン（blog/blog.css を流用）で passkey-auth-starter/guide/NN.html に変換する。標準ライブラリのみ。手で HTML を編集しない前提
- passkey-auth-starter/index.html: 紹介ページ（何ができるか、なぜ作ったか、5 分で動かす、GitHub へのリンク、解説の目次）。fde/index.html の構成に倣う
- build/gen_blog.py の render_sitemap() に /passkey-auth-starter/ と guide/ を追加
- llms.txt に追記
- セキュリティ関連コラム 4 本（itakusaki-roei-jisha-mukizu, mail-address-dake-roei, kaiin-app-100man-ken-roei, password-hirabun-rongai-passkey）の本文末尾に紹介ページへのリンクを 1 文ずつ追加

終わったら: gen_blog.py --check と check_links.py を通し、PR を作成して止まる。本番へのアップロードは人間が行う
