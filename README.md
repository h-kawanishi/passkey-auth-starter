# passkey-auth-starter

[日本語](#passkey-auth-starter) | [English](#passkey-auth-starter-english)

パスワード認証を「正しく」実装し、パスキー（WebAuthn）を最初から選べるログイン機能の参照実装です。
受託案件の土台としてそのまま使えること、そしてプログラム初心者が読んで「認証とは何をしているのか」を理解できることを目指しています。

- 言語: TypeScript / Node.js 22 / Fastify
- パスキー: SimpleWebAuthn ／ パスワード: Argon2id ／ DB: SQLite
- ライセンス: MIT
- 設計書: [docs/design.md](docs/design.md) ／ 脅威モデル: [docs/threat-model.md](docs/threat-model.md) ／ 実装計画: [docs/plan.md](docs/plan.md)

紹介ページと解説の HTML 版: https://jumpstack.co.jp/passkey-auth-starter/ （準備中）

## できること

- メールアドレス + パスワードでの登録・ログイン（Argon2id で保存、15 文字以上、文字種の強制なし、漏えい済みパスワードの拒否）
- パスキーでの登録・ログイン（ログイン画面の自動入力から 1 タップ）、アカウント設定でのパスキーの追加・名前変更・削除
- サーバー側セッション（HttpOnly / SameSite=Lax / 本番は Secure の Cookie）、ログアウト、すべての端末からのログアウト
- パスワード忘れ: メールで届く 15 分・1 回限りのリンクで再設定（メールは回復専用で、ログインには使わない）
- レート制限と連続失敗のロック、CSRF 対策（Origin ヘッダの検証）、監査ログ

「漏れても使えないものだけを持つ」を設計原則にしています。DB にはパスワード・セッション ID・再設定トークンの生値を保存しません。

## 5 分で動かす

必要なもの: Node.js 22.12 以降、Git

```bash
git clone https://github.com/h-kawanishi/passkey-auth-starter.git
cd passkey-auth-starter
npm install
cp .env.example .env
npm run dev
```

ターミナルのログ（JSON 形式）に `"msg":"Server listening at http://127.0.0.1:3000"` と出たら、ブラウザで **http://localhost:3000** を開きます
（パスキーはドメイン名で動くので、`127.0.0.1` ではなく `localhost` で開いてください）。

1. 「新規登録」から、メールアドレスと 15 文字以上のパスワードで登録するか、「パスキーで登録」を押します
2. アカウント設定画面で、パスキーの追加や名前変更、パスワードの変更を試せます
3. ログアウトして、ログイン画面のメール欄をクリックすると、自動入力の候補にパスキーが出ます
4. 「パスワードを忘れた場合」から再設定を依頼すると、開発中はメールを送る代わりに、`npm run dev` のターミナルにメールの本文（リンク）が表示されます

- `.env` を書き換えなくても動きます。`SESSION_SECRET` が空のときは起動ごとに使い捨ての値を作るので、再起動するとログイン状態は消えます。
- データは `data/app.sqlite` に保存されます。最初からやり直したいときは、サーバーを止めて `data/` を消してください。
- ポートを変えるときは `.env` の `PORT` と `ORIGIN` を両方変えます（例: `PORT=3100` と `ORIGIN=http://localhost:3100`）。

## 初心者向け解説

仕組みを「なぜそうするのか」から説明した解説を [docs/guide/](docs/guide/) に置いています（日本語）。

| 章 | 内容 |
|---|---|
| [00 読む前に](docs/guide/00-読む前に.md) | この解説の読み方と約束 |
| [01 ログインとは何か](docs/guide/01-ログインとは何か.md) | 「本人であることを確かめる」をどう機械にやらせるか |
| [02 パスワードの正しい持ち方](docs/guide/02-パスワードの正しい持ち方.md) | 平文・暗号化・ハッシュの違い、ソルト、Argon2id |
| [03 なぜ15文字で記号は不要なのか](docs/guide/03-なぜ15文字で記号は不要なのか.md) | NIST SP 800-63B-4 の考え方と漏えい一覧の照合 |
| [04 セッションとCookie](docs/guide/04-セッションとCookie.md) | ログイン状態の覚え方、HttpOnly と SameSite |
| [05 パスキーの仕組み](docs/guide/05-パスキーの仕組み.md) | 鍵の組、公開鍵だけを持つサーバー、偽サイトで効かない理由 |
| [06 コードを読む: 登録](docs/guide/06-コードを読む-登録.md) | 新規登録のルートを上から順に読む |
| [07 コードを読む: ログイン](docs/guide/07-コードを読む-ログイン.md) | パスワードとパスキーの 2 経路を読む |
| [08 パスワード忘れと回復](docs/guide/08-パスワード忘れと回復.md) | 使い切りトークン、メールが認証ではなく回復である理由 |
| [09 攻撃と防御](docs/guide/09-攻撃と防御.md) | 攻撃ごとに、どの仕組みのどの行が防いでいるか |
| [10 自分のサービスに組み込む](docs/guide/10-自分のサービスに組み込む.md) | 変えるもの、変えてはいけないもの |

## 検証

```bash
npm run lint && npm run typecheck && npm test && npm run e2e
```

`npm run e2e` は Playwright で Chromium を動かし、WebAuthn の仮想認証器でパスキーの登録とログインを自動で試します。
初めて実行するときは `npx playwright install chromium` でブラウザを入れてください。CI（GitHub Actions）も同じ 4 つを実行します。

## 本番で使うとき

`.env` の `NODE_ENV=production`、`ORIGIN`（https）、`RP_ID`、`SESSION_SECRET` を設定し、再設定メールの送信手段（Mailer）を自分のメール送信事業者につないでください。
本番では Mailer を渡さないと起動しないようにしています。詳しくは [10 自分のサービスに組み込む](docs/guide/10-自分のサービスに組み込む.md) を参照してください。

## このプロジェクトについて

JumpStack株式会社（[jumpstack.co.jp](https://jumpstack.co.jp/)）が公開しています。
背景はコラム「[パスワードの平文保存は論外——OTPの限界とパスキーという答え](https://jumpstack.co.jp/blog/password-hirabun-rongai-passkey.html)」をご覧ください。

---

# passkey-auth-starter (English)

A reference implementation of a login system that stores passwords correctly and offers passkeys (WebAuthn) from day one.
It aims to be usable as-is as the foundation for real projects, and readable enough for beginners to understand what authentication actually does.

- Stack: TypeScript / Node.js 22 / Fastify
- Passkeys: SimpleWebAuthn / Passwords: Argon2id / Database: SQLite
- License: MIT
- Design: [docs/design.md](docs/design.md) / Threat model: [docs/threat-model.md](docs/threat-model.md) (both in Japanese)

## Features

- Sign up and sign in with email + password (Argon2id with a per-user salt, at least 15 characters, no composition rules, breached-password check)
- Sign up and sign in with passkeys (one tap from the browser's autofill), and add, rename or delete passkeys in account settings
- Server-side sessions (HttpOnly / SameSite=Lax cookies, Secure in production), sign out, and sign out of all devices
- Password reset via a single-use link that expires in 15 minutes (email is used only for account recovery, never as a sign-in factor)
- Rate limiting, account lockout after repeated failures, CSRF protection (Origin header check), and an audit log

The guiding principle is "only keep what is useless if leaked": the database never stores raw passwords, session IDs or reset tokens.

## Quick start (5 minutes)

Requirements: Node.js 22.12 or later, Git

```bash
git clone https://github.com/h-kawanishi/passkey-auth-starter.git
cd passkey-auth-starter
npm install
cp .env.example .env
npm run dev
```

When the (JSON) log in the terminal shows `"msg":"Server listening at http://127.0.0.1:3000"`, open **http://localhost:3000** in your browser
(passkeys are bound to a domain name, so use `localhost` rather than `127.0.0.1`).

1. Go to "新規登録" (Sign up) and register with an email and a password of 15+ characters, or press "パスキーで登録" (Sign up with a passkey)
2. In account settings, try adding or renaming passkeys and changing your password
3. Sign out and click the email field on the sign-in page: your passkey appears among the autofill suggestions
4. Request a password reset from "パスワードを忘れた場合" (Forgot password). In development no email is sent; the message (with the link) is printed in the terminal running `npm run dev`

- It works without editing `.env`. If `SESSION_SECRET` is empty, a throwaway value is generated on each start, so sessions are lost on restart.
- Data is stored in `data/app.sqlite`. To start over, stop the server and delete `data/`.
- To use another port, change both `PORT` and `ORIGIN` in `.env` (e.g. `PORT=3100` and `ORIGIN=http://localhost:3100`).

The UI text is in Japanese.

## Beginner's guide

A step-by-step guide that explains *why* each mechanism exists is in [docs/guide/](docs/guide/) (Japanese only for now).
An HTML version will be published at https://jumpstack.co.jp/passkey-auth-starter/ (coming soon).

## Verification

```bash
npm run lint && npm run typecheck && npm test && npm run e2e
```

`npm run e2e` drives Chromium with Playwright and uses a WebAuthn virtual authenticator to register and sign in with a passkey automatically.
Run `npx playwright install chromium` once before the first run. CI (GitHub Actions) runs the same four commands.

## Using it in production

Set `NODE_ENV=production`, `ORIGIN` (https), `RP_ID` and `SESSION_SECRET` in `.env`, and connect the password-reset `Mailer` to your email provider.
The server refuses to start in production without a Mailer. See [chapter 10 of the guide](docs/guide/10-自分のサービスに組み込む.md) (Japanese) for what to change and what must not be changed.

## About

Published by JumpStack Inc. ([jumpstack.co.jp](https://jumpstack.co.jp/)).
