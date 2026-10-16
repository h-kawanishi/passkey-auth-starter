# passkey-auth-starter

パスワード認証を「正しく」実装し、パスキー（WebAuthn）を最初から選べるログイン機能の参照実装です。
受託案件の土台としてそのまま使えること、そしてプログラム初心者が読んで「認証とは何をしているのか」を理解できることを目指しています。

- 言語: TypeScript / Node.js 22 / Fastify
- パスキー: SimpleWebAuthn ／ パスワード: Argon2id ／ DB: SQLite
- ライセンス: MIT
- 設計書: [docs/design.md](docs/design.md) ／ 実装計画: [docs/plan.md](docs/plan.md) ／ 初心者向け解説: [docs/guide/](docs/guide/)（準備中）

紹介ページと解説の HTML 版: https://jumpstack.co.jp/passkey-auth-starter/ （準備中）

## 5分で動かす

```bash
git clone https://github.com/h-kawanishi/passkey-auth-starter.git
cd passkey-auth-starter
npm install
cp .env.example .env
npm run dev
# http://localhost:3000 を開く
```

## 検証

```bash
npm run lint && npm run typecheck && npm test && npm run e2e
```

## このプロジェクトについて

JumpStack株式会社（[jumpstack.co.jp](https://jumpstack.co.jp/)）が公開しています。
背景はコラム「[パスワードの平文保存は論外——OTPの限界とパスキーという答え](https://jumpstack.co.jp/blog/password-hirabun-rongai-passkey.html)」をご覧ください。

---

# passkey-auth-starter (English)

A reference implementation of a login system that stores passwords correctly (Argon2id with per-user salt) and offers passkeys (WebAuthn) from day one. Built with TypeScript, Node.js 22, Fastify, SimpleWebAuthn and SQLite. MIT licensed.

See [docs/design.md](docs/design.md) (Japanese) for the design and security requirements. English documentation is planned.
