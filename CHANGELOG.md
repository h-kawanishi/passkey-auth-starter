# 変更履歴

このプロジェクトの主な変更を記録します。書式は [Keep a Changelog](https://keepachangelog.com/ja/1.1.0/) に、
版の付け方は [Semantic Versioning](https://semver.org/lang/ja/) に倣います。

## [1.0.0] - 2026-10-21

設計書 [docs/design.md](docs/design.md) §9 の受け入れ条件をすべて満たした最初の版です。

### できること

- メールアドレス + パスワードでの登録・ログイン（Argon2id で保存、15 文字以上、文字種の強制なし、漏えい済みパスワードの拒否）— S1〜S4
- パスキーでの登録・ログイン（Discoverable Credential、ログイン画面の自動入力＝条件付き UI）、署名カウンタの巻き戻りの拒否 — S5, S6
- アカウント設定: パスキーの追加・名前変更・削除、パスワードの変更。パスキーの追加は直近 5 分以内の再認証が必要
- サーバー側セッション（256bit 乱数、HttpOnly / SameSite=Lax / 本番は Secure の Cookie）、ログアウト、すべての端末からのログアウト — S7
- IP とアカウントの双方へのレート制限、連続失敗でのアカウントの一時ロック（パスキーのログインはロックの対象外）— S8, S9
- パスワード忘れ: 15 分・1 回限り・ハッシュ保存のトークンをメールで送る再設定。メールは回復専用で、ログインには使わない — S10, S11
- 監査ログ（パスワード・トークンの生値は書かない）— S12
- CSRF 対策（SameSite=Lax に加えて Origin ヘッダの検証）— S13
- 初心者向け解説 [docs/guide/](docs/guide/) 00〜10、脅威モデル [docs/threat-model.md](docs/threat-model.md)、README（日本語・英語）

### 既知の制約と受け入れたリスク

詳しくは [docs/threat-model.md](docs/threat-model.md) §10・§11 を参照してください。

- 新規登録で、登録済みのメールアドレスは「登録済み」と分かる（列挙）。IP ごとのレート制限で速度を抑えている
- ログイン・再認証の直後 5 分以内の Cookie を盗まれると、パスキーを追加されうる
- レート制限のカウンタとチャレンジの置き場はプロセスのメモリにある。複数台・複数プロセスで動かすときは共有の置き場へ移す必要がある
- リバースプロキシの後ろでは `trustProxy` を設定しないと、IP がプロキシのものになる
- `login_attempts` と `audit_log` は消さずに増え続ける。保存期間は利用する側で決める
- メール送信は抽象化のみ。本番では Mailer を自分のメール送信事業者につなぐ（渡さないと起動しない）

[1.0.0]: https://github.com/h-kawanishi/passkey-auth-starter/releases/tag/v1.0.0
