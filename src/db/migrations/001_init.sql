-- 001_init: 設計書 §5 のデータモデル。
-- 時刻はすべて UNIX エポックからのミリ秒（INTEGER）。文字列の日時より大小比較（期限切れ判定）が単純になる。
-- 「漏れても使えないものだけを持つ」（§1）ため、秘密に当たる値は生値ではなくハッシュの列だけを持つ。

CREATE TABLE users (
  id            INTEGER PRIMARY KEY,
  -- 大文字小文字の正規化はアプリ側で行ってから保存する（B で実装）
  email         TEXT    NOT NULL UNIQUE,
  -- S1: Argon2id のハッシュ（PHC 文字列。ソルトを内包する）。NULL は「パスキーのみ」のユーザー
  password_hash TEXT,
  created_at    INTEGER NOT NULL,
  -- S9: 連続失敗でロックしている間の終了時刻。NULL はロックなし
  locked_until  INTEGER
);

CREATE TABLE credentials (
  id            INTEGER PRIMARY KEY,
  user_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  -- 認証器が発行する ID。ログイン時はこの値でどの公開鍵を使うかを引く
  credential_id BLOB    NOT NULL UNIQUE,
  -- 公開鍵。漏れてもログインには使えない（秘密鍵は利用者の端末にしかない）
  public_key    BLOB    NOT NULL,
  -- S6: 署名カウンタ。巻き戻りを検出して複製された認証器を拒否する
  counter       INTEGER NOT NULL DEFAULT 0 CHECK (counter >= 0),
  -- 対応する通信手段（"internal", "hybrid" など）の JSON 配列
  transports    TEXT    NOT NULL DEFAULT '[]' CHECK (json_valid(transports)),
  device_name   TEXT    NOT NULL,
  created_at    INTEGER NOT NULL,
  last_used_at  INTEGER
);
CREATE INDEX credentials_user_id ON credentials(user_id);

-- 設計書ではセッションの主キーを id としているが、CLAUDE.md の「セッション ID を平文で保存しない」に
-- 従い、Cookie に入れる生の ID（256bit 乱数, S7）の HMAC-SHA256（鍵は SESSION_SECRET）だけを保存する。
-- DB が漏れても、そこから有効な Cookie は作れない。
CREATE TABLE sessions (
  id_hash     BLOB    PRIMARY KEY,
  user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at  INTEGER NOT NULL,
  expires_at  INTEGER NOT NULL,
  ip          TEXT,
  user_agent  TEXT
);
CREATE INDEX sessions_user_id ON sessions(user_id);
CREATE INDEX sessions_expires_at ON sessions(expires_at);

-- S10: 再設定トークンもハッシュだけを保存する。使い切り（used_at）・短期（expires_at）
CREATE TABLE reset_tokens (
  token_hash  BLOB    PRIMARY KEY,
  user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at  INTEGER NOT NULL,
  used_at     INTEGER
);
CREATE INDEX reset_tokens_user_id ON reset_tokens(user_id);

-- S8 / S9: ログイン試行の記録。存在しないメールへの試行も数えるため、user_id か email のどちらかを持つ
CREATE TABLE login_attempts (
  id         INTEGER PRIMARY KEY,
  user_id    INTEGER REFERENCES users(id) ON DELETE CASCADE,
  email      TEXT,
  succeeded  INTEGER NOT NULL CHECK (succeeded IN (0, 1)),
  at         INTEGER NOT NULL,
  ip         TEXT,
  CHECK (user_id IS NOT NULL OR email IS NOT NULL)
);
CREATE INDEX login_attempts_user_id_at ON login_attempts(user_id, at);
CREATE INDEX login_attempts_email_at ON login_attempts(email, at);
CREATE INDEX login_attempts_ip_at ON login_attempts(ip, at);

-- S12: 監査ログ。ユーザーを削除しても記録は残すため、外部キーは SET NULL にする。
-- detail にパスワードやトークンの生値を入れないことはアプリ側とテストで担保する
CREATE TABLE audit_log (
  id       INTEGER PRIMARY KEY,
  user_id  INTEGER REFERENCES users(id) ON DELETE SET NULL,
  event    TEXT    NOT NULL,
  detail   TEXT    NOT NULL DEFAULT '{}' CHECK (json_valid(detail)),
  at       INTEGER NOT NULL,
  ip       TEXT
);
CREATE INDEX audit_log_user_id_at ON audit_log(user_id, at);
