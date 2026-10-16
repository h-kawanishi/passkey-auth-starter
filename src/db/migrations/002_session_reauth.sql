-- 002_session_reauth: セッションごとに「最後に本人確認した時刻」を持つ。
-- パスキーの追加など、盗んだ Cookie だけでされると困る操作の前に、直近 5 分以内の本人確認
-- （ログイン・パスワード・既存のパスキー）を求めるため（threat-model.md §4）。
-- 001 は適用済みの環境があるので書き換えず、列の追加だけをここで行う。
-- NULL は「このセッションではまだ本人確認していない」（この列ができる前に発行されたセッション）。
ALTER TABLE sessions ADD COLUMN reauthenticated_at INTEGER;
