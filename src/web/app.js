// 各画面で共通に使う、最小限のスクリプト。
// フォームを JSON で送り、結果の文言を画面に出す。失敗の理由（たとえば S3 の「漏えい一覧にある」）を
// ページを再読み込みせずに伝え、入力した内容を消さないようにするため。
// パスキーの呼び出し（C）はこのファイルか、別のファイルに足す。

/** 結果の文言を、フォームの中の role="alert" / role="status" の要素に出す */
function showMessage(form, text, isError) {
  const box = form.querySelector('[data-message]');
  if (!box) return;
  box.textContent = text;
  box.setAttribute('role', isError ? 'alert' : 'status');
}

async function submitJson(form) {
  const body = Object.fromEntries(new FormData(form));
  const res = await fetch(form.action, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
    // Cookie（セッション）は同じオリジンにだけ送る
    credentials: 'same-origin',
  });
  const data = await res.json().catch(() => ({}));
  if (res.ok && data.redirect) {
    location.assign(data.redirect);
    return;
  }
  showMessage(form, data.message || (res.ok ? '完了しました' : 'エラーが起きました'), !res.ok);
  if (res.ok) form.reset();
}

for (const form of document.querySelectorAll('form[data-json]')) {
  form.addEventListener('submit', (event) => {
    event.preventDefault();
    submitJson(form).catch(() => showMessage(form, '通信に失敗しました。もう一度お試しください', true));
  });
}

// アカウント設定画面: ログイン中のメールアドレスを表示する
const emailSlot = document.querySelector('[data-me-email]');
if (emailSlot) {
  fetch('/account/me', { credentials: 'same-origin' })
    .then((res) => (res.ok ? res.json() : Promise.reject(new Error(String(res.status)))))
    .then((me) => {
      emailSlot.textContent = me.email;
    })
    .catch(() => location.assign('/login'));
}
