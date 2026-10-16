// 画面の動き（素の JavaScript）。すべての画面がこの 1 ファイルを読む。
// UI フレームワークを使わないのは、認証の流れを「どの要求がいつ飛ぶか」のまま読めるようにするため（§2）。
// パスキーの呼び出しは @simplewebauthn/browser に任せる。SimpleWebAuthnBrowser は
// /assets/simplewebauthn-browser.js が置く全体変数。
'use strict';

const { startRegistration, startAuthentication, browserSupportsWebAuthn, browserSupportsWebAuthnAutofill } =
  SimpleWebAuthnBrowser;

// ---------------------------------------------------------------- 共通

/** JSON を送る。Cookie は同じオリジンなので自動で付く（SameSite=Lax）。失敗ならサーバーの文言で例外にする */
async function api(method, url, body) {
  const res = await fetch(url, {
    method,
    headers: body === undefined ? {} : { 'content-type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
    credentials: 'same-origin',
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const err = new Error(data.message || '通信に失敗しました。');
    // 画面が次の操作を選べるよう、サーバーが付けた理由（例: reauth_required）を残す
    err.reason = data.reason;
    throw err;
  }
  return data;
}

/**
 * 結果の文言を出す。form を渡すとそのフォームの中の [data-message] に、渡さなければ #message に出す。
 * エラーは role="alert" にして、画面読み上げソフトにもすぐ伝わるようにする。
 */
function showMessage(text, isError = false, form = undefined) {
  const box = form ? form.querySelector('[data-message]') : document.getElementById('message');
  if (!box) return;
  box.textContent = text;
  box.setAttribute('role', isError ? 'alert' : 'status');
}

// 利用者が認証器のダイアログを閉じたときなどの例外。失敗ではないので静かに扱う
function isCancel(err) {
  return err && (err.name === 'NotAllowedError' || err.name === 'AbortError');
}

/**
 * data-json の付いたフォームを JSON で送る（パスワードの登録・ログイン・変更、ログアウト、再設定）。
 * ページを再読み込みしないのは、失敗の理由（たとえば S3 の「漏えい一覧にある」）を、入力を消さずに伝えるため。
 */
async function submitJson(form) {
  const body = Object.fromEntries(new FormData(form));
  try {
    const data = await api('POST', form.getAttribute('action'), body);
    if (data.redirect) {
      location.assign(data.redirect);
      return;
    }
    showMessage(data.message || '完了しました', false, form);
    form.reset();
  } catch (err) {
    showMessage(err.message, true, form);
  }
}

for (const form of document.querySelectorAll('form[data-json]')) {
  form.addEventListener('submit', (event) => {
    event.preventDefault();
    submitJson(form);
  });
}

// ---------------------------------------------------------------- ログイン画面

async function loginWithPasskey(useBrowserAutofill) {
  const optionsJSON = await api('POST', '/passkeys/login/options', {});
  const response = await startAuthentication({ optionsJSON, useBrowserAutofill });
  await api('POST', '/passkeys/login/verify', { response });
  location.assign('/account');
}

function initLogin() {
  document.getElementById('passkey-login').addEventListener('click', () => {
    showMessage('');
    loginWithPasskey(false).catch((err) => {
      if (!isCancel(err)) showMessage(err.message, true);
    });
  });

  // 条件付き UI: メール欄（autocomplete="username webauthn"）の自動入力候補にパスキーを並べる。
  // 利用者が候補を選ぶまで待ち続ける。ボタンが押されたらライブラリがこの待ちを取り消す。
  if (browserSupportsWebAuthnAutofill) {
    browserSupportsWebAuthnAutofill().then((ok) => {
      if (!ok) return;
      loginWithPasskey(true).catch((err) => {
        if (!isCancel(err)) showMessage(err.message, true);
      });
    });
  }
}

// ---------------------------------------------------------------- 新規登録画面

function initSignup() {
  // パスワード欄の required に止められないよう、パスキーでの登録はフォーム送信ではなくボタンの click で始める
  document.getElementById('passkey-signup').addEventListener('click', async () => {
    showMessage('');
    try {
      const email = document.getElementById('email').value;
      const optionsJSON = await api('POST', '/passkeys/register/options', { email });
      const response = await startRegistration({ optionsJSON });
      await api('POST', '/passkeys/register/verify', { response, deviceName: 'はじめのパスキー' });
      location.assign('/account');
    } catch (err) {
      showMessage(isCancel(err) ? '登録を取り消しました。' : err.message, !isCancel(err));
    }
  });
}

// ---------------------------------------------------------------- アカウント設定画面

function formatDate(ms) {
  return ms == null ? '—' : new Date(ms).toLocaleString('ja-JP');
}

// 本人確認の欄で使う。パスワードを持たない人には、パスワードの入力欄を出さない
let accountHasPassword = false;

async function renderPasskeys() {
  const data = await api('GET', '/passkeys');
  accountHasPassword = data.hasPassword;
  document.getElementById('account-email').textContent = data.email;
  // パスキーのみのユーザーには「現在のパスワード」が無いので、変更フォームの代わりに案内を出す
  document.getElementById('password-section').hidden = !data.hasPassword;
  document.getElementById('no-password-section').hidden = data.hasPassword;
  const list = document.getElementById('passkey-list');
  list.replaceChildren();
  for (const pk of data.passkeys) {
    const li = document.createElement('li');
    li.dataset.id = String(pk.id);
    // textContent で入れる。利用者が付けた名前を innerHTML に入れると、名前に仕込んだスクリプトが動く（XSS）
    const name = document.createElement('strong');
    name.className = 'passkey-name';
    name.textContent = pk.deviceName;
    const meta = document.createElement('span');
    meta.textContent = ` 作成: ${formatDate(pk.createdAt)} / 最終利用: ${formatDate(pk.lastUsedAt)} `;
    const rename = document.createElement('button');
    rename.type = 'button';
    rename.textContent = '名前を変える';
    rename.addEventListener('click', () => onRename(pk));
    const del = document.createElement('button');
    del.type = 'button';
    del.textContent = '削除';
    del.addEventListener('click', () => onDelete(pk));
    li.append(name, meta, rename, del);
    list.append(li);
  }
}

async function onRename(pk) {
  const deviceName = window.prompt('新しい名前', pk.deviceName);
  if (deviceName == null) return;
  try {
    await api('PATCH', `/passkeys/${pk.id}`, { deviceName });
    await renderPasskeys();
  } catch (err) {
    showMessage(err.message, true);
  }
}

async function onDelete(pk) {
  if (!window.confirm(`「${pk.deviceName}」を削除しますか？`)) return;
  try {
    await api('DELETE', `/passkeys/${pk.id}`);
    await renderPasskeys();
  } catch (err) {
    showMessage(err.message, true);
  }
}

// ---- 本人確認（パスキーの追加の前。サーバーが reauth_required を返したときに開く）

function showReauthMessage(text, isError = false) {
  const box = document.getElementById('reauth-message');
  box.textContent = text;
  box.setAttribute('role', isError ? 'alert' : 'status');
}

function openReauth() {
  document.getElementById('reauth-section').hidden = false;
  document.getElementById('reauth-password-form').hidden = !accountHasPassword;
  // パスキーのみの人は必ずパスキーを持っている（最後の 1 本は消せない）。パスワードの人も、持っていれば使える
  document.getElementById('reauth-passkey-row').hidden = document.querySelectorAll('#passkey-list li').length === 0;
  showReauthMessage('');
}

/** 確認できたら欄を閉じ、もう一度「パスキーを追加」を押してもらう（認証器の操作は利用者の操作から始める） */
function reauthDone(data) {
  document.getElementById('reauth-section').hidden = true;
  showMessage(data.message);
}

function initReauth() {
  const form = document.getElementById('reauth-password-form');
  form.addEventListener('submit', async (ev) => {
    ev.preventDefault();
    try {
      const data = await api('POST', '/account/reauth', { password: document.getElementById('reauth-password').value });
      form.reset();
      reauthDone(data);
    } catch (err) {
      showReauthMessage(err.message, true);
    }
  });
  document.getElementById('reauth-passkey').addEventListener('click', async () => {
    try {
      const optionsJSON = await api('POST', '/passkeys/reauth/options', {});
      const response = await startAuthentication({ optionsJSON });
      reauthDone(await api('POST', '/passkeys/reauth/verify', { response }));
    } catch (err) {
      showReauthMessage(isCancel(err) ? '確認を取り消しました。' : err.message, !isCancel(err));
    }
  });
}

function initAccount() {
  renderPasskeys().catch(() => location.assign('/login'));
  initReauth();

  document.getElementById('add-passkey').addEventListener('submit', async (ev) => {
    ev.preventDefault();
    showMessage('');
    try {
      const deviceName = document.getElementById('device-name').value;
      const optionsJSON = await api('POST', '/passkeys/register/options', {});
      const response = await startRegistration({ optionsJSON });
      await api('POST', '/passkeys/register/verify', { response, deviceName });
      showMessage('パスキーを追加しました。');
      await renderPasskeys();
    } catch (err) {
      if (err.reason === 'reauth_required') openReauth();
      showMessage(isCancel(err) ? '追加を取り消しました。' : err.message, !isCancel(err));
    }
  });
}

// ---------------------------------------------------------------- 新しいパスワードの設定画面（再設定リンクの先）

function initResetNew() {
  // トークンは URL の # の後ろにある（サーバーへは送られない部分。auth/reset.ts の resetLink を参照）。
  // 読み取ったらアドレス欄と履歴から消す。画面を共有したり URL をコピーしたりしたときに漏れないように
  const token = new URLSearchParams(location.hash.slice(1)).get('token') || '';
  history.replaceState(null, '', location.pathname);
  document.getElementById('reset-token').value = token;
  if (token === '') {
    showMessage('リンクが正しくありません。メールのリンクをもう一度開いてください', true, document.querySelector('form'));
  }
}

// ---------------------------------------------------------------- 入口

const page = document.body.dataset.page;
if ((page === 'login' || page === 'signup' || page === 'account') && !browserSupportsWebAuthn()) {
  showMessage('このブラウザはパスキーに対応していません。パスワードをお使いください。');
}
if (page === 'login') initLogin();
if (page === 'signup') initSignup();
if (page === 'account') initAccount();
if (page === 'reset-new') initResetNew();
