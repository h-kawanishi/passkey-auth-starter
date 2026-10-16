// 画面の動き（素の JavaScript）。パスキーの呼び出しは @simplewebauthn/browser に任せる。
// UI フレームワークを使わないのは、認証の流れを「どの要求がいつ飛ぶか」のまま読めるようにするため（§2）。
// SimpleWebAuthnBrowser は /assets/simplewebauthn-browser.js が置く全体変数。
'use strict';

const { startRegistration, startAuthentication, browserSupportsWebAuthn, browserSupportsWebAuthnAutofill } =
  SimpleWebAuthnBrowser;

/** JSON を POST/PATCH/DELETE する。Cookie は同じオリジンなので自動で付く（SameSite=Lax） */
async function api(method, url, body) {
  const res = await fetch(url, {
    method,
    headers: body === undefined ? {} : { 'content-type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || '通信に失敗しました。');
  return data;
}

function showMessage(text) {
  const el = document.getElementById('message');
  if (el) el.textContent = text;
}

// 利用者が認証器のダイアログを閉じたときなどの例外。失敗ではないので静かに扱う
function isCancel(err) {
  return err && (err.name === 'NotAllowedError' || err.name === 'AbortError');
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
      if (!isCancel(err)) showMessage(err.message);
    });
  });

  // 条件付き UI: メール欄（autocomplete="username webauthn"）の自動入力候補にパスキーを並べる。
  // 利用者が候補を選ぶまで待ち続ける。ボタンが押されたらライブラリがこの待ちを取り消す。
  if (browserSupportsWebAuthnAutofill) {
    browserSupportsWebAuthnAutofill().then((ok) => {
      if (!ok) return;
      loginWithPasskey(true).catch((err) => {
        if (!isCancel(err)) showMessage(err.message);
      });
    });
  }
}

// ---------------------------------------------------------------- 新規登録画面

function initSignup() {
  document.getElementById('signup-form').addEventListener('submit', async (ev) => {
    ev.preventDefault();
    showMessage('');
    try {
      const email = document.getElementById('email').value;
      const optionsJSON = await api('POST', '/passkeys/register/options', { email });
      const response = await startRegistration({ optionsJSON });
      await api('POST', '/passkeys/register/verify', { response, deviceName: 'はじめのパスキー' });
      location.assign('/account');
    } catch (err) {
      showMessage(isCancel(err) ? '登録を取り消しました。' : err.message);
    }
  });
}

// ---------------------------------------------------------------- アカウント設定画面

function formatDate(ms) {
  return ms == null ? '—' : new Date(ms).toLocaleString('ja-JP');
}

async function renderPasskeys() {
  const data = await api('GET', '/passkeys');
  document.getElementById('account-email').textContent = data.email;
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
    showMessage(err.message);
  }
}

async function onDelete(pk) {
  if (!window.confirm(`「${pk.deviceName}」を削除しますか？`)) return;
  try {
    await api('DELETE', `/passkeys/${pk.id}`);
    await renderPasskeys();
  } catch (err) {
    showMessage(err.message);
  }
}

function initAccount() {
  renderPasskeys().catch((err) => showMessage(err.message));

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
      showMessage(isCancel(err) ? '追加を取り消しました。' : err.message);
    }
  });

  document.getElementById('logout').addEventListener('click', async () => {
    try {
      await api('POST', '/logout', {});
      location.assign('/login');
    } catch (err) {
      showMessage(err.message);
    }
  });
}

// ---------------------------------------------------------------- 入口

const page = document.body.dataset.page;
if (page && !browserSupportsWebAuthn()) {
  showMessage('このブラウザはパスキーに対応していません。');
}
if (page === 'login') initLogin();
if (page === 'signup') initSignup();
if (page === 'account') initAccount();
