const admin = location.pathname === '/admin';
const role = admin ? 'admin' : 'client';
const sessionUrl = `/auth/session?role=${role}`;
const refreshUrl = `/auth/refresh?role=${role}`;
const ui = Object.fromEntries(
  ['heading', 'login', 'email', 'code', 'request-code', 'verify-code', 'signed-in', 'account',
    'message', 'logout', 'retry-session'].map(id => [id, document.getElementById(id)])
);
const updates = typeof BroadcastChannel === 'function' ? new BroadcastChannel('ceilings-auth') : null;
let challengeEmail = null;
let expiryTimer;
let pending = Promise.resolve();
let logoutPending = false;

ui.heading.textContent = admin ? 'Панель администратора' : 'Кабинет клиента';

function serialized(action) {
  const current = pending.then(() => navigator.locks
    ? navigator.locks.request('ceilings-auth', action) : action());
  pending = current.catch(() => {});
  return current;
}

async function request(path, body) {
  const options = {cache: 'no-store'};
  if (body !== undefined) {
    options.method = 'POST';
    options.headers = {'Content-Type': 'application/json'};
    options.body = JSON.stringify(body);
  }
  const response = await fetch(path, options);
  return {status: response.status, data: response.status === 204 ? {} : await response.json()};
}

function showMessage(message = '') {
  ui.message.textContent = message;
}

function showLogin(message) {
  clearTimeout(expiryTimer);
  ui['signed-in'].hidden = true;
  ui.logout.hidden = true;
  ui['retry-session'].hidden = true;
  ui.login.hidden = false;
  showMessage(message);
}

function showSessionError() {
  clearTimeout(expiryTimer);
  ui.login.hidden = true;
  ui['signed-in'].hidden = true;
  ui['retry-session'].hidden = false;
  showMessage('Не удалось проверить сеанс. Попробуйте ещё раз.');
}

async function checkSession() {
  if (logoutPending) return;
  const session = await request(sessionUrl);
  if (session.status === 401 && session.data.detail === 'refresh_available') {
    // This GET runs while holding the shared browser lock. Another tab may
    // already have replaced the cookies before this tab acquired it.
    const refreshed = await request(refreshUrl, {});
    if (refreshed.status === 200) return paintSession(await request(sessionUrl));
    return paintSession(refreshed);
  }
  paintSession(session);
}

function paintSession(session) {
  if (logoutPending) return;
  if (session.status === 200) {
    ui.account.textContent = session.data.email;
    ui['signed-in'].hidden = false;
    ui.logout.hidden = false;
    ui.login.hidden = true;
    ui['retry-session'].hidden = true;
    showMessage();
    clearTimeout(expiryTimer);
    expiryTimer = setTimeout(sync, Math.max(1000, session.data.expires_at * 1000 - Date.now() + 250));
  } else if (session.status === 403) {
    showLogin(admin ? 'Для панели требуется отдельный вход администратора.' : 'Войдите как клиент.');
  } else if (session.status === 401) {
    showLogin(session.data.detail === 'session_denied' ? 'Сеанс завершён. Запросите новый код.' : '');
  } else {
    showSessionError();
  }
}

function sync() {
  return serialized(checkSession).catch(() => { if (!logoutPending) showSessionError(); });
}

ui['request-code'].addEventListener('submit', async event => {
  event.preventDefault();
  const button = event.currentTarget.querySelector('button');
  button.disabled = true;
  try {
    const email = ui.email.value;
    const result = await request('/auth/code', {email, role});
    if (result.status === 429) {
      showMessage('Достигнут лимит запроса кодов. Повторите позже или введите действующий код.');
    } else if (result.status === 200) {
      challengeEmail = email;
      ui['verify-code'].hidden = false;
      ui.code.value = '';
      ui.code.focus();
      showMessage(result.data.publication_confirmed ? 'Если адрес подходит для этого входа, код придёт на почту.' :
        'Отправка не подтверждена. Если код придёт, его можно ввести здесь.');
    } else if (result.data.detail === 'unsupported_email_local_part') {
      showMessage('Используйте латинские буквы, цифры или допустимые знаки до @. Кириллический домен можно оставить.');
    } else {
      showMessage('Не удалось запросить код. Проверьте адрес или попробуйте позже.');
    }
  } catch {
    showMessage('Не удалось запросить код. Попробуйте ещё раз.');
  } finally {
    button.disabled = false;
  }
});

ui['verify-code'].addEventListener('submit', async event => {
  event.preventDefault();
  const button = event.currentTarget.querySelector('button');
  button.disabled = true;
  try {
    await serialized(async () => {
      const result = await request('/auth/verify', {email: challengeEmail, code: ui.code.value, role});
      if (result.status === 200) {
        ui.code.value = '';
        ui['verify-code'].hidden = true;
        challengeEmail = null;
        updates?.postMessage('session-changed');
        await checkSession();
      } else {
        showMessage(result.status === 401 ? 'Код неверен, истёк или уже использован.' : 'Не удалось подтвердить код.');
      }
    });
  } catch {
    showMessage('Не удалось подтвердить код. Попробуйте ещё раз.');
  } finally {
    button.disabled = false;
  }
});

ui.logout.addEventListener('click', async () => {
  logoutPending = true;
  ui.logout.disabled = true;
  try {
    await serialized(async () => {
      const result = await request('/auth/logout', {});
      if (result.status === 204) {
        ui['verify-code'].hidden = true;
        showLogin('Вы вышли из аккаунта.');
        updates?.postMessage('session-changed');
      } else {
        showMessage('Не удалось завершить сеанс. Попробуйте ещё раз.');
      }
    });
  } catch {
    showMessage('Не удалось завершить сеанс. Попробуйте ещё раз.');
  } finally {
    ui.logout.disabled = false;
    logoutPending = false;
  }
});

ui['retry-session'].addEventListener('click', sync);
if (updates) updates.onmessage = () => { if (!logoutPending) sync(); };
document.addEventListener('visibilitychange', () => { if (!document.hidden && !logoutPending) sync(); });
sync();
