// AUTH v4: RID + пароль + 16-словная фраза восстановления.
// Ключи только локально (IndexedDB + AES-GCM), приватник никогда не уходит в сеть.

const DB_NAME = 'logos_wallet_v2';
const STORE   = 'keys';
const enc     = new TextEncoder();
const ALPH    = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

const $ = s => document.querySelector(s);
const out = msg => { const el = $('#out'); if (el) el.textContent = String(msg); };

function normRid(s) { return (s || '').replace(/\s+/g, '').trim(); }

function ensureEnv() {
  if (!window.isSecureContext) throw new Error('Нужен HTTPS (secure context)');
  if (!window.indexedDB)      throw new Error('IndexedDB недоступен');
  if (!window.crypto || !window.crypto.subtle) throw new Error('WebCrypto недоступен');
}

// IndexedDB helpers
const idb = () => new Promise((res, rej) => {
  const r = indexedDB.open(DB_NAME, 1);
  r.onupgradeneeded = () => r.result.createObjectStore(STORE);
  r.onsuccess = () => res(r.result);
  r.onerror   = () => rej(r.error);
});
const idbGet = async k => {
  const db = await idb();
  return new Promise((res, rej) => {
    const t = db.transaction(STORE, 'readonly').objectStore(STORE).get(k);
    t.onsuccess = () => res(t.result || null);
    t.onerror   = () => rej(t.error);
  });
};
const idbSet = async (k, v) => {
  const db = await idb();
  return new Promise((res, rej) => {
    const t = db.transaction(STORE, 'readwrite').objectStore(STORE).put(v, k);
    t.onsuccess = () => res();
    t.onerror   = () => rej(t.error);
  });
};
const idbDel = async k => {
  const db = await idb();
  return new Promise((res, rej) => {
    const t = db.transaction(STORE, 'readwrite').objectStore(STORE).delete(k);
    t.onsuccess = () => res();
    t.onerror   = () => rej(t.error);
  });
};

// base58 для RID (как в ядре)
const b58 = bytes => {
  const h = [...new Uint8Array(bytes)].map(b => b.toString(16).padStart(2, '0')).join('');
  let x = BigInt('0x' + h), o = '';
  while (x > 0n) { o = ALPH[Number(x % 58n)] + o; x /= 58n; }
  return o || '1';
};

// Password helpers
function validateNewPassword(pass) {
  if (!pass || pass.length < 10) {
    throw new Error('Пароль ≥10 символов');
  }
  if (!/[A-Za-z]/.test(pass) || !/[0-9]/.test(pass)) {
    throw new Error('Пароль должен содержать буквы и цифры');
  }
  return pass;
}
function ensureLoginPassword(pass) {
  if (!pass || pass.length < 6) throw new Error('Пароль ≥6 символов');
  return pass;
}

// Crypto helpers
async function deriveKey(pass, salt) {
  const keyMat = await crypto.subtle.importKey(
    'raw',
    enc.encode(pass),
    'PBKDF2',
    false,
    ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 120000, hash: 'SHA-256' },
    keyMat,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}
async function aesEncrypt(aesKey, data) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(
    await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, data)
  );
  return { iv: Array.from(iv), ct: Array.from(ct) };
}
async function aesDecrypt(aesKey, iv, ct) {
  return new Uint8Array(
    await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: new Uint8Array(iv) },
      aesKey,
      new Uint8Array(ct)
    )
  );
}

// Accounts index
async function addAccount(rid) {
  const list = (await idbGet('accounts')) || [];
  if (!list.includes(rid)) {
    list.push(rid);
    await idbSet('accounts', list);
  }
}
async function listAccounts() {
  return (await idbGet('accounts')) || [];
}

// Mnemonic helpers (16 псевдо-слов, seed = SHA-256("logos-lrb-ed25519:"+phrase))
const MN_WORDS = 16;
const MN_ALPH  = 'abcdefghjkmnpqrstuvwxyz'; // без легко путаемых символов

function randomWord(len = 5) {
  const buf = new Uint8Array(len);
  crypto.getRandomValues(buf);
  let w = '';
  for (let i = 0; i < len; i++) {
    w += MN_ALPH[buf[i] % MN_ALPH.length];
  }
  return w;
}

function generateMnemonic() {
  const words = [];
  for (let i = 0; i < MN_WORDS; i++) words.push(randomWord());
  return words.join(' ');
}

function normalizeMnemonic(s) {
  return (s || '').trim().toLowerCase().replace(/\s+/g, ' ');
}

async function mnemonicToSeedBytes(mnemonic) {
  const norm = normalizeMnemonic(mnemonic);
  if (!norm) throw new Error('Резервная фраза пуста');
  const data = 'logos-lrb-ed25519:' + norm;
  const hash = await crypto.subtle.digest('SHA-256', enc.encode(data));
  return new Uint8Array(hash); // 32 байта
}

// PKCS8 Ed25519 (RFC 8410): 302e020100300506032b657004220420 || seed32
const ED25519_PKCS8_PREFIX = new Uint8Array([
  0x30, 0x2e, 0x02, 0x01, 0x00,
  0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70,
  0x04, 0x22, 0x04, 0x20
]);

function buildPkcs8FromSeed(seed) {
  if (!(seed instanceof Uint8Array) || seed.length !== 32) {
    throw new Error('seed должен быть 32 байта');
  }
  const outArr = new Uint8Array(ED25519_PKCS8_PREFIX.length + seed.length);
  outArr.set(ED25519_PKCS8_PREFIX, 0);
  outArr.set(seed, ED25519_PKCS8_PREFIX.length);
  return outArr;
}

function base64urlToBytes(str) {
  const pad = str.length % 4 === 2 ? '==' : str.length % 4 === 3 ? '=' : '';
  const b64 = str.replace(/-/g, '+').replace(/_/g, '/') + pad;
  const bin = atob(b64);
  const outArr = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) outArr[i] = bin.charCodeAt(i);
  return outArr;
}

// Pending state для подтверждения фразы
let pendingRid = null;
let pendingMnemonic = null;

async function createAccount(passRaw) {
  ensureEnv();
  const pass = validateNewPassword(passRaw);

  out('Создаём ключ и фразу…');

  // 1) фраза и seed
  const mnemonic = generateMnemonic();
  const seed = await mnemonicToSeedBytes(mnemonic);
  const pkcs8 = buildPkcs8FromSeed(seed);

  // 2) публичный ключ через JWK
  const privateKey = await crypto.subtle.importKey(
    'pkcs8',
    pkcs8,
    { name: 'Ed25519' },
    true,
    ['sign']
  );
  const jwk = await crypto.subtle.exportKey('jwk', privateKey);
  if (!jwk || !jwk.x) throw new Error('Не удалось извлечь публичный ключ');
  const pubBytes = base64urlToBytes(jwk.x);
  const rid = b58(pubBytes);

  // 3) шифруем приватник на пароль
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const aes = await deriveKey(pass, salt);
  const { iv, ct } = await aesEncrypt(aes, pkcs8);
  const meta = {
    rid,
    pub: Array.from(pubBytes),
    salt: Array.from(salt),
    iv,
    priv: ct
  };

  await idbSet('acct:' + rid, meta);
  await addAccount(rid);
  await idbSet('last_rid', rid);

  sessionStorage.setItem('logos_pass', pass);
  sessionStorage.setItem('logos_rid', rid);

  pendingRid = rid;
  pendingMnemonic = mnemonic;

  const sec = $('#mnemonicSection');
  const disp = $('#mnemonicShow');
  const confirm = $('#mnemonicConfirm');
  if (sec && disp && confirm) {
    disp.value = mnemonic;
    confirm.value = '';
    sec.style.display = 'block';
    sec.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  out('RID создан: ' + rid + '. Обязательно запиши фразу выше и подтверди её.');
}

async function loginAccount(ridRaw, passRaw) {
  ensureEnv();
  const rid = normRid(ridRaw);
  const pass = ensureLoginPassword(passRaw);

  if (!rid) throw new Error('Укажи RID');

  const meta = await idbGet('acct:' + rid);
  if (!meta) {
    const list = await listAccounts();
    throw new Error(
      'RID не найден на этом устройстве. Сохранённые RID:\n' +
      (list.length ? list.join('\n') : '—')
    );
  }
  const aes = await deriveKey(pass, new Uint8Array(meta.salt));
  try {
    await aesDecrypt(aes, meta.iv, meta.priv);
  } catch (e) {
    throw new Error('Неверный пароль');
  }

  sessionStorage.setItem('logos_pass', pass);
  sessionStorage.setItem('logos_rid', rid);
  await idbSet('last_rid', rid);
  out('Вход…');
  location.href = './app.html';
}

async function restoreAccount(mnemonicRaw, passRaw) {
  ensureEnv();
  const pass = validateNewPassword(passRaw);
  const mnemonic = normalizeMnemonic(mnemonicRaw);
  if (!mnemonic) throw new Error('Введи резервную фразу');

  out('Восстанавливаем кошелёк из фразы…');

  const seed = await mnemonicToSeedBytes(mnemonic);
  const pkcs8 = buildPkcs8FromSeed(seed);

  const privateKey = await crypto.subtle.importKey(
    'pkcs8',
    pkcs8,
    { name: 'Ed25519' },
    true,
    ['sign']
  );
  const jwk = await crypto.subtle.exportKey('jwk', privateKey);
  if (!jwk || !jwk.x) throw new Error('Не удалось извлечь публичный ключ');
  const pubBytes = base64urlToBytes(jwk.x);
  const rid = b58(pubBytes);

  const salt = crypto.getRandomValues(new Uint8Array(16));
  const aes = await deriveKey(pass, salt);
  const { iv, ct } = await aesEncrypt(aes, pkcs8);
  const meta = {
    rid,
    pub: Array.from(pubBytes),
    salt: Array.from(salt),
    iv,
    priv: ct
  };

  await idbSet('acct:' + rid, meta);
  await addAccount(rid);
  await idbSet('last_rid', rid);

  sessionStorage.setItem('logos_pass', pass);
  sessionStorage.setItem('logos_rid', rid);

  out('Кошелёк восстановлен: ' + rid + ' → вход…');
  location.href = './app.html';
}

async function resetAll() {
  const ok = confirm('Точно стереть все локальные аккаунты? Это нельзя отменить.');
  if (!ok) return;
  const list = await listAccounts();
  for (const rid of list) {
    await idbDel('acct:' + rid);
  }
  await idbDel('accounts');
  await idbDel('last_rid');
  sessionStorage.clear();
  out('Все аккаунты удалены.');
}

function renderRidList(list) {
  const wrap = $('#listWrap');
  const ul = $('#ridList');
  if (!wrap || !ul) return;
  ul.innerHTML = '';
  wrap.style.display = 'block';
  if (!list.length) {
    ul.innerHTML = '<li>— пусто —</li>';
    return;
  }
  list.forEach(rid => {
    const li = document.createElement('li');
    li.textContent = rid;
    li.addEventListener('click', () => {
      const inp = $('#loginRid');
      if (inp) inp.value = rid;
      out('RID подставлен');
    });
    ul.appendChild(li);
  });
}

// авто-подстановка last_rid и скрытие DEV-сброса в проде
(async () => {
  try {
    const last = await idbGet('last_rid');
    const loginRid = $('#loginRid');
    if (last && loginRid) loginRid.value = last;
  } catch (e) {
    console.error(e);
  }
  const resetBtn = $('#btn-reset');
  if (resetBtn) {
    const isDevHost = ['localhost', '127.0.0.1'].includes(location.hostname);
    if (!isDevHost) {
      resetBtn.style.display = 'none';
    }
  }
})();

// UI wiring
const btnLogin = $('#btn-login');
if (btnLogin) {
  btnLogin.addEventListener('click', async () => {
    const rid  = $('#loginRid')?.value || '';
    const pass = $('#loginPass')?.value || '';
    try {
      await loginAccount(rid, pass);
    } catch (e) {
      out('ERR: ' + (e && e.message ? e.message : e));
    }
  });
}

const btnCreate = $('#btn-create');
if (btnCreate) {
  btnCreate.addEventListener('click', async () => {
    const pass = $('#createPass')?.value || '';
    try {
      await createAccount(pass);
    } catch (e) {
      out('ERR: ' + (e && e.message ? e.message : e));
    }
  });
}

const btnList = $('#btn-list');
if (btnList) {
  btnList.addEventListener('click', async () => {
    try {
      renderRidList(await listAccounts());
    } catch (e) {
      out('ERR: ' + (e && e.message ? e.message : e));
    }
  });
}

const btnReset = $('#btn-reset');
if (btnReset) {
  btnReset.addEventListener('click', () => {
    const isDevHost = ['localhost', '127.0.0.1'].includes(location.hostname);
    if (!isDevHost) {
      alert('Сброс доступен только на dev-хосте (localhost).');
      return;
    }
    resetAll().catch(e => out('ERR: ' + e));
  });
}

const btnMnemonicOk = $('#btn-mnemonic-ok');
if (btnMnemonicOk) {
  btnMnemonicOk.addEventListener('click', () => {
    if (!pendingRid || !pendingMnemonic) {
      out('Нет созданного кошелька для подтверждения');
      return;
    }
    const confirmInput = $('#mnemonicConfirm');
    const typed = confirmInput ? normalizeMnemonic(confirmInput.value) : '';
    if (!typed) {
      out('Повтори фразу для подтверждения');
      return;
    }
    if (typed !== normalizeMnemonic(pendingMnemonic)) {
      out('Фразы не совпадают. Проверь, что записал всё без ошибок.');
      return;
    }
    out('Фраза подтверждена, вход…');
    location.href = './app.html';
  });
}

const btnRestore = $('#btn-restore');
if (btnRestore) {
  btnRestore.addEventListener('click', async () => {
    const phrase = $('#restoreMnemonic')?.value || '';
    const pass   = $('#restorePass')?.value   || '';
    try {
      await restoreAccount(phrase, pass);
    } catch (e) {
      out('ERR: ' + (e && e.message ? e.message : e));
    }
  });
}
