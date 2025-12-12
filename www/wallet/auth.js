'use strict';

// AUTH (mainnet-grade):
// - AES-GCM + PBKDF2 (WebCrypto)
// - Ed25519 via tweetnacl (НЕ зависит от WebCrypto Ed25519)
// - хранение: IndexedDB, зашифрованный PKCS8 (RFC8410 prefix + seed32)
// - CSP-safe: без inline handlers и без element.style

const DB_NAME = 'logos_wallet_v2';
const STORE   = 'keys';
const enc     = new TextEncoder();
const ALPH    = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

const MN_WORDS = 16;
const MN_ALPH  = 'abcdefghjkmnpqrstuvwxyz';

const ED25519_PKCS8_PREFIX = new Uint8Array([
  0x30, 0x2e, 0x02, 0x01, 0x00,
  0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70,
  0x04, 0x22, 0x04, 0x20
]);

const $ = (s) => document.querySelector(s);
const out = (msg) => { const el = $('#out'); if (el) el.textContent = String(msg); };

function ensureEnv() {
  if (!window.isSecureContext) throw new Error('Нужен HTTPS (secure context)');
  if (!window.indexedDB) throw new Error('IndexedDB недоступен');
  if (!window.crypto || !window.crypto.subtle) throw new Error('WebCrypto недоступен');
  if (!window.nacl || !window.nacl.sign || !window.nacl.sign.keyPair || !window.nacl.sign.keyPair.fromSeed) {
    throw new Error('tweetnacl не загружен (нет window.nacl)');
  }
}

function normRid(s) { return (s || '').replace(/\s+/g, '').trim(); }
function normalizeMnemonic(s) { return (s || '').trim().toLowerCase().replace(/\s+/g, ' '); }

function b58encode(bytes) {
  const src = (bytes instanceof Uint8Array) ? bytes : new Uint8Array(bytes || []);
  if (src.length === 0) return '';
  const digits = [0];
  for (let i = 0; i < src.length; i++) {
    let carry = src[i];
    for (let j = 0; j < digits.length; j++) {
      carry += digits[j] << 8;
      digits[j] = carry % 58;
      carry = (carry / 58) | 0;
    }
    while (carry) {
      digits.push(carry % 58);
      carry = (carry / 58) | 0;
    }
  }
  let out = '';
  for (let k = 0; k < src.length && src[k] === 0; k++) out += ALPH[0];
  for (let q = digits.length - 1; q >= 0; q--) out += ALPH[digits[q]];
  return out;
}

function validateNewPassword(pass) {
  if (!pass || pass.length < 10) throw new Error('Пароль ≥10 символов');
  if (!/[A-Za-z]/.test(pass) || !/[0-9]/.test(pass)) throw new Error('Пароль должен содержать буквы и цифры');
  return pass;
}
function ensureLoginPassword(pass) {
  if (!pass || pass.length < 6) throw new Error('Пароль ≥6 символов');
  return pass;
}

async function sha256Bytes(str) {
  const digest = await crypto.subtle.digest('SHA-256', enc.encode(str));
  return new Uint8Array(digest);
}

function randomWord(len = 5) {
  const buf = new Uint8Array(len);
  crypto.getRandomValues(buf);
  let w = '';
  for (let i = 0; i < len; i++) w += MN_ALPH[buf[i] % MN_ALPH.length];
  return w;
}
function generateMnemonic() {
  const words = [];
  for (let i = 0; i < MN_WORDS; i++) words.push(randomWord());
  return words.join(' ');
}

async function mnemonicToSeed(mnemonic) {
  const norm = normalizeMnemonic(mnemonic);
  if (!norm) throw new Error('Резервная фраза пуста');
  return sha256Bytes('logos-lrb-ed25519:' + norm); // 32 bytes
}

function buildPkcs8FromSeed(seed32) {
  if (!(seed32 instanceof Uint8Array) || seed32.length !== 32) throw new Error('seed должен быть 32 байта');
  const out = new Uint8Array(ED25519_PKCS8_PREFIX.length + 32);
  out.set(ED25519_PKCS8_PREFIX, 0);
  out.set(seed32, ED25519_PKCS8_PREFIX.length);
  return out;
}

function extractSeedFromPkcs8(pkcs8) {
  const u = (pkcs8 instanceof Uint8Array) ? pkcs8 : new Uint8Array(pkcs8 || []);
  if (u.length !== ED25519_PKCS8_PREFIX.length + 32) throw new Error('Неверная длина PKCS8');
  for (let i = 0; i < ED25519_PKCS8_PREFIX.length; i++) {
    if (u[i] !== ED25519_PKCS8_PREFIX[i]) throw new Error('PKCS8 prefix mismatch');
  }
  return u.slice(ED25519_PKCS8_PREFIX.length);
}

async function deriveKey(pass, saltU8) {
  const keyMat = await crypto.subtle.importKey('raw', enc.encode(pass), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: saltU8, iterations: 120000, hash: 'SHA-256' },
    keyMat,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

async function aesEncrypt(aesKey, plainU8) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, plainU8));
  return { iv, ct };
}

async function aesDecrypt(aesKey, ivU8, ctU8) {
  const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: ivU8 }, aesKey, ctU8);
  return new Uint8Array(plain);
}

// ---------- IndexedDB ----------
let DBP = null;
function openDb() {
  if (DBP) return DBP;
  DBP = new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, 1);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(STORE)) db.createObjectStore(STORE);
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
  return DBP;
}

async function idbGet(key) {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, 'readonly');
    const st = tx.objectStore(STORE);
    const r = st.get(key);
    r.onsuccess = () => resolve(r.result || null);
    r.onerror = () => reject(r.error);
  });
}
async function idbSet(key, val) {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, 'readwrite');
    const st = tx.objectStore(STORE);
    const r = st.put(val, key);
    r.onsuccess = () => resolve();
    r.onerror = () => reject(r.error);
  });
}
async function idbDel(key) {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, 'readwrite');
    const st = tx.objectStore(STORE);
    const r = st.delete(key);
    r.onsuccess = () => resolve();
    r.onerror = () => reject(r.error);
  });
}

async function listAccounts() { return (await idbGet('accounts')) || []; }
async function addAccount(rid) {
  const list = (await idbGet('accounts')) || [];
  if (!list.includes(rid)) {
    list.push(rid);
    await idbSet('accounts', list);
  }
}

// Pending state
let pendingRid = null;
let pendingMnemonic = null;

async function createAccount(passRaw) {
  ensureEnv();
  const pass = validateNewPassword(passRaw);

  out('Создаём ключ и фразу…');

  const mnemonic = generateMnemonic();
  const seed = await mnemonicToSeed(mnemonic);
  const pkcs8 = buildPkcs8FromSeed(seed);

  const kp = nacl.sign.keyPair.fromSeed(seed);
  const pub = new Uint8Array(kp.publicKey);
  const rid = b58encode(pub);

  const salt = crypto.getRandomValues(new Uint8Array(16));
  const aes = await deriveKey(pass, salt);
  const { iv, ct } = await aesEncrypt(aes, pkcs8);

  const meta = {
    rid,
    pub: Array.from(pub),
    salt: Array.from(salt),
    iv: Array.from(iv),
    priv: Array.from(ct),
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
    sec.hidden = false;
    sec.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  out('RID создан: ' + rid + '. Запиши фразу и подтверди её.');
}

async function loginAccount(ridRaw, passRaw) {
  ensureEnv();
  const rid = normRid(ridRaw);
  const pass = ensureLoginPassword(passRaw);
  if (!rid) throw new Error('Укажи RID');

  const meta = await idbGet('acct:' + rid);
  if (!meta) {
    const list = await listAccounts();
    throw new Error('RID не найден на этом устройстве.\n' + (list.length ? list.join('\n') : '— пусто —'));
  }

  const aes = await deriveKey(pass, new Uint8Array(meta.salt || []));
  try {
    const pkcs8 = await aesDecrypt(aes, new Uint8Array(meta.iv || []), new Uint8Array(meta.priv || []));
    // проверим, что это действительно наш PKCS8 (совместимость/коррупция)
    extractSeedFromPkcs8(pkcs8);
  } catch (_) {
    throw new Error('Неверный пароль или повреждённый ключ');
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

  out('Восстанавливаем кошелёк…');

  const seed = await mnemonicToSeed(mnemonic);
  const pkcs8 = buildPkcs8FromSeed(seed);

  const kp = nacl.sign.keyPair.fromSeed(seed);
  const pub = new Uint8Array(kp.publicKey);
  const rid = b58encode(pub);

  const salt = crypto.getRandomValues(new Uint8Array(16));
  const aes = await deriveKey(pass, salt);
  const { iv, ct } = await aesEncrypt(aes, pkcs8);

  const meta = {
    rid,
    pub: Array.from(pub),
    salt: Array.from(salt),
    iv: Array.from(iv),
    priv: Array.from(ct),
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
  for (const rid of list) await idbDel('acct:' + rid);
  await idbDel('accounts');
  await idbDel('last_rid');
  sessionStorage.clear();
  pendingRid = null;
  pendingMnemonic = null;
  out('Все аккаунты удалены.');
}

function renderRidList(list) {
  const wrap = $('#listWrap');
  const ul = $('#ridList');
  if (!wrap || !ul) return;
  ul.innerHTML = '';
  wrap.hidden = false;

  if (!list.length) {
    const li = document.createElement('li');
    li.textContent = '— пусто —';
    ul.appendChild(li);
    return;
  }

  for (const rid of list) {
    const li = document.createElement('li');
    li.textContent = rid;
    li.addEventListener('click', () => {
      const inp = $('#loginRid');
      if (inp) inp.value = rid;
      out('RID подставлен');
    });
    ul.appendChild(li);
  }
}

// boot helpers
(async () => {
  try {
    // last_rid
    const last = await idbGet('last_rid');
    const loginRid = $('#loginRid');
    if (last && loginRid) loginRid.value = last;

    // DEV reset only on localhost
    const resetBtn = $('#btn-reset');
    if (resetBtn) {
      const isDevHost = (location.hostname === 'localhost' || location.hostname === '127.0.0.1');
      resetBtn.hidden = !isDevHost;
    }
  } catch (e) {
    console.error(e);
  }
})();

// UI wiring
$('#btn-login')?.addEventListener('click', async () => {
  try {
    await loginAccount($('#loginRid')?.value || '', $('#loginPass')?.value || '');
  } catch (e) {
    out('ERR: ' + (e && e.message ? e.message : e));
  }
});

$('#btn-create')?.addEventListener('click', async () => {
  try {
    await createAccount($('#createPass')?.value || '');
  } catch (e) {
    out('ERR: ' + (e && e.message ? e.message : e));
  }
});

$('#btn-list')?.addEventListener('click', async () => {
  try {
    renderRidList(await listAccounts());
  } catch (e) {
    out('ERR: ' + (e && e.message ? e.message : e));
  }
});

$('#btn-reset')?.addEventListener('click', async () => {
  const isDevHost = (location.hostname === 'localhost' || location.hostname === '127.0.0.1');
  if (!isDevHost) {
    out('ERR: reset доступен только на localhost (dev)');
    return;
  }
  try {
    await resetAll();
  } catch (e) {
    out('ERR: ' + (e && e.message ? e.message : e));
  }
});

$('#btn-mnemonic-ok')?.addEventListener('click', () => {
  if (!pendingRid || !pendingMnemonic) {
    out('Нет созданного кошелька для подтверждения');
    return;
  }
  const typed = normalizeMnemonic($('#mnemonicConfirm')?.value || '');
  if (!typed) { out('Повтори фразу для подтверждения'); return; }
  if (typed !== normalizeMnemonic(pendingMnemonic)) { out('Фразы не совпадают'); return; }
  out('Фраза подтверждена, вход…');
  location.href = './app.html';
});

$('#btn-restore')?.addEventListener('click', async () => {
  try {
    await restoreAccount($('#restoreMnemonic')?.value || '', $('#restorePass')?.value || '');
  } catch (e) {
    out('ERR: ' + (e && e.message ? e.message : e));
  }
});
