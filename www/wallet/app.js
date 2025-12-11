'use strict';

// -------------------- CONFIG / GLOBALS --------------------

// Базовый endpoint API. Для прод‑узла это https://<твой-домен>/api
// Для локальной ноды — origin + /api.
const API = (window.API_ENDPOINT || (location.origin.replace(/\/$/, '') + '/api'));

const DB_NAME  = 'logos_wallet_v2';
const DB_STORE = 'keys';
const AUTOLOCK_MS = 15 * 60 * 1000; // 15 минут бездействия → автолок

const enc = new TextEncoder();

let RID  = sessionStorage.getItem('logos_rid') || '';
let PASS = sessionStorage.getItem('logos_pass') || '';

let META = null;             // { rid, pub: number[], salt: number[], iv: number[], priv: number[] }
let KEYS = null;             // { privateKey: CryptoKey }
let lastActivity = Date.now();

// -------------------- DOM HELPERS --------------------

const $  = (sel) => document.querySelector(sel);
const $$ = (sel) => Array.from(document.querySelectorAll(sel));

function bumpActivity() {
  lastActivity = Date.now();
}

function lockNow() {
  try {
    PASS = '';
    KEYS = null;
    META = null;
    sessionStorage.removeItem('logos_pass');
    sessionStorage.removeItem('logos_rid');
  } catch (_) {}
  alert('Сессия кошелька завершена, войди снова.');
  try {
    location.href = './auth.html';
  } catch (_) {}
}

function ensureEnv() {
  if (!window.isSecureContext) {
    throw new Error('Нужен HTTPS (secure context)');
  }
  if (!window.crypto || !window.crypto.subtle) {
    throw new Error('Нужен современный браузер с WebCrypto');
  }
  if (!RID || !PASS) {
    throw new Error('Нет активной сессии (RID/PASS)');
  }
}

// -------------------- INDEXED DB --------------------

function openDb() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, 1);
    req.onupgradeneeded = (ev) => {
      const db = ev.target.result;
      if (!db.objectStoreNames.contains(DB_STORE)) {
        db.createObjectStore(DB_STORE);
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror   = () => reject(req.error);
  });
}

async function idbGet(key) {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(DB_STORE, 'readonly');
    const st = tx.objectStore(DB_STORE);
    const req = st.get(key);
    req.onsuccess = () => resolve(req.result || null);
    req.onerror   = () => reject(req.error);
  });
}

// -------------------- CRYPTO HELPERS --------------------

// PBKDF2(pass, salt) -> AES‑GCM key (совместимо с auth.js)
async function deriveKey(pass, saltArr) {
  const salt = saltArr instanceof Uint8Array ? saltArr : new Uint8Array(saltArr || []);
  const keyMat = await crypto.subtle.importKey(
    'raw',
    enc.encode(pass),
    'PBKDF2',
    false,
    ['deriveKey'],
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 120000, hash: 'SHA-256' },
    keyMat,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

async function aesDecrypt(aesKey, ivArr, ctArr) {
  const iv = ivArr instanceof Uint8Array ? ivArr : new Uint8Array(ivArr || []);
  const ct = ctArr instanceof Uint8Array ? ctArr : new Uint8Array(ctArr || []);
  const plain = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv },
    aesKey,
    ct,
  );
  return new Uint8Array(plain);
}

// hex helpers
function toHex(arr) {
  return Array.from(arr).map((b) => b.toString(16).padStart(2, '0')).join('');
}
function fromHex(hex) {
  const clean = (hex || '').trim();
  if (clean.length % 2 !== 0) {
    throw new Error('нечётная длина hex');
  }
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

// -------------------- HTTP HELPERS --------------------

async function getJSON(url) {
  const resp = await fetch(url, {
    method: 'GET',
    credentials: 'same-origin',
    cache: 'no-store',
  });
  if (!resp.ok) {
    throw new Error(`${url} ${resp.status}`);
  }
  return resp.json();
}

async function postJSON(url, body) {
  const resp = await fetch(url, {
    method: 'POST',
    credentials: 'same-origin',
    cache: 'no-store',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body ?? {}),
  });
  if (!resp.ok) {
    throw new Error(`${url} ${resp.status}`);
  }
  return resp.json();
}

// -------------------- NODE API WRAPPERS --------------------

// /balance/:rid → { balance, nonce }
async function getNonce(rid) {
  const j = await getJSON(`${API}/balance/${encodeURIComponent(rid)}`);
  if (!j || typeof j.nonce !== 'number') {
    throw new Error('не удалось получить nonce');
  }
  return j.nonce;
}

// /debug_canon: сервер сейчас ждёт ApiSubmitTx
// { from, to, amount, nonce, sig_hex } → { canon_hex, txid? }
async function canonHex(from, to, amount, nonce) {
  const body = {
    from,
    to,
    amount: Number(amount),
    nonce: Number(nonce),
    // сервер требует поле sig_hex, но для канонизации оно не нужно —
    // передаём пустую строку
    sig_hex: '',
  };
  const j = await postJSON(`${API}/debug_canon`, body);
  if (!j || typeof j.canon_hex !== 'string') {
    throw new Error('сервер не вернул canon_hex');
  }
  return j.canon_hex;
}

// /submit_tx_batch { txs: [ { from,to,amount,nonce,sig_hex } ] }
async function submitBatch(txs) {
  return postJSON(`${API}/submit_tx_batch`, { txs });
}

// staking API
async function getStakeInfo(rid) {
  return getJSON(`${API}/stake/my/${encodeURIComponent(rid)}`);
}
async function stakeDelegate(amount) {
  return postJSON(`${API}/stake/delegate`, { rid: RID, amount: Number(amount) });
}
async function stakeUndelegate(amount) {
  return postJSON(`${API}/stake/undelegate`, { rid: RID, amount: Number(amount) });
}
async function stakeClaim() {
  return postJSON(`${API}/stake/claim`, { rid: RID });
}

// bridge deposit (demo)
async function bridgeDeposit(rid, amount, ext) {
  return postJSON(`${API}/bridge/deposit`, {
    rid,
    amount: Number(amount),
    ext_txid: String(ext || ''),
  });
}

// Подпись Ed25519(canonHex)
async function signCanon(canonHexStr) {
  if (!KEYS || !KEYS.privateKey) throw new Error('ключи не загружены');
  const msg = fromHex(canonHexStr);
  const sig = await crypto.subtle.sign('Ed25519', KEYS.privateKey, msg);
  return toHex(new Uint8Array(sig));
}

// -------------------- UI HELPERS --------------------

async function refreshBalance() {
  const out = $('#out-balance');
  if (!out) return;
  try {
    const ridInput = $('#rid-balance');
    const rid = (ridInput && ridInput.value.trim()) || RID;
    const j = await getJSON(`${API}/balance/${encodeURIComponent(rid)}`);
    out.textContent = JSON.stringify(j, null, 2);
  } catch (e) {
    console.error(e);
    out.textContent = 'ERR: ' + e;
  }
}

async function refreshStake() {
  const out = $('#out-stake');
  if (!out) return;
  try {
    const info = await getStakeInfo(RID);
    out.textContent = JSON.stringify(info, null, 2);
  } catch (e) {
    console.error(e);
    out.textContent = 'ERR: ' + e;
  }
}

// -------------------- BOOT --------------------

(async () => {
  try {
    ensureEnv();

    const ep = $('#endpoint');
    if (ep) ep.textContent = API;

    // достаём зашифрованный приватник + мета
    META = await idbGet('acct:' + RID);
    if (!META) {
      throw new Error('локальная запись аккаунта не найдена');
    }

    const aes = await deriveKey(PASS, META.salt);
    const pkcs8 = await aesDecrypt(aes, META.iv, META.priv);

    const privateKey = await crypto.subtle.importKey(
      'pkcs8',
      pkcs8,
      { name: 'Ed25519' },
      false,
      ['sign'],
    );
    KEYS = { privateKey };

    // показать RID + PUB (hex)
    const pubBytes = new Uint8Array(META.pub || []);
    const pubArea = $('#pub');
    if (pubArea) {
      pubArea.value = `RID: ${RID}\nPUB (hex): ${toHex(pubBytes)}`;
    }

    const rb = $('#rid-balance');
    if (rb) rb.value = RID;

    const rb2 = $('#rid-bridge');
    if (rb2) rb2.value = RID;

    // спрятать ручной nonce и кнопку "Получить nonce"
    const nonceInput = $('#nonce');
    if (nonceInput && nonceInput.parentElement) {
      nonceInput.parentElement.style.display = 'none';
    }
    const btnNonce = $('#btn-nonce');
    if (btnNonce && btnNonce.parentElement) {
      btnNonce.parentElement.style.display = 'none';
    }

    bumpActivity();
    await refreshBalance();
    await refreshStake();
  } catch (e) {
    console.error('wallet boot error:', e);
    alert('Не удалось инициализировать кошелёк: ' + e);
    lockNow();
  }
})();

// -------------------- BUTTONS --------------------

// выход
const btnLock = $('#btn-lock');
if (btnLock) {
  btnLock.addEventListener('click', () => {
    bumpActivity();
    lockNow();
  });
}

// баланс
const btnBalance = $('#btn-balance');
if (btnBalance) {
  btnBalance.addEventListener('click', () => {
    bumpActivity();
    refreshBalance();
  });
}

// ручное обновление nonce (оставим для совместимости, но прячем в UI)
const btnNonce = $('#btn-nonce');
if (btnNonce) {
  btnNonce.addEventListener('click', async () => {
    bumpActivity();
    const out = $('#out-balance');
    try {
      const nonce = await getNonce(RID);
      const nonceInput = $('#nonce');
      if (nonceInput) {
        nonceInput.value = String(nonce);
      }
      if (out) out.textContent = `nonce = ${nonce}`;
    } catch (e) {
      console.error(e);
      if (out) out.textContent = 'ERR: ' + e;
    }
  });
}

// отправка платежа (nonce берём автоматически с ноды)
const btnSend = $('#btn-send');
if (btnSend) {
  btnSend.addEventListener('click', async () => {
    const out = $('#out-send');
    try {
      bumpActivity();

      if (!RID || !KEYS) {
        throw new Error('Сначала войди / разблокируй кошелёк');
      }

      const toInput = $('#to');
      const amountInput = $('#amount');
      if (!toInput || !amountInput) {
        throw new Error('нет полей получателя/суммы');
      }

      const to = toInput.value.trim();
      const amountStr = amountInput.value.trim();

      if (!to) throw new Error('введи RID получателя');
      const amount = Number(amountStr);
      if (!Number.isFinite(amount) || amount <= 0) {
        throw new Error('сумма должна быть > 0');
      }

      // 1) актуальный nonce с ноды (возвращает последний, берём +1)
      const currentNonce = await getNonce(RID);
      const nonce = currentNonce + 1;

      const nonceInput = $('#nonce');
      if (nonceInput) {
        nonceInput.value = String(nonce);
      }

      // 2) канонический hex
      const ch = await canonHex(RID, to, amount, nonce);

      // 3) подпись
      const sigHex = await signCanon(ch);

      // 4) отправляем батч (одна транзакция)
      const batch = [{
        from: RID,
        to,
        amount,
        nonce,
        sig_hex: sigHex,
      }];

      const res = await submitBatch(batch);

      if (out) {
        out.textContent = JSON.stringify(res, null, 2);
      }
      await refreshBalance();
    } catch (e) {
      console.error('send error', e);
      if (out) out.textContent = 'ERR: ' + e;
      else alert('ERR: ' + e);
    }
  });
}

// стейкинг

const btnStakeRefresh = $('#btn-stake-refresh');
if (btnStakeRefresh) {
  btnStakeRefresh.addEventListener('click', async () => {
    bumpActivity();
    await refreshStake();
  });
}

const btnStakeDelegate = $('#btn-stake-delegate');
if (btnStakeDelegate) {
  btnStakeDelegate.addEventListener('click', async () => {
    const out = $('#out-stake');
    try {
      bumpActivity();
      const inp = $('#stake-amount');
      const val = Number((inp && inp.value) || '0');
      if (!Number.isFinite(val) || val <= 0) throw new Error('сумма должна быть > 0');
      const res = await stakeDelegate(val);
      if (out) out.textContent = JSON.stringify(res, null, 2);
      await refreshStake();
      await refreshBalance();
    } catch (e) {
      console.error(e);
      if (out) out.textContent = 'ERR: ' + e;
    }
  });
}

const btnStakeUndel = $('#btn-stake-undelegate');
if (btnStakeUndel) {
  btnStakeUndel.addEventListener('click', async () => {
    const out = $('#out-stake');
    try {
      bumpActivity();
      const inp = $('#unstake-amount');
      const val = Number((inp && inp.value) || '0');
      if (!Number.isFinite(val) || val <= 0) throw new Error('сумма должна быть > 0');
      const res = await stakeUndelegate(val);
      if (out) out.textContent = JSON.stringify(res, null, 2);
      await refreshStake();
      await refreshBalance();
    } catch (e) {
      console.error(e);
      if (out) out.textContent = 'ERR: ' + e;
    }
  });
}

const btnStakeClaim = $('#btn-stake-claim');
if (btnStakeClaim) {
  btnStakeClaim.addEventListener('click', async () => {
    const out = $('#out-stake');
    try {
      bumpActivity();
      const res = await stakeClaim();
      if (out) out.textContent = JSON.stringify(res, null, 2);
      await refreshStake();
      await refreshBalance();
    } catch (e) {
      console.error(e);
      if (out) out.textContent = 'ERR: ' + e;
    }
  });
}

// мост deposit rLGN (demo)
const btnDeposit = $('#btn-deposit');
if (btnDeposit) {
  btnDeposit.addEventListener('click', async () => {
    const out = $('#out-bridge');
    try {
      bumpActivity();
      const rid = ($('#rid-bridge') && $('#rid-bridge').value || RID || '').trim();
      const amountStr = ($('#amount-bridge') && $('#amount-bridge').value) || '0';
      const ext = ($('#ext') && $('#ext').value) || '';

      if (!rid) throw new Error('RID пустой');
      const amount = Number(amountStr);
      if (!Number.isFinite(amount) || amount <= 0) {
        throw new Error('сумма должна быть > 0');
      }

      const res = await bridgeDeposit(rid, amount, ext);
      if (out) out.textContent = JSON.stringify(res, null, 2);
    } catch (e) {
      console.error(e);
      if (out) out.textContent = 'ERR: ' + e;
    }
  });
}

// -------------------- AUTOLOCK TIMER --------------------

setInterval(() => {
  const now = Date.now();
  if (now - lastActivity > AUTOLOCK_MS) {
    console.log('autolock by inactivity');
    lockNow();
  }
}, 30_000);
