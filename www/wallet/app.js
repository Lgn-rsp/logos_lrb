'use strict';

// -------------------- CONFIG / GLOBALS --------------------

const API = location.origin.replace(/\/$/, '') + '/api';

const DB_NAME  = 'logos_wallet_v2';
const DB_STORE = 'keys';
const AUTOLOCK_MS = 15 * 60 * 1000; // 15 минут

const enc = new TextEncoder();

let RID  = sessionStorage.getItem('logos_rid') || '';
let PASS = sessionStorage.getItem('logos_pass') || '';

let META = null;
let KEYS = null; // { privateKey: CryptoKey }
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
  alert('Сессия кошелька завершена, войди ещё раз.');
  location.href = './index.html';
}

function ensureEnv() {
  if (!window.crypto || !window.crypto.subtle || !window.indexedDB) {
    alert('Браузер слишком старый, нужен WebCrypto и IndexedDB.');
    throw new Error('Unsupported browser');
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
    req.onerror = () => reject(req.error);
  });
}

async function idbGet(key) {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(DB_STORE, 'readonly');
    const st = tx.objectStore(DB_STORE);
    const req = st.get(key);
    req.onsuccess = () => resolve(req.result || null);
    req.onerror = () => reject(req.error);
  });
}

// -------------------- CRYPTO HELPERS --------------------

// PBKDF2(pass, salt) -> AES‑GCM key
async function deriveKey(pass, salt, iterations = 120_000) {
  const pw = await crypto.subtle.importKey(
    'raw',
    enc.encode(pass),
    'PBKDF2',
    false,
    ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: new Uint8Array(salt),
      iterations,
      hash: 'SHA-256'
    },
    pw,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

async function aesDecrypt(aesKey, iv, ct) {
  const plain = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: new Uint8Array(iv) },
    aesKey,
    new Uint8Array(ct)
  );
  return new Uint8Array(plain);
}

// hex
function toHex(arr) {
  return Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('');
}
function fromHex(str) {
  const clean = (str || '').trim();
  if (clean.length % 2 !== 0) throw new Error('bad hex length');
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.substr(i * 2, 2), 16);
  }
  return out;
}

// -------------------- REST HELPERS --------------------

async function getJSON(url, init = {}) {
  const resp = await fetch(url, {
    method: 'GET',
    credentials: 'same-origin',
    cache: 'no-store',
    ...init
  });
  if (!resp.ok) throw new Error(`${resp.url || url} ${resp.status}`);
  return resp.json();
}

async function postJSON(url, body) {
  const resp = await fetch(url, {
    method: 'POST',
    credentials: 'same-origin',
    cache: 'no-store',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  });
  if (!resp.ok) throw new Error(`${resp.url || url} ${resp.status}`);
  return resp.json();
}

async function getNonce(rid) {
  const j = await getJSON(`${API}/balance/${encodeURIComponent(rid)}`);
  if (!j || typeof j.nonce !== 'number') {
    throw new Error('не удалось получить nonce');
  }
  return j.nonce;
}

async function canonHex(from, to, amount, nonce) {
  const j = await postJSON(`${API}/debug_canon`, {
    tx: {
      from,
      to,
      amount: Number(amount),
      nonce: Number(nonce)
    }
  });
  if (!j || typeof j.canon_hex !== 'string') {
    throw new Error('сервер не вернул canon_hex');
  }
  return j.canon_hex;
}

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
    out.textContent = 'ERR: ' + e;
  }
}

async function refreshStake() {
  const out = $('#out-stake');
  if (!out) return;
  try {
    const j = await getStakeInfo(RID);
    out.textContent = JSON.stringify(j, null, 2);
  } catch (e) {
    out.textContent = 'ERR: ' + e;
  }
}

// автолок по таймеру
setInterval(() => {
  if (!PASS) return;
  if (Date.now() - lastActivity > AUTOLOCK_MS) {
    lockNow();
  }
}, 30_000);

// -------------------- BOOT --------------------

(async () => {
  try {
    ensureEnv();

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
      ['sign']
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

    const ep = $('#endpoint');
    if (ep) ep.textContent = API;

    // спрятать ручной nonce и кнопку "получить nonce"
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

// показать баланс
const btnBalance = $('#btn-balance');
if (btnBalance) {
  btnBalance.addEventListener('click', () => {
    bumpActivity();
    refreshBalance();
  });
}

// отправка платежа (nonce берём автоматически)
const btnSend = $('#btn-send');
if (btnSend) {
  btnSend.addEventListener('click', async () => {
    const out = $('#out-send');
    try {
      bumpActivity();

      const toInput = $('#to');
      const amountInput = $('#amount');
      if (!toInput || !amountInput) throw new Error('нет полей получателя/суммы');

      const to = toInput.value.trim();
      const amountStr = amountInput.value.trim();

      if (!to) throw new Error('введи RID получателя');
      const amount = Number(amountStr);
      if (!Number.isFinite(amount) || amount <= 0) {
        throw new Error('сумма должна быть > 0');
      }

      // 1) актуальный nonce с ноды
      const currentNonce = await getNonce(RID);
      const nonce = currentNonce + 1;

      // 2) канонический байтстрим + подпись
      const ch  = await canonHex(RID, to, amount, nonce);
      const sig = await signCanon(ch);

      // 3) отправляем батч (одна транзакция)
      const btnSend = $('#btn-send');
if (btnSend) btnSend.addEventListener('click', async () => {
  bumpActivity();
  if (!RID || !KEYS) {
    alert('Сначала войди / разблокируй кошелёк');
    return;
  }

  const to   = $('#rid-send')?.value.trim();
  const amtS = $('#amount')?.value || '';
  const out  = $('#out-send');

  try {
    if (!to) throw new Error('Нужен RID получателя');

    const amount = BigInt(amtS || '0');
    if (amount <= 0n) throw new Error('Сумма должна быть > 0');

    // --- АВТО‑NONCE ---
    const onChainNonce = await getNonce(RID);  // /balance/:rid → nonce
    const nonce        = BigInt(onChainNonce + 1); // следующий nonce

    // на всякий — подставим в инпут, но он будет скрыт
    const nonceInput = $('#nonce');
    if (nonceInput) nonceInput.value = nonce.toString();

    const canon = await canonHex({
      from:   RID,
      to,
      amount: amount.toString(),
      nonce:  nonce.toString(),
    });

    const sigHex = await signCanon(canon);
    const batch  = [{
      from:   RID,
      to,
      amount: amount.toString(),
      nonce:  nonce.toString(),
      sig_hex: sigHex,
    }];

    const res = await submitBatch(batch);
    if (out) out.textContent = JSON.stringify(res, null, 2);

    await refreshBalance();
  } catch (e) {
    console.error(e);
    if (out) out.textContent = 'ERR: ' + e;
  }
});

// -------- STAKING --------

// обновить статус стейкинга (если есть кнопка)
const btnStakeStatus = $('#btn-stake-status');
if (btnStakeStatus) {
  btnStakeStatus.addEventListener('click', () => {
    bumpActivity();
    refreshStake();
  });
}

const btnStakeDelegate = $('#btn-stake-delegate');
if (btnStakeDelegate) {
  btnStakeDelegate.addEventListener('click', async () => {
    const out = $('#out-stake-op');
    try {
      bumpActivity();
      const inp = $('#stake-delegate-amount');
      const val = Number((inp && inp.value) || '0');
      if (!Number.isFinite(val) || val <= 0) throw new Error('сумма должна быть > 0');
      const res = await stakeDelegate(val);
      if (out) out.textContent = JSON.stringify(res, null, 2);
      await refreshStake();
      await refreshBalance();
    } catch (e) {
      if (out) out.textContent = 'ERR: ' + e;
      else alert('ERR: ' + e);
    }
  });
});

const btnStakeUndel = $('#btn-stake-undelegate');
if (btnStakeUndel) {
  btnStakeUndel.addEventListener('click', async () => {
    const out = $('#out-stake-op');
    try {
      bumpActivity();
      const inp = $('#stake-undelegate-amount');
      const val = Number((inp && inp.value) || '0');
      if (!Number.isFinite(val) || val <= 0) throw new Error('сумма должна быть > 0');
      const res = await stakeUndelegate(val);
      if (out) out.textContent = JSON.stringify(res, null, 2);
      await refreshStake();
      await refreshBalance();
    } catch (e) {
      if (out) out.textContent = 'ERR: ' + e;
      else alert('ERR: ' + e);
    }
  });
});

const btnStakeClaim = $('#btn-stake-claim');
if (btnStakeClaim) {
  btnStakeClaim.addEventListener('click', async () => {
    const out = $('#out-stake-op');
    try {
      bumpActivity();
      const res = await stakeClaim();
      if (out) out.textContent = JSON.stringify(res, null, 2);
      await refreshStake();
      await refreshBalance();
    } catch (e) {
      if (out) out.textContent = 'ERR: ' + e;
      else alert('ERR: ' + e);
    }
  });
});

// ===== LOGOS PATCH: /debug_canon + авто‑nonce ===============================
(async function () {
  const API = (window.API || (location.origin.replace(/\/$/, '') + '/api'));
  const $   = (sel) => document.querySelector(sel);

  // Берём глобальный RID, который уже показывает кошелёк
  function getFromRid() {
    if (window.RID && typeof window.RID === 'string') return window.RID.trim();
    const ta = document.querySelector('textarea');
    if (ta && ta.value.includes('RID:')) {
      // в верхнем блоке RID: xxxx\nPUB (hex): yyyy
      const m = ta.value.match(/RID:\s*([A-Za-z0-9]+)/);
      if (m) return m[1];
    }
    return '';
  }

  async function fetchNonce(rid) {
    const resp = await fetch(`${API}/balance/${encodeURIComponent(rid)}`, {
      method: 'GET',
      credentials: 'same-origin',
      cache: 'no-store',
    });
    if (!resp.ok) throw new Error(`/balance ${resp.status}`);
    const j = await resp.json();
    return (j && typeof j.nonce === 'number') ? j.nonce : 0;
  }

  // Новый helper, который будем вызывать из старого кода
  async function logosDebugCanonPatched(txLike) {
    const from = (txLike.from || getFromRid() || '').trim();
    const to   = (txLike.to   || txLike.rid_to || '').trim();
    const amt  = Number(txLike.amount || txLike.lgn || 0);

    if (!from || !to || !Number.isFinite(amt)) {
      throw new Error('bad tx params (from/to/amount)');
    }

    const nonce = await fetchNonce(from);

    const body = {
      from,
      to,
      amount: amt,
      nonce,
    };

    const resp = await fetch(`${API}/debug_canon`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin',
      body: JSON.stringify(body),
    });

    if (!resp.ok) {
      throw new Error(`/debug_canon ${resp.status}`);
    }

    // если фронт ожидает какое‑то тело — отдаём как есть
    try {
      return await resp.json();
    } catch (_) {
      return { ok: true };
    }
  }

  // Подменяем глобальную функцию, если она есть,
  // либо вешаем нашу на window, а старый код может её вызвать.
  window.logosDebugCanon = logosDebugCanonPatched;
})();

// авто‑показ nonce в форме отправки (опционально)
(function () {
  const API = (window.API || (location.origin.replace(/\/$/, '') + '/api'));
  const $   = (sel) => document.querySelector(sel);

  async function fillNonceField() {
    const from = (window.RID || '').trim();
    const nonceInput = $('input[placeholder="Nonce"]') || $('input[name="nonce"]');
    if (!from || !nonceInput) return;

    try {
      const r = await fetch(`${API}/balance/${encodeURIComponent(from)}`);
      if (!r.ok) return;
      const j = await r.json();
      if (typeof j.nonce === 'number') {
        nonceInput.value = String(j.nonce);
        nonceInput.readOnly = true;
      }
    } catch (_) {}
  }

  window.addEventListener('load', fillNonceField);
})();

// ===== LOGOS PATCH: /debug_canon + авто‑nonce ===============================
(async function () {
  const API = (window.API || (location.origin.replace(/\/$/, '') + '/api'));
  const $   = (sel) => document.querySelector(sel);

  // Берём глобальный RID, который уже показывает кошелёк
  function getFromRid() {
    if (window.RID && typeof window.RID === 'string') return window.RID.trim();
    const ta = document.querySelector('textarea');
    if (ta && ta.value.includes('RID:')) {
      // в верхнем блоке RID: xxxx\nPUB (hex): yyyy
      const m = ta.value.match(/RID:\s*([A-Za-z0-9]+)/);
      if (m) return m[1];
    }
    return '';
  }

  async function fetchNonce(rid) {
    const resp = await fetch(`${API}/balance/${encodeURIComponent(rid)}`, {
      method: 'GET',
      credentials: 'same-origin',
      cache: 'no-store',
    });
    if (!resp.ok) throw new Error(`/balance ${resp.status}`);
    const j = await resp.json();
    return (j && typeof j.nonce === 'number') ? j.nonce : 0;
  }

  // Новый helper, который будем вызывать из старого кода
  async function logosDebugCanonPatched(txLike) {
    const from = (txLike.from || getFromRid() || '').trim();
    const to   = (txLike.to   || txLike.rid_to || '').trim();
    const amt  = Number(txLike.amount || txLike.lgn || 0);

    if (!from || !to || !Number.isFinite(amt)) {
      throw new Error('bad tx params (from/to/amount)');
    }

    const nonce = await fetchNonce(from);

    const body = {
      from,
      to,
      amount: amt,
      nonce,
    };

    const resp = await fetch(`${API}/debug_canon`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin',
      body: JSON.stringify(body),
    });

    if (!resp.ok) {
      throw new Error(`/debug_canon ${resp.status}`);
    }

    // если фронт ожидает какое‑то тело — отдаём как есть
    try {
      return await resp.json();
    } catch (_) {
      return { ok: true };
    }
  }

  // Подменяем глобальную функцию, если она есть,
  // либо вешаем нашу на window, а старый код может её вызвать.
  window.logosDebugCanon = logosDebugCanonPatched;
})();
