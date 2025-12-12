'use strict';

const API = (window.API_ENDPOINT || (location.origin.replace(/\/$/, '') + '/api'));

const DB_NAME  = 'logos_wallet_v2';
const STORE    = 'keys';
const AUTOLOCK_MS = 15 * 60 * 1000;

const enc = new TextEncoder();

const ED25519_PKCS8_PREFIX = new Uint8Array([
  0x30, 0x2e, 0x02, 0x01, 0x00,
  0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70,
  0x04, 0x22, 0x04, 0x20
]);

const $ = (s) => document.querySelector(s);

let RID  = sessionStorage.getItem('logos_rid') || '';
let PASS = sessionStorage.getItem('logos_pass') || '';

let META = null;
let SEED = null;           // Uint8Array(32)
let KP   = null;           // nacl keypair
let lastActivity = Date.now();

function bump() { lastActivity = Date.now(); }

function lockNow() {
  try {
    PASS = '';
    RID = '';
    META = null;
    SEED = null;
    KP = null;
    sessionStorage.removeItem('logos_pass');
    sessionStorage.removeItem('logos_rid');
  } catch (_) {}
  location.href = './auth.html';
}

function ensureEnv() {
  if (!window.isSecureContext) throw new Error('Нужен HTTPS (secure context)');
  if (!window.crypto || !window.crypto.subtle) throw new Error('WebCrypto недоступен');
  if (!window.indexedDB) throw new Error('IndexedDB недоступен');
  if (!window.nacl || !window.nacl.sign || !window.nacl.sign.keyPair || !window.nacl.sign.keyPair.fromSeed) {
    throw new Error('tweetnacl не загружен (нет window.nacl)');
  }
}

function toHex(u8) {
  const a = (u8 instanceof Uint8Array) ? u8 : new Uint8Array(u8 || []);
  let s = '';
  for (let i = 0; i < a.length; i++) s += a[i].toString(16).padStart(2, '0');
  return s;
}
function fromHex(hex) {
  const clean = (hex || '').trim();
  if (clean.length % 2 !== 0) throw new Error('нечётная длина hex');
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.slice(i*2, i*2+2), 16);
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

// IndexedDB
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

async function deriveKey(pass, saltArr) {
  const salt = (saltArr instanceof Uint8Array) ? saltArr : new Uint8Array(saltArr || []);
  const keyMat = await crypto.subtle.importKey('raw', enc.encode(pass), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 120000, hash: 'SHA-256' },
    keyMat,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt']
  );
}
async function aesDecrypt(aesKey, ivArr, ctArr) {
  const iv = (ivArr instanceof Uint8Array) ? ivArr : new Uint8Array(ivArr || []);
  const ct = (ctArr instanceof Uint8Array) ? ctArr : new Uint8Array(ctArr || []);
  const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, aesKey, ct);
  return new Uint8Array(plain);
}

// HTTP
async function getJSON(url) {
  const r = await fetch(url, { method:'GET', cache:'no-store', credentials:'same-origin' });
  if (!r.ok) throw new Error(`${url} ${r.status}`);
  return r.json();
}
async function postJSON(url, body) {
  const r = await fetch(url, {
    method:'POST', cache:'no-store', credentials:'same-origin',
    headers:{'Content-Type':'application/json'},
    body: JSON.stringify(body ?? {})
  });
  if (!r.ok) throw new Error(`${url} ${r.status}`);
  return r.json();
}

async function getBalance(rid) {
  return getJSON(`${API}/balance/${encodeURIComponent(rid)}`);
}
async function getNonce(rid) {
  const j = await getBalance(rid);
  if (!j || typeof j.nonce !== 'number') throw new Error('не удалось получить nonce');
  return j.nonce;
}

// msg = from | '|' | to | '|' | amount(8 BE) | '|' | nonce(8 BE)
function canonBytes(from, to, amount, nonce) {
  const fromB = enc.encode(from);
  const toB   = enc.encode(to);

  const ab = new ArrayBuffer(8);
  const av = new DataView(ab);
  av.setBigUint64(0, BigInt(amount), false);

  const nb = new ArrayBuffer(8);
  const nv = new DataView(nb);
  nv.setBigUint64(0, BigInt(nonce), false);

  const sep = new Uint8Array([ '|'.charCodeAt(0) ]);

  const parts = [fromB, sep, toB, sep, new Uint8Array(ab), sep, new Uint8Array(nb)];
  const total = parts.reduce((s,a)=>s+a.length,0);
  const out = new Uint8Array(total);
  let off=0;
  for (const p of parts) { out.set(p, off); off += p.length; }
  return out;
}

async function sha256(u8) {
  const d = await crypto.subtle.digest('SHA-256', u8);
  return new Uint8Array(d);
}

async function signHash32(hash32) {
  if (!KP) throw new Error('ключ не загружен');
  const sig = nacl.sign.detached(hash32, KP.secretKey);
  return toHex(new Uint8Array(sig));
}

async function refreshBalanceUI() {
  const out = $('#out-balance');
  try {
    const rid = ($('#rid-balance')?.value || RID || '').trim();
    const j = await getBalance(rid);
    if (out) out.textContent = JSON.stringify(j, null, 2);
    const nonce = (typeof j.nonce === 'number') ? (j.nonce + 1) : '';
    const nonceInp = $('#nonce');
    if (nonceInp) nonceInp.value = String(nonce);
  } catch (e) {
    if (out) out.textContent = 'ERR: ' + (e && e.message ? e.message : e);
  }
}

async function refreshStakeUI() {
  const out = $('#out-stake');
  try {
    const j = await getJSON(`${API}/stake/my/${encodeURIComponent(RID)}`);
    if (out) out.textContent = JSON.stringify(j, null, 2);
  } catch (e) {
    if (out) out.textContent = 'ERR: ' + (e && e.message ? e.message : e);
  }
}

async function submitBatch(txs) {
  return postJSON(`${API}/submit_tx_batch`, { txs });
}

(async () => {
  try {
    ensureEnv();

    if (!RID || !PASS) { lockNow(); return; }

    const ep = $('#endpoint');
    if (ep) ep.textContent = API;

    META = await idbGet('acct:' + RID);
    if (!META) { lockNow(); return; }

    const aes = await deriveKey(PASS, META.salt || []);
    const pkcs8 = await aesDecrypt(aes, META.iv || [], META.priv || []);
    SEED = extractSeedFromPkcs8(pkcs8);

    KP = nacl.sign.keyPair.fromSeed(SEED);

    const pubHex = toHex(new Uint8Array(KP.publicKey));
    const pubArea = $('#pub');
    if (pubArea) pubArea.value = `RID (base58): ${RID}\nPUB (hex): ${pubHex}`;

    const rb = $('#rid-balance');
    if (rb) rb.value = RID;

    const rbridge = $('#rid-bridge');
    if (rbridge) rbridge.value = RID;

    bump();
    await refreshBalanceUI();
    await refreshStakeUI();

  } catch (e) {
    console.error('wallet boot error:', e);
    const st = $('#out-status');
    if (st) st.textContent = 'ERR: ' + (e && e.message ? e.message : e);
    lockNow();
  }
})();

// глобальная активность (чтобы автолок не срабатывал “во время работы”)
['click','keydown','mousemove','touchstart'].forEach(ev=>{
  window.addEventListener(ev, ()=>bump(), { passive:true });
});

$('#btn-lock')?.addEventListener('click', () => lockNow());

$('#btn-balance')?.addEventListener('click', async () => {
  bump();
  await refreshBalanceUI();
});

$('#btn-nonce')?.addEventListener('click', async () => {
  bump();
  await refreshBalanceUI();
});

$('#btn-send')?.addEventListener('click', async () => {
  const out = $('#out-send');
  try {
    bump();
    const to = ($('#to')?.value || '').trim();
    const amount = Number(($('#amount')?.value || '').trim());
    if (!to) throw new Error('введи RID получателя');
    if (!Number.isFinite(amount) || amount <= 0) throw new Error('сумма должна быть > 0');

    const currentNonce = await getNonce(RID);
    const nonce = currentNonce + 1;
    if ($('#nonce')) $('#nonce').value = String(nonce);

    const msg = canonBytes(RID, to, amount, nonce);
    const h32 = await sha256(msg);
    const sig_hex = await signHash32(h32);

    const res = await submitBatch([{
      from: RID,
      to,
      amount,
      nonce,
      sig_hex
    }]);

    if (out) out.textContent = JSON.stringify(res, null, 2);
    await refreshBalanceUI();
  } catch (e) {
    console.error(e);
    if (out) out.textContent = 'ERR: ' + (e && e.message ? e.message : e);
  }
});

// staking
$('#btn-stake-refresh')?.addEventListener('click', async () => { bump(); await refreshStakeUI(); });
$('#btn-stake-delegate')?.addEventListener('click', async () => {
  const out = $('#out-stake');
  try {
    bump();
    const val = Number(($('#stake-amount')?.value || '0'));
    if (!Number.isFinite(val) || val <= 0) throw new Error('сумма должна быть > 0');
    const res = await postJSON(`${API}/stake/delegate`, { rid: RID, amount: val });
    if (out) out.textContent = JSON.stringify(res, null, 2);
    await refreshStakeUI();
    await refreshBalanceUI();
  } catch (e) {
    if (out) out.textContent = 'ERR: ' + (e && e.message ? e.message : e);
  }
});
$('#btn-stake-undelegate')?.addEventListener('click', async () => {
  const out = $('#out-stake');
  try {
    bump();
    const val = Number(($('#unstake-amount')?.value || '0'));
    if (!Number.isFinite(val) || val <= 0) throw new Error('сумма должна быть > 0');
    const res = await postJSON(`${API}/stake/undelegate`, { rid: RID, amount: val });
    if (out) out.textContent = JSON.stringify(res, null, 2);
    await refreshStakeUI();
    await refreshBalanceUI();
  } catch (e) {
    if (out) out.textContent = 'ERR: ' + (e && e.message ? e.message : e);
  }
});
$('#btn-stake-claim')?.addEventListener('click', async () => {
  const out = $('#out-stake');
  try {
    bump();
    const res = await postJSON(`${API}/stake/claim`, { rid: RID });
    if (out) out.textContent = JSON.stringify(res, null, 2);
    await refreshStakeUI();
    await refreshBalanceUI();
  } catch (e) {
    if (out) out.textContent = 'ERR: ' + (e && e.message ? e.message : e);
  }
});

// bridge
$('#btn-deposit')?.addEventListener('click', async () => {
  const out = $('#out-bridge');
  try {
    bump();
    const rid = ( ($('#rid-bridge')?.value || RID || '').trim() );
    const amount = Number(($('#amount-bridge')?.value || '0'));
    const ext = String($('#ext')?.value || '');
    if (!rid) throw new Error('RID пустой');
    if (!Number.isFinite(amount) || amount <= 0) throw new Error('сумма должна быть > 0');
    const res = await postJSON(`${API}/bridge/deposit`, { rid, amount, ext_txid: ext });
    if (out) out.textContent = JSON.stringify(res, null, 2);
  } catch (e) {
    if (out) out.textContent = 'ERR: ' + (e && e.message ? e.message : e);
  }
});

// autolock
setInterval(() => {
  const now = Date.now();
  if (now - lastActivity > AUTOLOCK_MS) lockNow();
}, 30_000);
