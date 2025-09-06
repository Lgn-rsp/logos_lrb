// APP: ключи в памяти; RID неизменен — берём из sessionStorage, meta из acct:<RID>
const API = location.origin + '/api';
const DB_NAME='logos_wallet_v2', STORE='keys', enc=new TextEncoder();
const ALPH="123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

const $=s=>document.querySelector(s);
const toHex=b=>[...new Uint8Array(b)].map(x=>x.toString(16).padStart(2,'0')).join('');
const fromHex=h=>new Uint8Array(h.match(/.{1,2}/g).map(x=>parseInt(x,16)));
const b58=bytes=>{const h=[...new Uint8Array(bytes)].map(b=>b.toString(16).padStart(2,'0')).join('');let x=BigInt('0x'+h),o='';while(x>0n){o=ALPH[Number(x%58n)]+o;x/=58n;}return o||'1';};

const idb=()=>new Promise((res,rej)=>{const r=indexedDB.open(DB_NAME,1);r.onupgradeneeded=()=>r.result.createObjectStore(STORE);r.onsuccess=()=>res(r.result);r.onerror=()=>rej(r.error);});
const idbGet=async k=>{const db=await idb();return new Promise((res,rej)=>{const t=db.transaction(STORE,'readonly').objectStore(STORE).get(k);t.onsuccess=()=>res(t.result||null);t.onerror=()=>rej(t.error);});};

async function deriveKey(pass,salt){const keyMat=await crypto.subtle.importKey('raw',new TextEncoder().encode(pass),'PBKDF2',false,['deriveKey']);return crypto.subtle.deriveKey({name:'PBKDF2',salt,iterations:120000,hash:'SHA-256'},keyMat,{name:'AES-GCM',length:256},false,['decrypt']);}
async function aesDecrypt(aesKey,iv,ct){return new Uint8Array(await crypto.subtle.decrypt({name:'AES-GCM',iv:new Uint8Array(iv)},aesKey,new Uint8Array(ct)))}
async function importKey(pass, meta){
  const aes=await deriveKey(pass,new Uint8Array(meta.salt));
  const pkcs8=await aesDecrypt(aes,meta.iv,meta.priv);
  const privateKey=await crypto.subtle.importKey('pkcs8',pkcs8,{name:'Ed25519'},true,['sign']);
  const publicKey =await crypto.subtle.importKey('raw',new Uint8Array(meta.pub),{name:'Ed25519'},true,['verify']);
  return {privateKey, publicKey};
}

// Session guard
const PASS=sessionStorage.getItem('logos_pass');
const RID =sessionStorage.getItem('logos_rid');
if(!PASS || !RID){ location.replace('./login.html'); throw new Error('locked'); }

let KEYS=null, META=null;

(async ()=>{
  META=await idbGet('acct:'+RID);
  if(!META){ sessionStorage.clear(); location.replace('./login.html'); return; }
  KEYS=await importKey(PASS,META);
  document.getElementById('pub').value=`RID: ${RID}\nPUB (hex): ${toHex(new Uint8Array(META.pub))}`;
  document.getElementById('rid-balance').value=RID;
})();

document.getElementById('btn-lock').addEventListener('click', ()=>{ sessionStorage.clear(); location.replace('./login.html'); });

// API helpers
async function getJSON(url, body){
  const r = await fetch(url, body ? {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)} : {});
  if(!r.ok){ throw new Error(`${r.status} ${await r.text()}`); }
  return r.json();
}
async function getNonce(rid){ const j=await getJSON(`${API}/balance/${rid}`); return j.nonce||0; }
async function canonHex(from,to,amount,nonce){
  const r=await fetch(`${API}/debug_canon`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({tx:{from,to,amount:Number(amount),nonce:Number(nonce)}})});
  if(!r.ok){ throw new Error(`/debug_canon ${r.status}`); }
  return (await r.json()).canon_hex;
}
async function submitBatch(txs){
  const r=await fetch(`${API}/submit_tx_batch`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({txs})});
  if(!r.ok){ throw new Error(`/submit_tx_batch ${r.status}`); }
  return r.json();
}
async function deposit(rid, amount, ext){
  const r=await fetch(`${API}/bridge/deposit`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({rid,amount:Number(amount),ext_txid:ext})});
  return {status:r.status, text:await r.text()};
}
async function signCanon(privateKey, canonHex){
  const msg=fromHex(canonHex);
  const sig=await crypto.subtle.sign('Ed25519', privateKey, msg);
  return [...new Uint8Array(sig)].map(b=>b.toString(16).padStart(2,'0')).join('');
}

// Buttons
document.getElementById('btn-nonce').addEventListener('click', async ()=>{
  try{ const n=await getNonce(RID); document.getElementById('nonce').value=String(n+1); }
  catch(e){ alert('ERR '+e); }
});

document.getElementById('btn-balance').addEventListener('click', async ()=>{
  try{ const rid=document.getElementById('rid-balance').value.trim(); const j=await getJSON(`${API}/balance/${rid}`); document.getElementById('out-balance').textContent=JSON.stringify(j,null,2); }
  catch(e){ document.getElementById('out-balance').textContent=String(e); }
});

document.getElementById('btn-send').addEventListener('click', async ()=>{
  const to=document.getElementById('to').value.trim();
  const amount=document.getElementById('amount').value;
  const nonce=document.getElementById('nonce').value;
  const out=document.getElementById('out-send');
  try{
    const ch = await canonHex(RID,to,amount,nonce);
    const sig= await signCanon(KEYS.privateKey,ch);
    const res= await submitBatch([{from:RID,to,amount:Number(amount),nonce:Number(nonce),sig_hex:sig}]);
    out.textContent=JSON.stringify(res,null,2);
  }catch(e){ out.textContent=String(e); }
});

document.getElementById('btn-deposit').addEventListener('click', async ()=>{
  const ext=document.getElementById('ext').value.trim()||'eth_txid_demo';
  const r=await deposit(RID,123,ext);
  document.getElementById('out-bridge').textContent=`HTTP ${r.status}\n${r.text}`;
});
