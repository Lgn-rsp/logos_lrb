// LOGOS Wallet — secure MVP с тёмной темой, статусами и историей с пагинацией
const API = location.origin.replace(/\/$/, "") + "/api";
const $ = (id)=>document.getElementById(id);
let HIST_CURSOR = null;

// ====== Тема (переключатель) ======
(function initTheme(){
  const saved = localStorage.getItem("logos.theme"); // 'light' | 'dark' | 'auto'
  if(saved){ document.documentElement.setAttribute("data-theme", saved); }
  $("themeToggle").onclick = ()=>{
    const cur = document.documentElement.getAttribute("data-theme") || "auto";
    const next = cur === "dark" ? "light" : "dark";
    document.documentElement.setAttribute("data-theme", next);
    localStorage.setItem("logos.theme", next);
  };
})();

// ====== UI helpers ======
const statusBar = $("statusBar");
function status(msg){ statusBar.textContent = msg; }
function busy(btn, v){
  if(!btn) return;
  btn.disabled = v;
}

// endpoint label
(function updateApiBase(){
  $("apiBase").textContent = API;
})();

// ====== b58 ======
const ALPH = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
function b58encode(bytes){ let n=0n; for(const b of bytes) n=(n<<8n)+BigInt(b);
  let s=""; while(n>0n){const r=n%58n; s=ALPH[Number(r)]+s; n/=58n;} let z=0; for(const b of bytes){if(b===0)z++;else break;} return "1".repeat(z)+(s||"1"); }

// ====== IndexedDB ======
const DB="logos_wallet", STORE="keys";
function idbOpen(){return new Promise((res,rej)=>{const r=indexedDB.open(DB,1); r.onupgradeneeded=()=>{const db=r.result; if(!db.objectStoreNames.contains(STORE)) db.createObjectStore(STORE);}; r.onsuccess=()=>res(r.result); r.onerror=()=>rej(r.error);});}
async function idbPut(k,v){const db=await idbOpen(); return new Promise((res,rej)=>{const tx=db.transaction(STORE,"readwrite"); tx.objectStore(STORE).put(v,k); tx.oncomplete=()=>res(); tx.onerror=()=>rej(tx.error);});}
async function idbGet(k){const db=await idbOpen(); return new Promise((res,rej)=>{const tx=db.transaction(STORE,"readonly"); const rq=tx.objectStore(STORE).get(k); rq.onsuccess=()=>res(rq.result||null); rq.onerror=()=>rej(rq.error);});}

// ====== Keys ======
async function showRID(vk){ const raw=new Uint8Array(await crypto.subtle.exportKey("raw",vk)); const rid=b58encode(raw); $("rid").textContent=rid; return rid; }
async function generateKey(){ const kp=await crypto.subtle.generateKey({name:"Ed25519"},true,["sign","verify"]); await idbPut("sk",kp.privateKey); await idbPut("vk",kp.publicKey); await showRID(kp.publicKey); return kp; }
async function loadKey(){ const sk=await idbGet("sk"); const vk=await idbGet("vk"); if(!sk||!vk) throw new Error("Нет ключа: нажмите «Сгенерировать ключ»"); await showRID(vk); return {sk,vk}; }

// ====== API helpers ======
async function apiGET(p){ const r=await fetch(API+p); const ct=r.headers.get("content-type")||""; const payload=ct.includes("json")?await r.json().catch(()=>null):await r.text().catch(()=>null); if(!r.ok){ const e=new Error(`GET ${r.status}`); e.payload=payload; throw e;} return payload; }
async function apiPOST(p,b){ const r=await fetch(API+p,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(b)}); const ct=r.headers.get("content-type")||""; const payload=ct.includes("json")?await r.json().catch(()=>null):await r.text().catch(()=>null); if(!r.ok){ const e=new Error(`POST ${r.status}`); e.payload=payload; throw e;} return payload; }
async function txCanon(tx){ const r=await apiPOST("/debug_canon",{tx}); return r.canon_hex; }
async function signHex(sk,hex){ const bytes=new Uint8Array(hex.match(/../g).map(h=>parseInt(h,16))); const sig=await crypto.subtle.sign({name:"Ed25519"},sk,bytes); return Array.from(new Uint8Array(sig)).map(b=>b.toString(16).padStart(2,"0")).join(""); }

// ====== State ======
async function refreshState(rid){ const st=await apiGET("/balance/"+encodeURIComponent(rid)); $("balance").textContent=st.balance; $("nonce").textContent=st.nonce; return st; }

// ====== History (with cursor) ======
function renderHistory(items, append=false){
  const box = $("histList");
  if(!append) box.textContent = "";
  if(!items || !items.length){
    if(!append && box.textContent==="") box.textContent="(пусто)";
    return;
  }
  const lines = items.map(it => `#${String(it.nonce).padStart(3," ")}  ${it.from.slice(0,6)}… → ${it.to.slice(0,6)}…   ${it.amount}  (h=${it.height}, ts=${it.ts_ms})`);
  box.textContent = append ? (box.textContent + (box.textContent?"\n":"") + lines.join("\n")) : lines.join("\n");
}

async function loadHistory(append=false){
  try{
    const rid = $("histRid").value.trim() || $("rid").textContent.trim();
    let from = append ? (HIST_CURSOR ?? 0) : ($("histFrom").value.trim() || "0");
    let limit = $("histLimit") ? $("histLimit").value.trim() : "20";
    status(append ? "Догружаю историю…" : "Загружаю историю…");
    busy($("loadHist"), true); busy($("moreHist"), true);
    const r = await apiGET(`/history/${encodeURIComponent(rid)}?from=${from}&limit=${limit}`);
    HIST_CURSOR = r.next_from ?? null;
    renderHistory(r.items || [], append);
    status(HIST_CURSOR ? `Готово. next_from=${HIST_CURSOR}` : "Готово (конец)");
  }catch(e){
    const payload = e.payload ? JSON.stringify(e.payload).slice(0,200) : "";
    $("histList").textContent = "";
    status(`Ошибка истории: ${e.message} ${payload}`);
  } finally {
    busy($("loadHist"), false); busy($("moreHist"), false);
  }
}

// ====== UI wiring ======
$("gen").onclick = async()=>{ try{ busy($("gen"),true); await generateKey(); status("Ключ сгенерирован"); }catch(e){ alert(e.message);} finally{busy($("gen"),false);} };
$("load").onclick = async()=>{ try{ busy($("load"),true); await loadKey(); status("Ключ загружен"); }catch(e){ alert(e.message);} finally{busy($("load"),false);} };
$("copyRid").onclick = async()=>{ try{ const rid=$("rid").textContent.trim(); await navigator.clipboard.writeText(rid); status("RID скопирован"); }catch(e){ alert("Clipboard error"); } };

$("getState").onclick = async()=>{ try{
  busy($("getState"),true);
  const rid = $("acctRid").value.trim() || $("rid").textContent.trim();
  await refreshState(rid); status("Состояние обновлено");
} catch(e){ alert("State error: "+e.message);} finally{busy($("getState"),false);} };

$("devFaucet").onclick = async()=>{ try{
  busy($("devFaucet"),true);
  const {vk}=await loadKey(); const rid=await showRID(vk);
  await apiPOST("/faucet",{rid,amount:1_000_000});
  await refreshState(rid); HIST_CURSOR=null; $("histFrom").value="0"; await loadHistory(false);
  status("Faucet OK");
} catch(e){ alert("Faucet error: "+e.message);} finally{busy($("devFaucet"),false);} };

$("send").onclick = async()=>{ try{
  busy($("send"),true);
  const {sk, vk} = await loadKey(); const fromRid=await showRID(vk);
  const to=$("toRid").value.trim(); const amount=parseInt($("amount").value,10);
  if(!to||!amount) throw new Error("RID получателя и сумма обязательны");
  const st=await refreshState(fromRid);
  const tx={from:fromRid,to,amount,nonce:(st.nonce||0)+1};
  const canonHex=await txCanon(tx);
  const sig_hex=await signHex(sk,canonHex);
  const resp=await apiPOST("/submit_tx_batch",{txs:[{...tx,sig_hex}]});
  $("txOut").textContent=JSON.stringify(resp,null,2);
  await refreshState(fromRid); HIST_CURSOR=null; $("histFrom").value="0"; await loadHistory(false);
  status("Транзакция отправлена");
} catch(e){
  const m=String(e.message||e);
  if(m.includes("401")) alert("Ошибка подписи (bad_sig). Проверьте ключ/канон.");
  else if(m.includes("409")) alert("Неправильный nonce (bad_nonce). Обновите состояние.");
  else if(m.includes("402")) alert("Недостаточно средств (insufficient_funds).");
  else alert("Send error: "+m);
} finally{ busy($("send"),false); } };

$("loadHist").onclick = ()=>{ HIST_CURSOR=null; $("histFrom").value=$("histFrom").value.trim()||"0"; loadHistory(false); };
$("moreHist").onclick = ()=>{ if(HIST_CURSOR===null){ status("Конец истории"); return; } loadHistory(true); };

// auto-load
loadKey().then(async ({vk})=>{
  const rid=await showRID(vk);
  $("acctRid").value = rid;
  $("histRid").value = rid;
  $("histFrom").value = "0";
  await refreshState(rid);
  await loadHistory(false);
  status("Готово");
}).catch(()=>{ status("Сгенерируйте ключ для начала"); });
