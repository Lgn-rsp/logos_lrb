import * as ed from "https://cdn.jsdelivr.net/npm/@noble/ed25519@1.7.3/+esm";
import bs58 from "https://cdn.jsdelivr.net/npm/bs58@5.0.0/+esm";

/* =============== helpers =============== */
const $ = (id)=>document.getElementById(id);
const enc = new TextEncoder();

const st = {
  node: localStorage.getItem("lrb_node") || "http://45.159.248.232:8080",
  skHex: localStorage.getItem("lrb_sk") || "",
  pkHex: localStorage.getItem("lrb_pk") || "",
  cursor_h: null, cursor_seq: null
};

function ridFromPkHex(pkHex){ return bs58.encode(Buffer.from(pkHex,"hex")); }
function toB64(u8){ return btoa(String.fromCharCode(...u8)); }

function canonicalBytes(from, to, amount, nonce, pkHex) {
  const pk = Buffer.from(pkHex, "hex");
  const a = enc.encode(from), b = enc.encode(to),
        c = enc.encode(String(amount)), d = enc.encode(String(nonce));
  const out = new Uint8Array(a.length+b.length+c.length+d.length+pk.length);
  out.set(a,0); out.set(b,a.length); out.set(c,a.length+b.length);
  out.set(d,a.length+b.length+c.length); out.set(pk,a.length+b.length+c.length+d.length);
  return out;
}

async function getJSON(url, opts={}) {
  const r = await fetch(url, opts);
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return await r.json();
}
async function postJSON(url, body, headers={}) {
  const r = await fetch(url, {method:"POST",headers:{'content-type':'application/json',...headers},body:JSON.stringify(body)});
  const t = await r.text();
  try { return { ok:r.ok, status:r.status, body: JSON.parse(t||"{}") }; }
  catch { return { ok:r.ok, status:r.status, body: t }; }
}

/* =============== network / head =============== */
$("nodeUrl").value = st.node;
$("saveNode").onclick = () => { st.node = $("nodeUrl").value.trim(); localStorage.setItem("lrb_node", st.node); alert("Node URL сохранён"); };
$("ping").onclick = async ()=>{
  try {
    const h = await getJSON(`${st.node}/healthz`); $("pingRes").textContent = h.ok?"OK":"ERR";
    const head = await getJSON(`${st.node}/head`);
    $("headHeight").textContent = head.height ?? "-";
    $("headFinal").textContent  = head.finalized ?? "-";
    $("headHash").textContent   = (head.hash||"").slice(0,16)+"…";
  } catch(e){ $("pingRes").textContent = `ERR: ${e.message}`; }
};

/* =============== keys =============== */
function renderKeys(){
  const pkHex = st.pkHex;
  $("pk58").textContent = pkHex? bs58.encode(Buffer.from(pkHex,"hex")) : "";
  $("rid").textContent  = pkHex? ridFromPkHex(pkHex) : "";
  $("skHex").value = st.skHex || "";
}
$("gen").onclick = async ()=>{
  const sk = ed.utils.randomPrivateKey(); const pk = await ed.getPublicKey(sk);
  st.skHex = Buffer.from(sk).toString("hex"); st.pkHex = Buffer.from(pk).toString("hex");
  localStorage.setItem("lrb_sk", st.skHex); localStorage.setItem("lrb_pk", st.pkHex); renderKeys();
};
$("wipe").onclick = ()=>{ localStorage.removeItem("lrb_sk"); localStorage.removeItem("lrb_pk"); st.skHex=""; st.pkHex=""; renderKeys(); };
$("importSk").onclick = async ()=>{
  try{
    const val = $("skHex").value.trim(); if(!val) throw new Error("пусто");
    const sk = Buffer.from(val,"hex"); const pk = await ed.getPublicKey(sk);
    st.skHex = val; st.pkHex = Buffer.from(pk).toString("hex");
    localStorage.setItem("lrb_sk", st.skHex); localStorage.setItem("lrb_pk", st.pkHex); renderKeys();
    $("impRes").textContent = "OK";
  }catch(e){ $("impRes").textContent = "ERR"; }
};
$("exportSk").onclick = ()=>{ $("skHex").value = st.skHex || ""; };

renderKeys();

/* =============== account state =============== */
$("refreshState").onclick = async ()=>{
  $("stateRes").textContent = "";
  if(!st.pkHex) return $("stateRes").textContent = "Нет ключа";
  try{
    const rid = $("rid").textContent;
    const s = await getJSON(`${st.node}/account/${rid}/state`);
    $("balance").textContent = s.balance ?? 0;
    $("nonce").textContent   = s.nonce ?? 0;
    $("stateRes").textContent = "OK";
  }catch(e){ $("stateRes").textContent = `ERR: ${e.message}`; }
};

/* =============== send / batch =============== */
function nextNonce(){ return (parseInt($("nonce").textContent||"0",10) || 0) + 1; }

$("tabSend").onclick = ()=>{ $("panelSend").style.display="block"; $("panelBatch").style.display="none"; $("tabSend").classList.add("active"); $("tabBatch").classList.remove("active"); };
$("tabBatch").onclick= ()=>{ $("panelSend").style.display="none"; $("panelBatch").style.display="block"; $("tabBatch").classList.add("active"); $("tabSend").classList.remove("active"); };

$("send").onclick = async ()=>{
  try{
    if(!st.skHex||!st.pkHex) throw new Error("нет ключей");
    const from = $("rid").textContent.trim(), to=$("toRid").value.trim();
    const amount = parseInt($("amount").value||"0",10); if(!to||!amount) throw new Error("проверь поля");
    const nonce = nextNonce();
    const canon = canonicalBytes(from,to,amount,nonce,st.pkHex);
    const sig = await ed.sign(canon, st.skHex);
    const item = { from,to,amount,nonce, public_key_b58: bs58.encode(Buffer.from(st.pkHex,"hex")), signature_b64: toB64(sig) };
    const r = await postJSON(`${st.node}/submit_tx_batch`, [item]);
    $("sendRes").textContent = r.ok? `OK accepted=${r.body.accepted||0}` : `ERR ${r.status}`;
    // обновим nonce
    await $("refreshState").onclick();
  }catch(e){ $("sendRes").textContent = `ERR: ${e.message}`; }
};

$("sendBatch").onclick = async ()=>{
  try{
    if(!st.skHex||!st.pkHex) throw new Error("нет ключей");
    const from = $("rid").textContent.trim();
    const list = $("batchList").value.split("\n").map(s=>s.trim()).filter(Boolean);
    const amount = parseInt($("batchAmount").value||"0",10);
    const batchSize = parseInt($("batchSize").value||"50",10);
    if(list.length===0 || !amount) throw new Error("укажи получателей и сумму");
    let nonce = nextNonce(), accepted=0, sent=0;
    for(let i=0;i<list.length;i+=batchSize){
      const chunk = list.slice(i,i+batchSize);
      const req = [];
      for(const to of chunk){
        const canon = canonicalBytes(from,to,amount,nonce,st.pkHex);
        const sig   = await ed.sign(canon, st.skHex);
        req.push({ from,to,amount,nonce, public_key_b58: bs58.encode(Buffer.from(st.pkHex,"hex")), signature_b64: toB64(sig) });
        nonce++;
      }
      const r = await postJSON(`${st.node}/submit_tx_batch`, req);
      sent += req.length; if(r.ok) accepted += (r.body.accepted||0);
      $("batchRes").textContent = `sent=${sent} accepted=${accepted}`;
    }
    await $("refreshState").onclick();
  }catch(e){ $("batchRes").textContent = `ERR: ${e.message}`; }
};

/* =============== history / recent =============== */
async function loadAccountTxs(next=false){
  try{
    const rid = $("rid").textContent.trim(), params=[];
    params.push(`limit=20`);
    if(next && st.cursor_h!=null && st.cursor_seq!=null){
      params.push(`cursor_h=${st.cursor_h}`); params.push(`cursor_seq=${st.cursor_seq}`);
    }
    const url = `${st.node}/account/${rid}/txs?`+params.join("&");
    const r = await getJSON(url);
    const tbody = $("hist").querySelector("tbody");
    if(!next) tbody.innerHTML="";
    for(const it of r.items||[]){
      const tr = document.createElement("tr");
      tr.innerHTML = `<td class="mono small">${it.height??""}</td>
                      <td class="mono small">${(it.tx_id||"").slice(0,12)}…</td>
                      <td>${it.dir==-1?"→":"←"}</td>
                      <td class="right mono">${it.amount??0}</td>
                      <td class="mono small">${(it.counterparty||"").slice(0,10)}…</td>`;
      tbody.appendChild(tr);
    }
    st.cursor_h = r.next_cursor_h ?? null;
    st.cursor_seq = r.next_cursor_seq ?? null;
    $("histRes").textContent = r.items?.length ? "OK" : "—";
  }catch(e){ $("histRes").textContent = `ERR: ${e.message}`; }
}
$("loadTxs").onclick = ()=>loadAccountTxs(false);
$("nextTxs").onclick = ()=>loadAccountTxs(true);

$("recentBlocks").onclick = async ()=>{
  try{
    const r = await getJSON(`${st.node}/recent/blocks?limit=10`);
    const tbody = $("recent").querySelector("tbody"); tbody.innerHTML="";
    for(const b of r.items||[]){
      const tr = document.createElement("tr");
      tr.innerHTML = `<td class="pill">Block</td><td class="mono small">h=${b.height} tx=${(b.txs||[]).length} hash=${(b.block_hash||"").slice(0,14)}…</td>`;
      tbody.appendChild(tr);
    }
    $("recentRes").textContent="OK";
  }catch(e){ $("recentRes").textContent = `ERR: ${e.message}`; }
};
$("recentTxs").onclick = async ()=>{
  try{
    const r = await getJSON(`${st.node}/recent/txs?limit=20`);
    const tbody = $("recent").querySelector("tbody"); tbody.innerHTML="";
    for(const t of r.items||[]){
      const tr = document.createElement("tr");
      tr.innerHTML = `<td class="pill">Tx</td><td class="mono small">h=${t.height} tx=${(t.tx_id||"").slice(0,12)}… ${t.from?.slice(0,8)}→${t.to?.slice(0,8)} a=${t.amount}</td>`;
      tbody.appendChild(tr);
    }
    $("recentRes").textContent="OK";
  }catch(e){ $("recentRes").textContent = `ERR: ${e.message}`; }
};

/* =============== bridge (operator) =============== */
function authHeader(val){
  const s = (val||"").trim(); if(!s) return {};
  // Если строка похожа на JWT — отправим как Bearer, иначе X-Bridge-Key
  return s.split(".").length===3 ? {Authorization:`Bearer ${s}`} : {"X-Bridge-Key": s};
}
$("deposit").onclick = async ()=>{
  const key = $("bridgeKey").value, rid = $("bridgeRid").value.trim();
  const amount = parseInt($("depAmount").value||"0",10), ext = $("depExt").value.trim();
  const r = await postJSON(`${st.node}/bridge/deposit`, {rid,amount,ext_txid:ext}, authHeader(key));
  $("bridgeRes").textContent = r.ok ? `deposit OK: r_balance=${r.body.r_balance}` : `ERR ${r.status}`;
};
$("redeem").onclick = async ()=>{
  const key = $("bridgeKey").value, rid = $("bridgeRid").value.trim();
  const amount = parseInt($("redAmount").value||"0",10), req = $("redReq").value.trim();
  const r = await postJSON(`${st.node}/bridge/redeem`, {rid,amount,request_id:req}, authHeader(key));
  $("bridgeRes").textContent = r.ok ? `redeem OK: ticket=${r.body.redeem_ticket.slice(0,18)}…` : `ERR ${r.status}`;
};

/* =============== admin JWT =============== */
$("mintAdminToken").onclick = async ()=>{
  const key = $("adminKey").value.trim(), ttl = parseInt($("adminTtl").value||"600",10);
  const r = await fetch(`${st.node}/admin/token?ttl=${ttl}`, {headers: {"X-Admin-Key": key}});
  const body = await r.json().catch(()=>({}));
  $("adminRes").textContent = r.ok ? `OK token=${(body.token||"").slice(0,16)}…` : `ERR ${r.status}`;
};

/* =============== init =============== */
(async()=>{ await $("ping").onclick(); if(st.pkHex) await $("refreshState").onclick(); })();
