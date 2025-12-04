# LOGOS Explorer Snapshot

_Автогенерация: `2025-11-29 10:33:36Z`_


## Explorer Frontend (sources)

`/root/logos_lrb/www/explorer`


---

### `/root/logos_lrb/www/explorer/explorer.css`

```css
body { font-family: system-ui, sans-serif; margin: 0; background: #0b0c10; color: #e6edf3; }
header { padding: 12px; background: #11151a; border-bottom: 1px solid #1e242c; display:flex; justify-content:space-between; }
main { padding: 12px; display: grid; gap: 20px; }
section { background: #141a21; padding: 12px; border-radius: 10px; }
button { padding: 10px 14px; border-radius: 8px; border: none; margin: 4px; cursor: pointer; background: #1665c1; color: #fff; font-weight: 600; }
button:hover { background: #1f77d0; }
input { padding: 8px; margin: 4px; border-radius: 6px; border: 1px solid #333; background: #0b0c10; color: #e6edf3; width: 100%; max-width: 380px; }
pre { background: #0e1116; padding: 8px; border-radius: 6px; overflow-x: auto; }
table { width: 100%; border-collapse: collapse; margin-top: 10px; }
th, td { padding: 6px 8px; border-bottom: 1px solid #333; font-size: 13px; }

```

---

### `/root/logos_lrb/www/explorer/explorer.js`

```javascript
// LOGOS Explorer – history debug + stable fill
const API = location.origin + "/api";
const $  = s => document.querySelector(s);
const out= (id,v)=>{$(id).textContent=(typeof v==="string")?v:JSON.stringify(v,null,2)};
const fmtNum=n=>Number(n).toLocaleString("ru-RU");
const fmtTs =ms=>isFinite(ms)?new Date(Number(ms)).toLocaleString("ru-RU"):"";

async function jget(path){
  const r=await fetch(API+path,{cache:"no-store"});
  if(!r.ok) throw new Error(r.status+" "+(await r.text()).slice(0,400));
  return r.json();
}

// status
document.addEventListener("DOMContentLoaded",()=>{ const s=$("#jsStat"); if(s){ s.style.color="#0bd464"; s.textContent="js: готов"; }});

// HEAD / ECONOMY
let autoTimer=null;
async function fetchHead(){ try{ out("out-head", await jget("/head")); }catch(e){ out("out-head","ERR: "+e.message); } }
async function fetchEconomy(){ try{ out("out-economy", await jget("/economy")); }catch(e){ out("out-economy","ERR: "+e.message); } }
function toggleAuto(){
  if(autoTimer){ clearInterval(autoTimer); autoTimer=null; $("#btn-auto").textContent="Автообновление: выключено"; return; }
  const tick=async()=>{ await fetchHead(); await fetchEconomy(); };
  tick(); autoTimer=setInterval(tick,5000);
  $("#btn-auto").textContent="Автообновление: включено";
}

// BLOCK / MIX
async function fetchBlock(){
  const h=Number($("#inp-height").value); if(!h){ alert("Укажи высоту"); return; }
  try{ out("out-block", await jget("/block/"+h)); }catch(e){ out("out-block","ERR: "+e.message); }
}
async function fetchMix(){
  const h=Number($("#inp-height").value); if(!h){ alert("Укажи высоту"); return; }
  try{ out("out-block", await jget(`/block/${h}/mix`)); }catch(e){ out("out-block","ERR: "+e.message); }
}

// HISTORY
let histRid="", limit=20, fromNonce=0, nextFrom=null, prevStack=[];
function renderHistory(arr){
  const tb=$("#tbl-history tbody"); tb.innerHTML="";
  if(!arr || arr.length===0){
    const tr=document.createElement("tr");
    tr.innerHTML=`<td colspan="6" style="opacity:.8">0 записей</td>`;
    tb.appendChild(tr);
  } else {
    arr.forEach(tx=>{
      const tr=document.createElement("tr");
      tr.innerHTML=`<td>${tx.nonce??""}</td><td>${tx.from??""}</td><td>${tx.to??""}</td>`+
                   `<td>${fmtNum(tx.amount??0)}</td><td>${tx.height??""}</td><td>${fmtTs(tx.ts_ms)}</td>`;
      tb.appendChild(tr);
    });
  }
  $("#hist-info").textContent=`RID=${histRid} · from=${fromNonce} · limit=${limit} · next=${nextFrom??"-"}`;
  $("#btn-prev").disabled = (prevStack.length===0);
  $("#btn-next").disabled = (nextFrom==null);
}

async function pageHistory(rid, from, lim){
  const q=new URLSearchParams({from:String(from||0),limit:String(lim||20)});
  const j=await jget(`/history/${rid}?`+q.toString());
  // DEBUG: покажем сырой ответ под таблицей
  out("out-history", j); $("#out-history").style.display="block";
  const arr=j.items || j.txs || [];
  nextFrom=(typeof j.next_from!=="undefined")?j.next_from:null;
  renderHistory(arr);
}

async function fetchHistory(){
  histRid=($("#inp-rid").value||"").trim();
  limit=Math.max(1, Number($("#inp-limit").value)||20);
  if(!histRid){ alert("Укажи RID"); return; }
  fromNonce=0; nextFrom=null; prevStack=[];
  try{ await pageHistory(histRid, fromNonce, limit); }catch(e){ alert("ERR: "+e.message); }
}
async function prevPage(){ if(prevStack.length===0) return; fromNonce=prevStack.pop(); await pageHistory(histRid, fromNonce, limit); }
async function nextPage(){ if(nextFrom==null) return; prevStack.push(fromNonce); fromNonce=nextFrom; await pageHistory(histRid, fromNonce, limit); }

// экспорт под onclick
window.fetchHead=fetchHead; window.fetchEconomy=fetchEconomy; window.toggleAuto=toggleAuto;
window.fetchBlock=fetchBlock; window.fetchMix=fetchMix;
window.fetchHistory=fetchHistory; window.prevPage=prevPage; window.nextPage=nextPage;

```

---

### `/root/logos_lrb/www/explorer/index.html`

```html
<!doctype html>
<html lang="ru">
<head>
  <meta charset="utf-8"/>
  <meta http-equiv="Cache-Control" content="no-store"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>LOGOS Explorer — v2 (inline)</title>
  <style>
    :root{--bg:#0b0c10;--card:#11151a;--line:#1e242c;--muted:#9aa4af;--txt:#e6edf3;--btn:#1665c1;--btn-b:#3b7ddd;}
    *{box-sizing:border-box}
    body{font-family:system-ui,Segoe UI,Roboto,Arial,sans-serif;margin:0;background:var(--bg);color:var(--txt)}
    header{padding:12px;background:var(--card);border-bottom:1px solid var(--line);display:flex;gap:10px;align-items:center;flex-wrap:wrap}
    header h1{font-size:18px;margin:0}
    #jsStat{font-size:12px;margin-left:auto}
    main{max-width:1100px;margin:18px auto;padding:0 12px}
    section{background:var(--card);margin:12px 0;border-radius:14px;padding:14px;border:1px solid var(--line)}
    h3{margin:6px 0 12px 0}
    .row{display:flex;gap:10px;flex-wrap:wrap}
    .row>.grow{flex:1 1 360px}
    .row>.fit{flex:0 0 140px}
    input{width:100%;padding:10px;border-radius:10px;border:1px solid var(--line);background:#0b0f14;color:#e6edf3}
    button{padding:10px 14px;border-radius:10px;border:1px solid var(--btn-b);background:var(--btn);color:#fff;font-weight:600;cursor:pointer}
    .btns{display:flex;gap:8px;flex-wrap:wrap}
    pre{white-space:pre-wrap;word-break:break-word;background:#0b0f14;border:1px solid var(--line);border-radius:10px;padding:10px;overflow:auto;margin:8px 0 0}
    .cards{display:grid;grid-template-columns:1fr 1fr;gap:12px}
    @media(max-width:900px){.cards{grid-template-columns:1fr}}
    .table-wrap{overflow-x:auto;border:1px solid var(--line);border-radius:10px;margin-top:8px}
    table{width:100%;border-collapse:collapse;min-width:700px}
    th,td{border-bottom:1px solid var(--line);padding:8px 10px;text-align:left;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:13px;white-space:nowrap}
    .muted{color:#9aa4af}
    .pill{border:1px solid var(--line);padding:8px 10px;border-radius:10px;background:#0b0f14}
  </style>
</head>
<body>
<header>
  <h1>LOGOS LRB — исследователь</h1>
  <div class="pill">
    <input id="q" placeholder="Поиск: RID, высота блока или псевдо-txid from:nonce" style="min-width:260px">
    <button onclick="search()">Найти</button>
  </div>
  <div id="jsStat">js: загрузка…</div>
</header>

<main>

  <section class="cards">
    <div>
      <h3>Голова</h3>
      <div class="btns">
        <button onclick="fetchHead()">GET /head</button>
        <button onclick="toggleAuto()">Автообновление</button>
      </div>
      <pre id="out-head"></pre>
    </div>
    <div>
      <h3>Эконом</h3>
      <button onclick="fetchEconomy()">GET /economy</button>
      <pre id="out-economy"></pre>
    </div>
  </section>

  <section>
    <h3>Блок</h3>
    <div class="row">
      <div class="grow"><label class="muted">высота блока</label><input id="inp-height" type="number" min="1" placeholder="например 1"></div>
      <div class="grow btns" style="align-items:flex-end">
        <button onclick="fetchBlock()">/block/:height</button>
        <button onclick="fetchMix()">/block/:height/mix</button>
        <button onclick="loadLatest()">Последние блоки</button>
      </div>
    </div>
    <div class="table-wrap" id="latest-wrap" style="display:none">
      <table><thead><tr><th>height</th><th>ts</th><th>finalized</th></tr></thead><tbody id="latest"></tbody></table>
    </div>
    <pre id="out-block"></pre>
  </section>

  <section>
    <h3>Адрес (RID)</h3>
    <div class="row">
      <div class="grow"><label class="muted">RID (base58)</label><input id="inp-rid" placeholder="вставь RID"></div>
      <div class="fit"><label class="muted">limit</label><input id="inp-limit" type="number" min="1" value="20"></div>
      <div class="grow btns" style="align-items:flex-end"><button onclick="fetchHistory()">GET /history</button></div>
    </div>
    <div class="table-wrap">
      <table id="tbl">
        <thead><tr><th>nonce</th><th>from</th><th>to</th><th>amount</th><th>height</th><th>ts</th></tr></thead>
        <tbody id="hist-body"></tbody>
      </table>
    </div>
    <pre id="out-history" style="display:none"></pre>
  </section>

</main>

<script>
(function(){
  const API = location.origin + "/api";
  const $  = s => document.querySelector(s);
  const setStat = (t,ok)=>{ const s=$("#jsStat"); if(!s) return; s.textContent=t; s.style.color=ok?"#0bd464":"#ff5252"; };
  const fmtNum=n=>Number(n).toLocaleString("ru-RU");
  const fmtTs =ms=>isFinite(ms)?new Date(Number(ms)).toLocaleString("ru-RU"):"";

  async function jget(path){
    try{ const r=await fetch(API+path,{cache:"no-store"}); if(!r.ok) return {error:r.status+" "+(await r.text()).slice(0,200)}; return await r.json(); }
    catch(e){ return {error:String(e)}; }
  }

  // HEAD & ECON
  let autoTimer=null;
  window.fetchHead = async ()=>{ $("#out-head").textContent = JSON.stringify(await jget("/head"), null, 2); };
  window.fetchEconomy = async ()=>{ $("#out-economy").textContent = JSON.stringify(await jget("/economy"), null, 2); };
  window.toggleAuto = ()=>{
    if(autoTimer){ clearInterval(autoTimer); autoTimer=null; setStat("js: авто выкл", true); return; }
    const tick=async()=>{ await fetchHead(); await fetchEconomy(); };
    tick(); autoTimer=setInterval(tick, 5000); setStat("js: авто вкл", true);
  };

  // BLOCKS
  window.fetchBlock = async ()=>{
    const h=Number($("#inp-height").value)||0; if(!h){ alert("Укажи высоту"); return; }
    $("#out-block").textContent = JSON.stringify(await jget("/block/"+h), null, 2);
    $("#latest-wrap").style.display="none";
  };
  window.fetchMix = async ()=>{
    const h=Number($("#inp-height").value)||0; if(!h){ alert("Укажи высоту"); return; }
    $("#out-block").textContent = JSON.stringify(await jget(`/block/${h}/mix`), null, 2);
    $("#latest-wrap").style.display="none";
  };
  window.loadLatest = async ()=>{
    const head=await jget("/head");
    const H = head && head.height ? Number(head.height) : 0;
    const tbody=$("#latest"); tbody.innerHTML="";
    if(!H){ $("#latest-wrap").style.display="none"; return; }
    const from=Math.max(1,H-9);  // последние 10
    for(let h=H; h>=from; h--){
      const b = await jget("/block/"+h);
      const tr=document.createElement("tr");
      tr.innerHTML = `<td>${h}</td><td>${b.ts_ms?fmtTs(b.ts_ms):""}</td><td>${b.finalized??""}</td>`;
      tbody.appendChild(tr);
    }
    $("#latest-wrap").style.display="block";
    $("#out-block").textContent = "";
  };

  // HISTORY
  function renderRows(arr){
    const tb=$("#hist-body"); tb.innerHTML="";
    if(!arr || arr.length===0){ const tr=document.createElement("tr"); tr.innerHTML='<td colspan="6" class="muted">0 записей</td>'; tb.appendChild(tr); return; }
    for(const tx of arr){
      const tr=document.createElement("tr");
      tr.innerHTML = `<td>${tx.nonce??""}</td><td>${tx.from??""}</td><td>${tx.to??""}</td>`+
                     `<td>${fmtNum(tx.amount??0)}</td><td>${tx.height??""}</td><td>${fmtTs(tx.ts_ms)}</td>`;
      tb.appendChild(tr);
    }
  }
  window.fetchHistory = async ()=>{
    const rid = ($("#inp-rid").value||"").trim(); if(!rid){ alert("Укажи RID"); return; }
    const lim = Math.max(1, Number($("#inp-limit").value)||20);
    const raw = await jget(`/history/${encodeURIComponent(rid)}?limit=${lim}`);
    $("#out-history").style.display="block"; $("#out-history").textContent=JSON.stringify(raw,null,2);
    const arr = (raw && (raw.items||raw.txs)) ? (raw.items||raw.txs) : [];
    renderRows(arr);
  };

  // SEARCH (RID / block height / pseudo txid "from:nonce")
  window.search = async ()=>{
    const q = ($("#q").value||"").trim();
    if(!q) return;
    if(/^\d+$/.test(q)){ $("#inp-height").value=q; await fetchBlock(); return; }
    if(/^[1-9A-HJ-NP-Za-km-z]+$/.test(q) && q.length>30){ $("#inp-rid").value=q; await fetchHistory(); return; }
    if(q.includes(":")){ // псевдо-txid from:nonce
      const [from,nonce] = q.split(":");
      $("#inp-rid").value = from;
      $("#inp-limit").value = 50;
      await fetchHistory();
      // подсветим найденную строку
      [...document.querySelectorAll("#hist-body tr")].forEach(tr=>{
        if(tr.firstChild && tr.firstChild.textContent===(nonce||"").trim()){ tr.style.background="#132235"; }
      });
      return;
    }
    alert("Не распознан формат запроса. Используй: RID, номер блока, или from:nonce");
  };

  // boot mark
  setStat("js: готов", true);
})();
</script>
</body>
</html>

```

## nginx: logos.conf

### `/etc/nginx/sites-available/logos.conf`

```ini
# === LOGOS LRB — продовый периметр (HTTPS+HTTP/2) ===
# upstream до Axum (локально)
upstream logos_node_backend {
    server 127.0.0.1:8080;
    keepalive 64;
}

# 80 -> 443
server {
    listen 80 default_server;
    server_name 45-159-248-232.sslip.io 45.159.248.232 _;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name 45-159-248-232.sslip.io 45.159.248.232 _;

    # --- TLS ---
    ssl_certificate     /etc/nginx/ssl/logos.crt;
    ssl_certificate_key /etc/nginx/ssl/logos.key;
    ssl_session_cache   shared:LOGOS_SSL:10m;
    ssl_session_timeout 10m;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;

    # --- Общие заголовки/параметры ---
    add_header X-Content-Type-Options nosniff always;
    add_header X-Frame-Options DENY always;
    add_header Referrer-Policy no-referrer-when-downgrade always;
    client_max_body_size 1m;

    # --- Проксирование к ноде на /api/ ---
    location /api/ {
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        proxy_read_timeout 30s;
        proxy_send_timeout 30s;

        # РОУТИНГ: /api/xxx -> http://127.0.0.1:8080/xxx
        proxy_pass http://logos_node_backend/;

        # Периметр-лимиты (важно: без ":20m")
        limit_conn logos_conn_api 120;
        limit_req  zone=logos_tx_api burst=50 nodelay;
    }

    # Узкое горлышко на метрики (не душим основной API)
    location = /api/metrics {
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_pass http://logos_node_backend/metrics;

        limit_req  zone=logos_metrics burst=20 nodelay;
        access_log off;
    }

    # (Опционально) статика кошелька/эксплорера, если раздаёшь с этого же инстанса
    # location /wallet/   { root /var/www; }
    # location /explorer/ { root /var/www; }
}

```

## nginx: logos_front

### `/etc/nginx/sites-available/logos_front`

```
# Upstream'ы для API

# LOGOS node / wallet / explorer API (lrb-proxy, 8090)
upstream logos_api {
    server 127.0.0.1:8090;
    keepalive 64;
}

# Airdrop API (FastAPI на 127.0.0.1:8092)
upstream airdrop_api {
    server 127.0.0.1:8092;
    keepalive 16;
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;

    server_name mw-expedition.com www.mw-expedition.com;

    root /var/www/logos/landing;
    index index.html;
    charset utf-8;

    # Отдельные логи проекта
    access_log /var/log/nginx/logos_front.access.log;
    error_log  /var/log/nginx/logos_front.error.log warn;

    # Базовая защита
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    add_header Permissions-Policy "geolocation=(), camera=(), microphone=()" always;

    # Gzip для текста и статики
    gzip on;
    gzip_comp_level 5;
    gzip_min_length 256;
    gzip_vary on;
    gzip_proxied any;
    gzip_types
        text/plain
        text/css
        text/javascript
        application/javascript
        application/json
        application/xml
        application/rss+xml
        font/woff2
        application/font-woff2
        image/svg+xml;

    # --- SPA фронт
    location / {
        try_files $uri $uri/ /index.html;
    }

    # --- Статика с долгим кэшем
    location ~* \.(?:css|js|ico|png|jpg|jpeg|gif|svg|woff2?)$ {
        access_log off;
        expires 30d;
        add_header Cache-Control "public, max-age=2592000, immutable";
        try_files $uri =404;
    }

    # --- Airdrop API (FastAPI)
    location /api/airdrop/ {
        proxy_pass http://airdrop_api;
        proxy_http_version 1.1;

        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        proxy_read_timeout   60s;
        proxy_connect_timeout 5s;
        proxy_send_timeout   60s;

        # Буферизация для массовых нагрузок
        proxy_buffering on;
        proxy_buffers 32 16k;
        proxy_busy_buffers_size 64k;
    }

    # --- Основной LOGOS API
    location /api/ {
        proxy_pass http://logos_api;
        proxy_http_version 1.1;

        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        proxy_read_timeout   120s;
        proxy_connect_timeout 5s;
        proxy_send_timeout   120s;

        proxy_buffering on;
        proxy_buffers 32 32k;
        proxy_busy_buffers_size 256k;

        # сюда можно навесить лимиты RPS, если захочешь
        # limit_req zone=api_burst burst=20 nodelay;
    }

    # SSL от Let's Encrypt
    ssl_certificate     /etc/letsencrypt/live/mw-expedition.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/mw-expedition.com/privkey.pem;
    include             /etc/letsencrypt/options-ssl-nginx.conf;
    ssl_dhparam         /etc/letsencrypt/ssl-dhparams.pem;
}

# HTTP -> HTTPS редирект
server {
    listen 80;
    listen [::]:80;
    server_name mw-expedition.com www.mw-expedition.com;

    return 301 https://$host$request_uri;
}

```

## nginx: logos-node-8000.conf

### `/etc/nginx/sites-available/logos-node-8000.conf`

```ini
server {
    listen 8000;
    server_name _;
    # если будете раздавать фронт-кошелёк со статикой — пропишите root
    # root /var/www/wallet;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}

```
