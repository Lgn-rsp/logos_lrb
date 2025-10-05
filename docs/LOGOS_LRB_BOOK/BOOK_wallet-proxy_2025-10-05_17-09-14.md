# BOOK for 'wallet-proxy' (LIVE 2025-10-05_17-09-14)

## Project tree (wallet-proxy)
```text
.
```

## Files (sources/configs/docs) — full content

### `wallet-proxy/app.py`

```python
import os, json, time, asyncio
from typing import Optional, Literal
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from web3 import Web3
from sqlalchemy import Column, Integer, String, BigInteger, create_engine, select, Index
from sqlalchemy.orm import declarative_base, Session
import aiohttp
from prometheus_client import Counter, Gauge, generate_latest, CONTENT_TYPE_LATEST

# ====== ENV ======
NODE_URL     = os.environ.get("LRB_NODE_URL", "http://127.0.0.1:8080")
BRIDGE_KEY   = os.environ.get("LRB_BRIDGE_KEY", "")
CORS         = [o.strip() for o in os.environ.get("LRB_WALLET_CORS", "*").split(",") if o.strip()]
ETH_RPC      = os.environ.get("ETH_PROVIDER_URL", "")
USDT_ADDRESS = os.environ.get("USDT_ERC20_ADDRESS", "0xdAC17F958D2ee523a2206206994597C13D831ec7")
HOT_PK       = os.environ.get("ETH_HOT_WALLET_PK", "")
DB_URL       = "sqlite:////opt/logos/wallet-proxy/wproxy.db"

# ====== DB ======
Base = declarative_base()
class DepositMap(Base):
    __tablename__ = "deposit_map"
    id = Column(Integer, primary_key=True)
    rid = Column(String, index=True, nullable=False)
    token = Column(String, nullable=False)
    network = Column(String, nullable=False)
    index = Column(Integer, nullable=False, default=0)
    address = Column(String, unique=True, nullable=False)
    created_at = Column(BigInteger, default=lambda:int(time.time()))
Index("ix_dep_unique", DepositMap.rid, DepositMap.token, DepositMap.network, unique=True)

class SeenTx(Base):
    __tablename__ = "seen_tx"
    id = Column(Integer, primary_key=True)
    txid = Column(String, unique=True, nullable=False)
    rid = Column(String, index=True)
    token = Column(String)
    network = Column(String)

engine = create_engine(DB_URL, future=True)
Base.metadata.create_all(engine)

# ====== Web3 ======
w3: Optional[Web3] = None
USDT = None
ERC20_ABI = json.loads("""
[
 {"constant":true,"inputs":[{"name":"_owner","type":"address"}],"name":"balanceOf","outputs":[{"name":"","type":"uint256"}],"type":"function"},
 {"constant":false,"inputs":[{"name":"_to","type":"address"},{"name":"_value","type":"uint256"}],"name":"transfer","outputs":[{"name":"","type":"bool"}],"type":"function"},
 {"anonymous":false,"inputs":[{"indexed":true,"name":"from","type":"address"},{"indexed":true,"name":"to","type":"address"},{"indexed":false,"name":"value","type":"uint256"}],"name":"Transfer","type":"event"}
]
""")
if ETH_RPC:
    try:
        w3 = Web3(Web3.HTTPProvider(ETH_RPC, request_kwargs={"timeout":10}))
        if w3.is_connected():
            USDT = w3.eth.contract(address=Web3.to_checksum_address(USDT_ADDRESS), abi=ERC20_ABI)
            print("INFO Web3 connected:", USDT_ADDRESS)
        else:
            print("WARN ETH RPC not reachable"); w3=None
    except Exception as e:
        print("WARN web3 init error:", e); w3=None; USDT=None

# ====== HTTP helper ======
async def http_json(method:str, url:str, body:dict=None, headers:dict=None):
    async with aiohttp.ClientSession() as sess:
        async with sess.request(method, url, json=body, headers=headers) as r:
            t = await r.text()
            try: data = json.loads(t) if t else {}
            except: data = {"raw": t}
            return r.status, data

# ====== FastAPI ======
app = FastAPI(title="LRB Wallet Proxy", version="1.2")
app.add_middleware(CORSMiddleware, allow_origins=CORS if CORS else ["*"],
                   allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

# ====== Pydantic v2-safe models ======
class TopupRequest(BaseModel):
    rid: str
    token: Literal["USDT"] = "USDT"
    network: Literal["ETH"] = "ETH"
class TopupResponse(BaseModel):
    rid: str; token: str; network: str; address: str
class WithdrawRequest(BaseModel):
    rid: str; token: Literal["USDT"]="USDT"; network: Literal["ETH"]="ETH"
    amount: int; to_address: str; request_id: str
class QuoteRequest(BaseModel):
    from_token: str; to_token: str; amount: int
class QuoteResponse(BaseModel):
    price: float; expected_out: float

# ====== Metrics ======
PROXY_TOPUP_REQ   = Counter("proxy_topup_requests_total", "topup requests")
PROXY_WITHDRAW_OK = Counter("proxy_withdraw_ok_total",   "withdraw ok")
PROXY_WITHDRAW_ERR= Counter("proxy_withdraw_err_total",  "withdraw err")

@app.get("/metrics")
def metrics():
    return app.responses.Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)

# ====== Endpoints ======
@app.get("/")
def root():
    return {"ok": True, "service": "wallet-proxy", "eth_connected": bool(w3)}

@app.post("/v1/topup/request", response_model=TopupResponse)
def topup_request(req: TopupRequest):
    PROXY_TOPUP_REQ.inc()
    if not w3: raise HTTPException(503, "ETH RPC not connected")
    if not HOT_PK: raise HTTPException(500, "HOT wallet not configured")
    deposit_address = w3.eth.account.from_key(HOT_PK).address
    with Session(engine) as s:
        dm = s.execute(select(DepositMap).where(
            DepositMap.rid==req.rid, DepositMap.token==req.token, DepositMap.network==req.network
        )).scalar_one_or_none()
        if dm is None:
            s.add(DepositMap(rid=req.rid, token=req.token, network=req.network, address=deposit_address))
            s.commit()
    return TopupResponse(rid=req.rid, token=req.token, network=req.network, address=deposit_address)

@app.post("/v1/withdraw")
async def withdraw(req: WithdrawRequest):
    try:
        if req.amount<=0: raise HTTPException(400,"amount<=0")
        if not w3 or not USDT: raise HTTPException(503, "ETH RPC not connected")
        acct = w3.eth.account.from_key(HOT_PK)
        # redeem
        hdr = {"X-Bridge-Key": BRIDGE_KEY} if not BRIDGE_KEY.startswith("ey") else {"Authorization": f"Bearer {BRIDGE_KEY}"}
        st, data = await http_json("POST", f"{NODE_URL}/bridge/redeem", {
            "rid": req.rid, "amount": req.amount, "request_id": req.request_id
        }, hdr)
        if st//100 != 2: raise HTTPException(st, f"bridge redeem failed: {data}")
        # ERC-20
        nonce = w3.eth.get_transaction_count(acct.address)
        tx = USDT.functions.transfer(Web3.to_checksum_address(req.to_address), int(req.amount)).build_transaction({
            "chainId": w3.eth.chain_id, "from": acct.address, "nonce": nonce,
            "gas": 90000, "maxFeePerGas": w3.to_wei("30","gwei"), "maxPriorityFeePerGas": w3.to_wei("1","gwei"),
        })
        signed = w3.eth.account.sign_transaction(tx, private_key=HOT_PK)
        tx_hash = w3.eth.send_raw_transaction(signed.rawTransaction).hex()
        with Session(engine) as s: s.add(SeenTx(txid=tx_hash, rid=req.rid, token=req.token, network=req.network)); s.commit()
        PROXY_WITHDRAW_OK.inc()
        return {"ok": True, "txid": tx_hash}
    except HTTPException:
        PROXY_WITHDRAW_ERR.inc(); raise
    except Exception as e:
        PROXY_WITHDRAW_ERR.inc(); raise HTTPException(500, f"withdraw error: {e}")

@app.post("/v1/quote", response_model=QuoteResponse)
async def quote(req: QuoteRequest):
    return QuoteResponse(price=1.0, expected_out=float(req.amount))
```

### `wallet-proxy/scanner.py`

```python
import os, json, time, asyncio
from typing import Optional
from web3 import Web3
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from prometheus_client import Counter, Gauge, start_http_server
import aiohttp

DB_URL       = "sqlite:////opt/logos/wallet-proxy/wproxy.db"
NODE_URL     = os.environ.get("LRB_NODE_URL", "http://127.0.0.1:8080")
BRIDGE_KEY   = os.environ.get("LRB_BRIDGE_KEY", "")
ETH_RPC      = os.environ.get("ETH_PROVIDER_URL", "")
USDT_ADDRESS = os.environ.get("USDT_ERC20_ADDRESS", "0xdAC17F958D2ee523a2206206994597C13D831ec7")
CONFIRMATIONS= int(os.environ.get("ETH_CONFIRMATIONS", "6"))

from sqlalchemy.orm import declarative_base
from sqlalchemy import Column, Integer, String, BigInteger

Base = declarative_base()
class DepositMap(Base):
    __tablename__ = "deposit_map"
    id = Column(Integer, primary_key=True); rid = Column(String); token = Column(String); network = Column(String); address = Column(String)
class SeenTx(Base):
    __tablename__ = "seen_tx"
    id = Column(Integer, primary_key=True); txid = Column(String, unique=True); rid = Column(String); token = Column(String); network = Column(String)
class Kv(Base):
    __tablename__ = "kv"
    k = Column(String, primary_key=True); v = Column(String, nullable=False)

engine = create_engine(DB_URL, future=True)

# metrics
SCAN_LAST_BLOCK = Gauge("scanner_last_scanned_block", "last scanned block")
SCAN_LAG        = Gauge("scanner_block_lag", "chain head minus safe block")
DEP_OK          = Counter("scanner_deposit_ok_total", "successful deposits")
DEP_ERR         = Counter("scanner_deposit_err_total","failed deposits")

async def http_json(method:str, url:str, body:dict=None, headers:dict=None):
    async with aiohttp.ClientSession() as sess:
        async with sess.request(method, url, json=body, headers=headers) as r:
            t = await r.text()
            try: data = json.loads(t) if t else {}
            except: data = {"raw": t}
            return r.status, data

def kv_get(key:str, default:str="0")->str:
    with Session(engine) as s:
        row = s.get(Kv, key); return row.v if row else default
def kv_set(key:str, val:str):
    with Session(engine) as s:
        row = s.get(Kv, key)
        if row: row.v = val
        else:   s.add(Kv(k=key, v=val))
        s.commit()

async def scanner():
    if not ETH_RPC:
        print("No ETH RPC configured; scanner idle"); 
        while True: await asyncio.sleep(30)

    w3 = Web3(Web3.HTTPProvider(ETH_RPC, request_kwargs={"timeout":10}))
    if not w3.is_connected():
        print("ETH RPC unreachable; scanner idle")
        while True: await asyncio.sleep(30)

    USDT = w3.eth.contract(address=Web3.to_checksum_address(USDT_ADDRESS), abi=json.loads("""
    [
     {"anonymous":false,"inputs":[{"indexed":true,"name":"from","type":"address"},{"indexed":true,"name":"to","type":"address"},{"indexed":false,"name":"value","type":"uint256"}],"name":"Transfer","type":"event"}
    ]
    """))
    key = "last_scanned_block"
    backoff = 1
    while True:
        try:
            head = w3.eth.block_number
            safe_to = head - CONFIRMATIONS
            last = int(kv_get(key, "0"))
            SCAN_LAG.set(max(0, head - safe_to))
            if safe_to <= last:
                await asyncio.sleep(5); continue

            step = 2000
            from_block = last + 1
            with Session(engine) as s:
                addr_map = {dm.address.lower(): dm for dm in s.query(DepositMap).all()}

            while from_block <= safe_to:
                to_block = min(from_block + step - 1, safe_to)
                logs = w3.eth.get_logs({
                    "fromBlock": from_block, "toBlock": to_block,
                    "address": Web3.to_checksum_address(USDT_ADDRESS),
                    "topics": [Web3.keccak(text="Transfer(address,address,uint256)")]
                })
                for lg in logs:
                    to_hex = "0x"+lg["topics"][2].hex()[-40:]
                    to_norm = Web3.to_checksum_address(to_hex).lower()
                    dm = addr_map.get(to_norm)
                    if not dm: continue
                    txid = lg["transactionHash"].hex()
                    value = int(lg["data"], 16)
                    # идемпотентность
                    with Session(engine) as s:
                        if s.execute(select(SeenTx).where(SeenTx.txid==txid)).scalar_one_or_none():
                            continue
                        s.add(SeenTx(txid=txid, rid=dm.rid, token=dm.token, network=dm.network)); s.commit()
                    # bridge deposit
                    hdr = {"X-Bridge-Key": os.environ.get("LRB_BRIDGE_KEY","")}
                    st, data = await http_json("POST", f"{NODE_URL}/bridge/deposit",
                                               {"rid": dm.rid, "amount": value, "ext_txid": txid}, hdr)
                    if st//100 == 2: DEP_OK.inc()
                    else:
                        DEP_ERR.inc()
                        print("WARN deposit fail", txid, st, data)
                kv_set(key, str(to_block))
                SCAN_LAST_BLOCK.set(to_block)
                from_block = to_block + 1
                backoff = 1
            await asyncio.sleep(5)
        except Exception as e:
            print("scanner error:", e)
            await asyncio.sleep(min(60, backoff)); backoff = min(60, backoff*2)

if __name__ == "__main__":
    # метрики на 9101
    start_http_server(9101)
    asyncio.run(scanner())
```

