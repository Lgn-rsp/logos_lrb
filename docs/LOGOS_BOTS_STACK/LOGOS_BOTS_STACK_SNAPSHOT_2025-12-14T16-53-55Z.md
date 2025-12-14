# LOGOS Bots Stack Snapshot (TG + X Guard + Airdrop API)

_Автогенерация: `2025-12-14 16:53:55Z`_


## Telegram Airdrop Bot (deployed)

`/opt/logos/airdrop-tg-bot`


---

### `/opt/logos/airdrop-tg-bot/bot.py`

```python
#!/usr/bin/env python3
import os
import time
import json
import logging
import urllib.request
import urllib.parse

log = logging.getLogger("logos-airdrop-tg-bot")
logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s [%(levelname)s] %(message)s",
)

def env_any(*names: str, default: str = "") -> str:
    for n in names:
        v = os.getenv(n)
        if v and v.strip():
            return v.strip()
    return default

BOT_TOKEN = env_any("LOGOS_TG_BOT_TOKEN", "TG_BOT_TOKEN", "TELEGRAM_BOT_TOKEN", "BOT_TOKEN")
if not BOT_TOKEN:
    raise SystemExit("Missing bot token env. Expected one of: LOGOS_TG_BOT_TOKEN / TG_BOT_TOKEN / TELEGRAM_BOT_TOKEN / BOT_TOKEN")

TG_CHANNEL = env_any("TG_CHANNEL", "TELEGRAM_CHANNEL", default="@logosblockchain")
AIRDROP_API_KEY = env_any("AIRDROP_API_KEY", default="")
AIRDROP_UPDATE_URL = env_any("AIRDROP_UPDATE_URL", default="http://127.0.0.1:8092/api/airdrop/update")
AIRDROP_KEY_HEADER = env_any("AIRDROP_API_KEY_HEADER", default="X-API-Key")

TG_API = f"https://api.telegram.org/bot{BOT_TOKEN}"

def http_json(url: str, payload: dict | None = None, headers: dict | None = None, timeout: int = 60) -> dict:
    data = None
    req_headers = {"Content-Type": "application/json"}
    if headers:
        req_headers.update(headers)

    if payload is not None:
        data = json.dumps(payload).encode("utf-8")

    req = urllib.request.Request(url, data=data, headers=req_headers, method="POST" if payload is not None else "GET")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read().decode("utf-8", errors="replace")
        return json.loads(raw) if raw else {}

def tg_call(method: str, payload: dict, timeout: int = 60) -> dict:
    return http_json(f"{TG_API}/{method}", payload=payload, timeout=timeout)

def send_message(chat_id: int, text: str) -> None:
    try:
        tg_call("sendMessage", {"chat_id": chat_id, "text": text, "disable_web_page_preview": True}, timeout=30)
    except Exception as e:
        log.warning("sendMessage failed: %s", e)

def extract_token(text: str) -> str:
    text = (text or "").strip()
    if not text.startswith("/start"):
        return ""
    parts = text.split(maxsplit=1)
    if len(parts) < 2:
        return ""
    param = parts[1].strip()
    if param.startswith("airdrop_"):
        param = param[len("airdrop_"):].strip()
    return param

def is_member(user_id: int) -> bool:
    try:
        r = tg_call("getChatMember", {"chat_id": TG_CHANNEL, "user_id": user_id}, timeout=30)
        if not r.get("ok"):
            return False
        st = (r.get("result") or {}).get("status") or ""
        # creator/administrator/member/restricted считаем "в канале"
        return st in ("creator", "administrator", "member", "restricted")
    except Exception as e:
        log.warning("getChatMember error: %s", e)
        return False

def airdrop_update(token: str) -> bool:
    if not AIRDROP_API_KEY:
        log.error("AIRDROP_API_KEY missing in env; cannot update airdrop")
        return False
    try:
        headers = {AIRDROP_KEY_HEADER: AIRDROP_API_KEY}
        payload = {"token": token, "telegram_ok": True}
        r = http_json(AIRDROP_UPDATE_URL, payload=payload, headers=headers, timeout=20)
        return bool(r)  # не жёстко проверяем формат, главное чтобы 200 и JSON пришёл
    except Exception as e:
        log.error("airdrop_update error: %s", e)
        return False

def main() -> None:
    log.info("Starting TG bot. channel=%s update_url=%s", TG_CHANNEL, AIRDROP_UPDATE_URL)

    offset = 0
    while True:
        try:
            # long-polling
            url = f"{TG_API}/getUpdates?timeout=50&offset={offset}"
            r = http_json(url, payload=None, timeout=70)
            if not r.get("ok"):
                time.sleep(2)
                continue

            for upd in r.get("result", []):
                offset = max(offset, int(upd.get("update_id", 0)) + 1)

                msg = upd.get("message") or upd.get("edited_message")
                if not msg:
                    continue

                chat_id = (msg.get("chat") or {}).get("id")
                frm = msg.get("from") or {}
                user_id = frm.get("id")
                text = msg.get("text") or ""

                if not chat_id or not user_id:
                    continue

                token = extract_token(text)
                if not token:
                    continue

                if not is_member(int(user_id)):
                    send_message(int(chat_id), "Подпишись на канал @logosblockchain, потом снова нажми /start с токеном.")
                    continue

                ok = airdrop_update(token)
                if ok:
                    send_message(int(chat_id), "✅ Подписка подтверждена. Возвращайся на airdrop-страницу и жми Refresh.")
                    log.info("telegram_ok=true token=%s user_id=%s", token[:8] + "...", user_id)
                else:
                    send_message(int(chat_id), "⚠️ Не смог обновить статус в airdrop. Попробуй позже или напиши админу.")
        except Exception as e:
            log.error("loop error: %s", e)
            time.sleep(2)

if __name__ == "__main__":
    main()

```

## Airdrop API (deployed)

`/opt/logos/airdrop-api`


---

### `/opt/logos/airdrop-api/app.py`

```python
# LOGOS Airdrop API (FastAPI + Postgres) — mainnet-ready hardening (wallet bind + atomic referrals)
# - Adds wallet challenge + bind endpoints (Ed25519 verify by RID base58(pubkey))
# - Makes referral increment atomic (SELECT ... FOR UPDATE)
# - Adds optional wallet_rid + challenge fields to DB
# - Keeps existing /healthz, /metrics, register_web, status, update endpoints

from __future__ import annotations

import base64
import logging
import os
import secrets
import time
from collections import deque
from contextlib import contextmanager
from typing import Deque, Dict, Optional

from fastapi import FastAPI, Header, HTTPException, Request, Response
from pydantic import BaseModel, Field
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest
from psycopg_pool import ConnectionPool
from psycopg.rows import dict_row

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


# -------------------- CONFIG --------------------

REF_TARGET = int(os.getenv("AIRDROP_REF_TARGET", "5"))
SITE_ORIGIN = (os.getenv("AIRDROP_SITE_ORIGIN", "https://mw-expedition.com") or "https://mw-expedition.com").rstrip("/")
AIRDROP_API_KEY = (os.getenv("AIRDROP_API_KEY", "") or "").strip()

DB_DSN = (os.getenv("AIRDROP_DB_DSN") or os.getenv("AIRDROP_PG_DSN") or "").strip()
if not DB_DSN:
    raise RuntimeError("AIRDROP_DB_DSN (or AIRDROP_PG_DSN) is required")

DB_POOL_MIN = int(os.getenv("AIRDROP_DB_POOL_MIN", "1"))
DB_POOL_MAX = int(os.getenv("AIRDROP_DB_POOL_MAX", "10"))

WALLET_CHALLENGE_TTL = int(os.getenv("AIRDROP_WALLET_CHALLENGE_TTL", "600"))  # seconds

RATE_WINDOW_SEC = int(os.getenv("AIRDROP_RATE_WINDOW_SEC", "60"))
RATE_REGISTER_PER_IP = int(os.getenv("AIRDROP_RATE_REGISTER_PER_IP", "12"))
RATE_STATUS_PER_TOKEN = int(os.getenv("AIRDROP_RATE_STATUS_PER_TOKEN", "30"))
RATE_WALLET_PER_TOKEN = int(os.getenv("AIRDROP_RATE_WALLET_PER_TOKEN", "10"))
RATE_UPDATE_PER_TOKEN = int(os.getenv("AIRDROP_RATE_UPDATE_PER_TOKEN", "10"))


# -------------------- LOGGING --------------------

log = logging.getLogger("airdrop-api")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")


# -------------------- DB --------------------

POOL = ConnectionPool(
    conninfo=DB_DSN,
    min_size=DB_POOL_MIN,
    max_size=DB_POOL_MAX,
    kwargs={"row_factory": dict_row},
)

@contextmanager
def get_cursor():
    with POOL.connection() as conn:
        with conn.cursor() as cur:
            yield conn, cur


def init_db() -> None:
    now = int(time.time())
    with get_cursor() as (conn, cur):
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS airdrop_users (
              id            BIGSERIAL PRIMARY KEY,
              token         TEXT UNIQUE NOT NULL,
              ref_token     TEXT,
              wallet_bound  BOOLEAN NOT NULL DEFAULT FALSE,
              telegram_ok   BOOLEAN NOT NULL DEFAULT FALSE,
              twitter_follow   BOOLEAN NOT NULL DEFAULT FALSE,
              twitter_like     BOOLEAN NOT NULL DEFAULT FALSE,
              twitter_retweet  BOOLEAN NOT NULL DEFAULT FALSE,
              referrals     INTEGER NOT NULL DEFAULT 0,
              points        INTEGER NOT NULL DEFAULT 0,
              created_at    BIGINT NOT NULL,
              updated_at    BIGINT NOT NULL
            );
            """
        )

        # Wallet binding extensions (safe migrations)
        cur.execute("ALTER TABLE airdrop_users ADD COLUMN IF NOT EXISTS wallet_rid TEXT;")
        cur.execute("ALTER TABLE airdrop_users ADD COLUMN IF NOT EXISTS wallet_bound_at BIGINT NOT NULL DEFAULT 0;")
        cur.execute("ALTER TABLE airdrop_users ADD COLUMN IF NOT EXISTS wallet_challenge TEXT;")
        cur.execute("ALTER TABLE airdrop_users ADD COLUMN IF NOT EXISTS wallet_challenge_exp BIGINT NOT NULL DEFAULT 0;")

        # Indexes
        cur.execute("CREATE INDEX IF NOT EXISTS idx_airdrop_points ON airdrop_users(points DESC);")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_airdrop_token ON airdrop_users(token);")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_airdrop_ref_token ON airdrop_users(ref_token);")

        # Prevent same wallet being bound to multiple accounts (partial unique index)
        cur.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_airdrop_wallet_rid_unique "
            "ON airdrop_users(wallet_rid) WHERE wallet_rid IS NOT NULL;"
        )

        conn.commit()

    log.info("airdrop-api db init ok (ts=%s)", now)


# -------------------- METRICS --------------------

REQS = Counter("airdrop_http_requests_total", "HTTP requests", ["path", "method", "status"])
LAT = Histogram("airdrop_http_request_duration_seconds", "HTTP request latency", ["path", "method"])

REG_TOTAL = Counter("airdrop_register_total", "Register attempts", ["result"])
STATUS_TOTAL = Counter("airdrop_status_total", "Status calls", ["result"])
WCH_TOTAL = Counter("airdrop_wallet_challenge_total", "Wallet challenge calls", ["result"])
WBIND_TOTAL = Counter("airdrop_wallet_bind_total", "Wallet bind calls", ["result"])
UPDATE_TOTAL = Counter("airdrop_update_total", "Update calls", ["result"])


# -------------------- RATE LIMIT (soft, per-worker) --------------------

_buckets: Dict[str, Deque[float]] = {}

def _rate_ok(key: str, limit: int) -> bool:
    now = time.monotonic()
    b = _buckets.setdefault(key, deque())
    while b and (now - b[0]) > RATE_WINDOW_SEC:
        b.popleft()
    if len(b) >= limit:
        return False
    b.append(now)
    return True


# -------------------- HELPERS --------------------

def get_ip(request: Request) -> str:
    xf = request.headers.get("x-forwarded-for", "")
    if xf:
        return xf.split(",")[0].strip()
    return request.client.host if request.client else "0.0.0.0"

_B58_ALPH = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_IDX = {c: i for i, c in enumerate(_B58_ALPH)}

def b58decode(s: str) -> bytes:
    s = (s or "").strip()
    if not s:
        return b""
    num = 0
    for ch in s:
        if ch not in _B58_IDX:
            raise ValueError("invalid base58 char")
        num = num * 58 + _B58_IDX[ch]
    pad = 0
    for ch in s:
        if ch == "1":
            pad += 1
        else:
            break
    full = num.to_bytes((num.bit_length() + 7) // 8, "big") if num > 0 else b""
    return (b"\x00" * pad) + full

def b64url_decode(s: str) -> bytes:
    s = (s or "").strip()
    if not s:
        return b""
    s = s.replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    return base64.b64decode(s.encode("ascii"))

def compute_points(wallet_bound: bool, telegram_ok: bool, twitter_follow: bool, twitter_like: bool, twitter_retweet: bool, referrals: int) -> int:
    flags = int(wallet_bound) + int(telegram_ok) + int(twitter_follow) + int(twitter_like) + int(twitter_retweet)
    refs = min(int(referrals or 0), REF_TARGET)
    return flags * 20 + refs * 10

def verify_wallet_signature(rid: str, challenge: str, sig_b64url: str) -> None:
    try:
        pub = b58decode(rid)
    except Exception:
        raise HTTPException(status_code=400, detail="RID is not valid base58")
    if len(pub) != 32:
        raise HTTPException(status_code=400, detail="RID must decode to 32 bytes (ed25519 public key)")

    sig = b64url_decode(sig_b64url)
    if len(sig) != 64:
        raise HTTPException(status_code=400, detail="signature must be 64 bytes (base64url)")

    pk = Ed25519PublicKey.from_public_bytes(pub)
    msg = (challenge or "").encode("utf-8")
    try:
        pk.verify(sig, msg)
    except InvalidSignature:
        raise HTTPException(status_code=400, detail="invalid signature")


# -------------------- MODELS --------------------

class RegisterRequest(BaseModel):
    ref_token: Optional[str] = Field(default=None, description="Referral token (optional)")

class RegisterResponse(BaseModel):
    ok: bool = True
    token: str

class StatusRequest(BaseModel):
    token: str

class AirdropStatus(BaseModel):
    ok: bool = True
    token: str
    points: int
    referrals: int
    ref_target: int

    wallet_bound: bool
    wallet_rid: Optional[str] = None

    telegram_ok: bool
    twitter_follow: bool
    twitter_like: bool
    twitter_retweet: bool

    rank: int
    total: int

    site_origin: str = SITE_ORIGIN

class UpdateRequest(BaseModel):
    token: str
    wallet_bound: Optional[bool] = None
    telegram_ok: Optional[bool] = None
    twitter_follow: Optional[bool] = None
    twitter_like: Optional[bool] = None
    twitter_retweet: Optional[bool] = None
    referrals: Optional[int] = None

class WalletChallengeRequest(BaseModel):
    token: str

class WalletChallengeResponse(BaseModel):
    ok: bool = True
    challenge: str
    expires_in: int

class BindWalletRequest(BaseModel):
    token: str
    rid: str
    sig: str
    challenge: Optional[str] = None


# -------------------- APP --------------------

app = FastAPI(title="LOGOS Airdrop API", version="1.1.0")


@app.on_event("startup")
def _startup():
    init_db()
    log.info("airdrop-api started")


@app.middleware("http")
async def _metrics_mw(request: Request, call_next):
    path = request.url.path
    method = request.method
    start = time.perf_counter()
    status = "500"
    try:
        resp = await call_next(request)
        status = str(resp.status_code)
        return resp
    finally:
        dur = time.perf_counter() - start
        LAT.labels(path=path, method=method).observe(dur)
        REQS.labels(path=path, method=method, status=status).inc()


@app.get("/healthz")
def healthz():
    return {"ok": True, "service": "airdrop-api"}


@app.get("/metrics")
def metrics():
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)


def _status_for_token(token: str) -> AirdropStatus:
    with get_cursor() as (conn, cur):
        cur.execute("SELECT * FROM airdrop_users WHERE token=%s", (token,))
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="token not found")

        wallet_bound = bool(row.get("wallet_bound"))
        telegram_ok = bool(row.get("telegram_ok"))
        twitter_follow = bool(row.get("twitter_follow"))
        twitter_like = bool(row.get("twitter_like"))
        twitter_retweet = bool(row.get("twitter_retweet"))
        referrals = int(row.get("referrals") or 0)

        points = int(row.get("points") or 0)
        if points == 0 and (wallet_bound or telegram_ok or twitter_follow or twitter_like or twitter_retweet or referrals):
            points = compute_points(wallet_bound, telegram_ok, twitter_follow, twitter_like, twitter_retweet, referrals)
            cur.execute("UPDATE airdrop_users SET points=%s, updated_at=%s WHERE token=%s", (points, int(time.time()), token))
            conn.commit()

        cur.execute("SELECT COUNT(*) AS n FROM airdrop_users")
        total = int((cur.fetchone() or {}).get("n") or 0)

        cur.execute("SELECT COUNT(*) AS better FROM airdrop_users WHERE points > %s", (points,))
        better = int((cur.fetchone() or {}).get("better") or 0)
        rank = better + 1

        return AirdropStatus(
            token=token,
            points=points,
            referrals=min(referrals, REF_TARGET),
            ref_target=REF_TARGET,
            wallet_bound=wallet_bound,
            wallet_rid=row.get("wallet_rid"),
            telegram_ok=telegram_ok,
            twitter_follow=twitter_follow,
            twitter_like=twitter_like,
            twitter_retweet=twitter_retweet,
            rank=rank,
            total=total,
        )


@app.post("/api/airdrop/register_web", response_model=RegisterResponse)
def register_web(req: RegisterRequest, request: Request):
    ip = get_ip(request)
    if not _rate_ok(f"reg:{ip}", RATE_REGISTER_PER_IP):
        REG_TOTAL.labels(result="rate_limited").inc()
        raise HTTPException(status_code=429, detail="rate limit: register")

    now = int(time.time())
    token = secrets.token_urlsafe(16)

    with get_cursor() as (conn, cur):
        cur.execute(
            """
            INSERT INTO airdrop_users(token, ref_token, created_at, updated_at)
            VALUES (%s, %s, %s, %s)
            """,
            (token, (req.ref_token or None), now, now),
        )

        # atomic referral increment
        if req.ref_token:
            cur.execute("SELECT * FROM airdrop_users WHERE token=%s FOR UPDATE", (req.ref_token,))
            ref_row = cur.fetchone()
            if ref_row:
                new_refs = min(REF_TARGET, int(ref_row.get("referrals") or 0) + 1)
                new_points = compute_points(
                    bool(ref_row.get("wallet_bound")),
                    bool(ref_row.get("telegram_ok")),
                    bool(ref_row.get("twitter_follow")),
                    bool(ref_row.get("twitter_like")),
                    bool(ref_row.get("twitter_retweet")),
                    new_refs,
                )
                cur.execute(
                    "UPDATE airdrop_users SET referrals=%s, points=%s, updated_at=%s WHERE token=%s",
                    (new_refs, new_points, now, req.ref_token),
                )

        conn.commit()

    REG_TOTAL.labels(result="ok").inc()
    return RegisterResponse(ok=True, token=token)


@app.post("/api/airdrop/status", response_model=AirdropStatus)
def status(req: StatusRequest, request: Request):
    tok = (req.token or "").strip()
    if not tok:
        STATUS_TOTAL.labels(result="bad_req").inc()
        raise HTTPException(status_code=400, detail="token required")

    ip = get_ip(request)
    if not _rate_ok(f"st:{tok}:{ip}", RATE_STATUS_PER_TOKEN):
        STATUS_TOTAL.labels(result="rate_limited").inc()
        raise HTTPException(status_code=429, detail="rate limit: status")

    STATUS_TOTAL.labels(result="ok").inc()
    return _status_for_token(tok)


@app.post("/api/airdrop/wallet_challenge", response_model=WalletChallengeResponse)
def wallet_challenge(req: WalletChallengeRequest, request: Request):
    tok = (req.token or "").strip()
    if not tok:
        WCH_TOTAL.labels(result="bad_req").inc()
        raise HTTPException(status_code=400, detail="token required")

    ip = get_ip(request)
    if not _rate_ok(f"wch:{tok}:{ip}", RATE_WALLET_PER_TOKEN):
        WCH_TOTAL.labels(result="rate_limited").inc()
        raise HTTPException(status_code=429, detail="rate limit: wallet_challenge")

    now = int(time.time())
    exp = now + WALLET_CHALLENGE_TTL
    nonce = secrets.token_urlsafe(16)
    challenge = f"LOGOS_AIRDROP_BIND|token={tok}|ts={now}|nonce={nonce}"

    with get_cursor() as (conn, cur):
        cur.execute("SELECT token FROM airdrop_users WHERE token=%s", (tok,))
        if not cur.fetchone():
            WCH_TOTAL.labels(result="not_found").inc()
            raise HTTPException(status_code=404, detail="token not found")

        cur.execute(
            "UPDATE airdrop_users SET wallet_challenge=%s, wallet_challenge_exp=%s, updated_at=%s WHERE token=%s",
            (challenge, exp, now, tok),
        )
        conn.commit()

    WCH_TOTAL.labels(result="ok").inc()
    return WalletChallengeResponse(ok=True, challenge=challenge, expires_in=WALLET_CHALLENGE_TTL)


@app.post("/api/airdrop/bind_wallet", response_model=AirdropStatus)
def bind_wallet(req: BindWalletRequest, request: Request):
    tok = (req.token or "").strip()
    rid = (req.rid or "").strip()
    sig = (req.sig or "").strip()

    if not tok or not rid or not sig:
        WBIND_TOTAL.labels(result="bad_req").inc()
        raise HTTPException(status_code=400, detail="token, rid, sig are required")

    ip = get_ip(request)
    if not _rate_ok(f"wbind:{tok}:{ip}", RATE_WALLET_PER_TOKEN):
        WBIND_TOTAL.labels(result="rate_limited").inc()
        raise HTTPException(status_code=429, detail="rate limit: bind_wallet")

    now = int(time.time())
    with get_cursor() as (conn, cur):
        cur.execute("SELECT * FROM airdrop_users WHERE token=%s FOR UPDATE", (tok,))
        row = cur.fetchone()
        if not row:
            WBIND_TOTAL.labels(result="not_found").inc()
            raise HTTPException(status_code=404, detail="token not found")

        if bool(row.get("wallet_bound")):
            WBIND_TOTAL.labels(result="already").inc()
            conn.commit()
            return _status_for_token(tok)

        ch = (row.get("wallet_challenge") or "").strip()
        exp = int(row.get("wallet_challenge_exp") or 0)
        if not ch or exp < now:
            WBIND_TOTAL.labels(result="no_challenge").inc()
            raise HTTPException(status_code=400, detail="challenge missing or expired; call wallet_challenge again")

        if req.challenge and req.challenge.strip() != ch:
            WBIND_TOTAL.labels(result="challenge_mismatch").inc()
            raise HTTPException(status_code=400, detail="challenge mismatch; refresh challenge")

        cur.execute("SELECT token FROM airdrop_users WHERE wallet_rid=%s AND token<>%s", (rid, tok))
        if cur.fetchone():
            WBIND_TOTAL.labels(result="wallet_taken").inc()
            raise HTTPException(status_code=409, detail="this wallet RID is already bound to another airdrop token")

        verify_wallet_signature(rid, ch, sig)

        telegram_ok = bool(row.get("telegram_ok"))
        twitter_follow = bool(row.get("twitter_follow"))
        twitter_like = bool(row.get("twitter_like"))
        twitter_retweet = bool(row.get("twitter_retweet"))
        referrals = int(row.get("referrals") or 0)

        points = compute_points(True, telegram_ok, twitter_follow, twitter_like, twitter_retweet, referrals)

        cur.execute(
            """
            UPDATE airdrop_users
            SET wallet_bound=TRUE,
                wallet_rid=%s,
                wallet_bound_at=%s,
                wallet_challenge=NULL,
                wallet_challenge_exp=0,
                points=%s,
                updated_at=%s
            WHERE token=%s
            """,
            (rid, now, points, now, tok),
        )
        conn.commit()

    WBIND_TOTAL.labels(result="ok").inc()
    return _status_for_token(tok)


@app.post("/api/airdrop/update", response_model=AirdropStatus)
def update(req: UpdateRequest, request: Request, x_api_key: Optional[str] = Header(default=None, alias="x-api-key")):
    if not AIRDROP_API_KEY:
        UPDATE_TOTAL.labels(result="server_misconf").inc()
        raise HTTPException(status_code=500, detail="AIRDROP_API_KEY is not set")
    if (x_api_key or "").strip() != AIRDROP_API_KEY:
        UPDATE_TOTAL.labels(result="unauthorized").inc()
        raise HTTPException(status_code=401, detail="bad api key")

    tok = (req.token or "").strip()
    if not tok:
        UPDATE_TOTAL.labels(result="bad_req").inc()
        raise HTTPException(status_code=400, detail="token required")

    ip = get_ip(request)
    if not _rate_ok(f"upd:{tok}:{ip}", RATE_UPDATE_PER_TOKEN):
        UPDATE_TOTAL.labels(result="rate_limited").inc()
        raise HTTPException(status_code=429, detail="rate limit: update")

    now = int(time.time())
    with get_cursor() as (conn, cur):
        cur.execute("SELECT * FROM airdrop_users WHERE token=%s FOR UPDATE", (tok,))
        row = cur.fetchone()
        if not row:
            UPDATE_TOTAL.labels(result="not_found").inc()
            raise HTTPException(status_code=404, detail="token not found")

        wallet_bound = bool(row.get("wallet_bound"))
        wallet_rid = row.get("wallet_rid")
        wallet_bound_at = int(row.get("wallet_bound_at") or 0)

        telegram_ok = bool(row.get("telegram_ok"))
        twitter_follow = bool(row.get("twitter_follow"))
        twitter_like = bool(row.get("twitter_like"))
        twitter_retweet = bool(row.get("twitter_retweet"))
        referrals = int(row.get("referrals") or 0)

        if req.wallet_bound is not None:
            wallet_bound = bool(req.wallet_bound)
            if not wallet_bound:
                wallet_rid = None
                wallet_bound_at = 0

        if req.telegram_ok is not None:
            telegram_ok = bool(req.telegram_ok)
        if req.twitter_follow is not None:
            twitter_follow = bool(req.twitter_follow)
        if req.twitter_like is not None:
            twitter_like = bool(req.twitter_like)
        if req.twitter_retweet is not None:
            twitter_retweet = bool(req.twitter_retweet)

        if req.referrals is not None:
            referrals = max(referrals, int(req.referrals))
        referrals = min(referrals, REF_TARGET)

        points = compute_points(wallet_bound, telegram_ok, twitter_follow, twitter_like, twitter_retweet, referrals)

        cur.execute(
            """
            UPDATE airdrop_users
            SET wallet_bound=%s,
                wallet_rid=%s,
                wallet_bound_at=%s,
                telegram_ok=%s,
                twitter_follow=%s,
                twitter_like=%s,
                twitter_retweet=%s,
                referrals=%s,
                points=%s,
                updated_at=%s
            WHERE token=%s
            """,
            (wallet_bound, wallet_rid, wallet_bound_at, telegram_ok, twitter_follow, twitter_like, twitter_retweet, referrals, points, now, tok),
        )
        conn.commit()

    UPDATE_TOTAL.labels(result="ok").inc()
    return _status_for_token(tok)

# --- X bind + verify (mainnet hardening) -------------------------------------

import json
import time
import urllib.request
from pydantic import BaseModel, Field
from psycopg_pool import ConnectionPool

X_GUARD_URL = (os.getenv("X_GUARD_URL", "http://127.0.0.1:8091").strip().rstrip("/"))
X_PROJECT_USERNAME = os.getenv("X_PROJECT_USERNAME", "RspLogos").strip().lstrip("@")

_X_DSN = (os.getenv("AIRDROP_DB_DSN") or os.getenv("AIRDROP_PG_DSN") or "").strip()
if not _X_DSN:
    # в твоём app.py это уже должно быть, но пусть будет защита
    raise RuntimeError("AIRDROP_DB_DSN (or AIRDROP_PG_DSN) is required")

# отдельный пул только для x-bind/verify (не ломаем текущую архитектуру)
_X_POOL = ConnectionPool(
    conninfo=_X_DSN,
    min_size=1,
    max_size=10,
    timeout=5,
    kwargs={"row_factory": dict_row},
)

def _norm_x_username(s: str) -> str:
    s = (s or "").strip()
    if s.startswith("@"):
        s = s[1:]
    # если вставили ссылку вида https://x.com/name — вытащим name
    s = s.replace("https://x.com/", "").replace("http://x.com/", "")
    s = s.replace("https://twitter.com/", "").replace("http://twitter.com/", "")
    s = s.split("?")[0].split("/")[0].strip()
    s = s.lower()
    if not s or len(s) > 32:
        raise ValueError("bad twitter_username")
    return s

def _now() -> int:
    return int(time.time())

def _compute_points_fallback(wallet_bound: bool, telegram_ok: bool, twitter_follow: bool, twitter_like: bool, twitter_retweet: bool, referrals: int) -> int:
    # если в app.py уже есть compute_points — используем его, иначе fallback
    try:
        return int(compute_points(wallet_bound, telegram_ok, twitter_follow, twitter_like, twitter_retweet, referrals))  # type: ignore
    except Exception:
        flags = int(wallet_bound) + int(telegram_ok) + int(twitter_follow) + int(twitter_like) + int(twitter_retweet)
        return int(flags + int(referrals or 0))

def _status_for_token_safe(tok: str):
    # если у тебя уже есть _status_for_token — используем его
    try:
        return _status_for_token(tok)  # type: ignore
    except Exception:
        # fallback status (минимум для UI)
        with _X_POOL.connection() as c:
            row = c.execute("""
                SELECT token,wallet_bound,telegram_ok,twitter_follow,twitter_like,twitter_retweet,referrals,points,updated_at
                FROM airdrop_users WHERE token=%s
            """, (tok,)).fetchone()
            if not row:
                raise RuntimeError("token not found")
            # rank (простая версия)
            r = c.execute("""
                SELECT 1 + COUNT(*) FROM airdrop_users
                WHERE (points > %s) OR (points=%s AND updated_at > %s)
            """, (row["points"], row["points"], row["updated_at"])).fetchone()
            rank = int(r[0]) if r else 1
        return {
            "ok": True,
            "token": tok,
            "wallet_bound": bool(row["wallet_bound"]),
            "telegram_ok": bool(row["telegram_ok"]),
            "twitter_follow": bool(row["twitter_follow"]),
            "twitter_like": bool(row["twitter_like"]),
            "twitter_retweet": bool(row["twitter_retweet"]),
            "referrals": int(row["referrals"]),
            "points": int(row["points"]),
            "rank": int(rank),
        }

def _x_guard_check(user_username: str) -> dict:
    payload = {
        "user_username": user_username,
        "project_username": X_PROJECT_USERNAME,
        "tweet_id": "any",
        "require_follow": True,
        "require_like": True,
        "require_retweet": True
    }
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        f"{X_GUARD_URL}/check_airdrop",
        data=data,
        headers={"content-type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=25) as resp:
        body = resp.read().decode("utf-8", "replace")
    return json.loads(body)

class SetXUsernameRequest(BaseModel):
    token: str = Field(..., min_length=8, max_length=128)
    twitter_username: str = Field(..., min_length=1, max_length=128)

class VerifyXRequest(BaseModel):
    token: str = Field(..., min_length=8, max_length=128)

@app.post("/api/airdrop/set_x_username")
def set_x_username(req: SetXUsernameRequest):
    """
    Save X username ONLY (no x_guard calls here) to avoid timeouts/rate limits.
    """
    import psycopg
    tok = req.token.strip()
    uname = _norm_x_username(req.twitter_username)
    now = _now()

    with psycopg.connect(_X_DSN, row_factory=dict_row) as c:
        cur = c.execute("""
            UPDATE airdrop_users
               SET twitter_username=%s,
                   updated_at=%s
             WHERE token=%s
        """, (uname, now, tok))
        if cur.rowcount != 1:
            raise HTTPException(status_code=404, detail="token_not_found")

    return _status_for_token_safe(tok)


@app.post("/api/airdrop/verify_x")
def verify_x(req: VerifyXRequest):
    """
    Verify X tasks via local x_guard. Never crash with 500 on x_guard errors.
    """
    import psycopg

    tok = req.token.strip()
    now = _now()

    with psycopg.connect(_X_DSN, row_factory=dict_row) as c:
        row = c.execute("""
            SELECT token,twitter_username,
                   wallet_bound,telegram_ok,
                   twitter_follow,twitter_like,twitter_retweet,
                   referrals,points,
                   twitter_checked_at
            FROM airdrop_users WHERE token=%s
        """, (tok,)).fetchone()

    if not row:
        raise HTTPException(status_code=404, detail="token_not_found")

    uname = (row.get("twitter_username") or "").strip()
    if not uname:
        return {"ok": False, "error": "x_username_required", "message": "Set X username first"}

    last = int(row.get("twitter_checked_at") or 0)
    if now - last < 30:
        return _status_for_token_safe(tok)

    try:
        res = _x_guard_check(uname)
    except Exception as e:
        with psycopg.connect(_X_DSN, row_factory=dict_row) as c:
            c.execute("UPDATE airdrop_users SET twitter_checked_at=%s, updated_at=%s WHERE token=%s", (now, now, tok))
        return {"ok": False, "error": "x_guard_failed", "message": str(e)}

    if not isinstance(res, dict):
        with psycopg.connect(_X_DSN, row_factory=dict_row) as c:
            c.execute("UPDATE airdrop_users SET twitter_checked_at=%s, updated_at=%s WHERE token=%s", (now, now, tok))
        return {"ok": False, "error": "x_guard_bad_response", "message": "not a dict"}

    if not bool(res.get("ok", False)):
        msg = str(res.get("message") or res.get("error") or "x_guard_failed")
        with psycopg.connect(_X_DSN, row_factory=dict_row) as c:
            c.execute("UPDATE airdrop_users SET twitter_checked_at=%s, updated_at=%s WHERE token=%s", (now, now, tok))
        return {"ok": False, "error": "x_guard_failed", "message": msg}

    follow_ok = bool(res.get("follow_ok"))
    like_ok = bool(res.get("like_ok"))
    retweet_ok = bool(res.get("retweet_ok"))

    new_follow = bool(row.get("twitter_follow")) or follow_ok
    new_like = bool(row.get("twitter_like")) or like_ok
    new_rt = bool(row.get("twitter_retweet")) or retweet_ok

    new_points = _compute_points_fallback(
        bool(row.get("wallet_bound")),
        bool(row.get("telegram_ok")),
        new_follow, new_like, new_rt,
        int(row.get("referrals") or 0),
    )

    with psycopg.connect(_X_DSN, row_factory=dict_row) as c:
        c.execute("""
            UPDATE airdrop_users
               SET twitter_follow=%s,
                   twitter_like=%s,
                   twitter_retweet=%s,
                   twitter_checked_at=%s,
                   points=%s,
                   updated_at=%s
             WHERE token=%s
        """, (new_follow, new_like, new_rt, now, new_points, now, tok))

    out = _status_for_token_safe(tok)
    out["details"] = res.get("details", {})
    return out

```

---

### `/opt/logos/airdrop-api/db_migrate_airdrop_sqlite_to_postgres.py`

```python
#!/usr/bin/env python3
"""
One-shot миграция: SQLite airdrop.sqlite3 -> Postgres logos_airdrop.

    AIRDROP_DB_DSN="postgresql://logos_airdrop:pass@127.0.0.1:5432/logos_airdrop" \
    AIRDROP_SQLITE_PATH="/opt/logos/airdrop-api/airdrop.sqlite3" \
    python3 db_migrate_airdrop_sqlite_to_postgres.py
"""

import os
import sqlite3
from datetime import datetime, timezone
from typing import Dict, Any, List

import psycopg2

REF_TARGET = int(os.getenv("AIRDROP_REF_TARGET", "5"))
SQLITE_PATH = os.getenv("AIRDROP_SQLITE_PATH", "/opt/logos/airdrop-api/airdrop.sqlite3")
PG_DSN = os.getenv(
    "AIRDROP_DB_DSN",
    "postgresql://logos_airdrop:change_me@127.0.0.1:5432/logos_airdrop",
)


def compute_points(
    wallet_bound: bool,
    telegram_ok: bool,
    twitter_follow: bool,
    twitter_like: bool,
    twitter_retweet: bool,
    referrals: int,
) -> int:
    base = 0
    if wallet_bound:
        base += 10
    if telegram_ok:
        base += 10
    if twitter_follow:
        base += 10
    if twitter_like:
        base += 10
    if twitter_retweet:
        base += 10

    refs_eff = max(0, min(referrals, REF_TARGET))
    return base + refs_eff * 10


def load_sqlite() -> List[Dict[str, Any]]:
    conn = sqlite3.connect(SQLITE_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("SELECT * FROM airdrop_users")
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


def main() -> None:
    rows = load_sqlite()
    if not rows:
        print("No rows in SQLite airdrop_users, nothing to migrate.")
        return

    by_token: Dict[str, Dict[str, Any]] = {r["token"]: r for r in rows}
    children_by_parent: Dict[str, List[Dict[str, Any]]] = {}
    for r in rows:
        ref_token = r.get("ref_token")
        if ref_token:
            children_by_parent.setdefault(ref_token, []).append(r)

    for r in rows:
        token = r["token"]
        children = children_by_parent.get(token, [])
        completed_children = [
            c
            for c in children
            if c.get("wallet_bound")
            and c.get("telegram_ok")
            and c.get("twitter_follow")
            and c.get("twitter_like")
            and c.get("twitter_retweet")
        ]
        refs_eff = min(len(completed_children), REF_TARGET)
        r["referrals_eff"] = refs_eff
        r["points_eff"] = compute_points(
            bool(r.get("wallet_bound")),
            bool(r.get("telegram_ok")),
            bool(r.get("twitter_follow")),
            bool(r.get("twitter_like")),
            bool(r.get("twitter_retweet")),
            refs_eff,
        )

    pg = psycopg2.connect(PG_DSN)
    pg.autocommit = False
    cur = pg.cursor()

    for r in rows:
        created_at = r.get("created_at")
        updated_at = r.get("updated_at")
        if isinstance(created_at, (int, float)):
            created_at_dt = datetime.fromtimestamp(created_at, tz=timezone.utc)
        else:
            created_at_dt = datetime.now(tz=timezone.utc)
        if isinstance(updated_at, (int, float)):
            updated_at_dt = datetime.fromtimestamp(updated_at, tz=timezone.utc)
        else:
            updated_at_dt = created_at_dt

        cur.execute(
            """
            INSERT INTO airdrop_users (
                token,
                ref_token,
                wallet_bound,
                telegram_ok,
                twitter_follow,
                twitter_like,
                twitter_retweet,
                referrals,
                points,
                created_at,
                updated_at
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (token) DO UPDATE
            SET ref_token = EXCLUDED.ref_token,
                wallet_bound = EXCLUDED.wallet_bound,
                telegram_ok = EXCLUDED.telegram_ok,
                twitter_follow = EXCLUDED.twitter_follow,
                twitter_like = EXCLUDED.twitter_like,
                twitter_retweet = EXCLUDED.twitter_retweet,
                referrals = EXCLUDED.referrals,
                points = EXCLUDED.points,
                created_at = LEAST(airdrop_users.created_at, EXCLUDED.created_at),
                updated_at = GREATEST(airdrop_users.updated_at, EXCLUDED.updated_at)
            """,
            (
                r["token"],
                r.get("ref_token"),
                bool(r.get("wallet_bound")),
                bool(r.get("telegram_ok")),
                bool(r.get("twitter_follow")),
                bool(r.get("twitter_like")),
                bool(r.get("twitter_retweet")),
                int(r.get("referrals_eff", 0)),
                int(r.get("points_eff", 0)),
                created_at_dt,
                updated_at_dt,
            ),
        )

    pg.commit()
    cur.close()
    pg.close()
    print(f"Migrated {len(rows)} users from SQLite to Postgres.")


if __name__ == "__main__":
    main()

```

---

### `/opt/logos/airdrop-api/x_bind.py`

```python
from __future__ import annotations

import os
import time
import json
import urllib.request
import urllib.parse
from typing import Any, Dict

import psycopg
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field


router = APIRouter(prefix="/api/airdrop", tags=["x-guard"])

DB_DSN = (os.getenv("AIRDROP_DB_DSN") or os.getenv("AIRDROP_PG_DSN") or "").strip()
if not DB_DSN:
    raise RuntimeError("AIRDROP_DB_DSN (or AIRDROP_PG_DSN) is required")

POOL = ConnectionPool(
    conninfo=DB_DSN,
    min_size=1,
    max_size=int(os.getenv("AIRDROP_X_POOL_MAX", "10")),
    timeout=5,
    kwargs={"row_factory": dict_row},
)

X_GUARD_URL = (os.getenv("X_GUARD_URL", "http://127.0.0.1:8091").strip().rstrip("/"))
X_PROJECT_USERNAME = os.getenv("X_PROJECT_USERNAME", "RspLogos").strip().lstrip("@")
THROTTLE_SEC = int(os.getenv("X_VERIFY_THROTTLE_SEC", "30"))


def _now() -> int:
    return int(time.time())


def compute_points(wallet_bound: bool, telegram_ok: bool, twitter_follow: bool, twitter_like: bool, twitter_retweet: bool, referrals: int) -> int:
    flags = int(wallet_bound) + int(telegram_ok) + int(twitter_follow) + int(twitter_like) + int(twitter_retweet)
    return int(flags + int(referrals or 0))


def _norm_x_username(s: str) -> str:
    s = (s or "").strip()
    if s.startswith("@"):
        s = s[1:]

    s = s.replace("https://x.com/", "").replace("http://x.com/", "")
    s = s.replace("https://twitter.com/", "").replace("http://twitter.com/", "")
    s = s.split("?")[0].split("/")[0].strip().lower()

    if not s or len(s) > 32:
        raise ValueError("bad twitter_username")

    for ch in s:
        if not (ch.isalnum() or ch == "_"):
            raise ValueError("bad twitter_username")

    return s


def _rank_for(points: int, updated_at: int) -> int:
    with POOL.connection() as c:
        r = c.execute(
            """
            SELECT 1 + COUNT(*) AS rank
            FROM airdrop_users
            WHERE (points > %s) OR (points=%s AND updated_at > %s)
            """,
            (points, points, updated_at),
        ).fetchone()
    return int(r["rank"]) if r else 1


def status_for_token(tok: str) -> Dict[str, Any]:
    with POOL.connection() as c:
        row = c.execute(
            """
            SELECT token,wallet_bound,wallet_rid,telegram_ok,
                   twitter_follow,twitter_like,twitter_retweet,
                   referrals,points,updated_at,
                   twitter_username,twitter_checked_at
            FROM airdrop_users WHERE token=%s
            """,
            (tok,),
        ).fetchone()

    if not row:
        raise HTTPException(status_code=404, detail="token not found")

    rank = _rank_for(int(row["points"]), int(row["updated_at"]))
    return {
        "ok": True,
        "token": tok,
        "wallet_bound": bool(row["wallet_bound"]),
        "wallet_rid": row.get("wallet_rid"),
        "telegram_ok": bool(row["telegram_ok"]),
        "twitter_follow": bool(row["twitter_follow"]),
        "twitter_like": bool(row["twitter_like"]),
        "twitter_retweet": bool(row["twitter_retweet"]),
        "twitter_username": row.get("twitter_username"),
        "twitter_checked_at": int(row.get("twitter_checked_at") or 0),
        "referrals": int(row["referrals"]),
        "points": int(row["points"]),
        "rank": int(rank),
    }


def x_guard_check(user_username: str) -> Dict[str, Any]:
    payload = {
        "user_username": user_username,
        "project_username": X_PROJECT_USERNAME,
        "tweet_id": "any",
        "mode": "any",
        "require_follow": True,
        "require_like": True,
        "require_retweet": True,
    }

    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        f"{X_GUARD_URL}/check_airdrop",
        data=data,
        headers={"content-type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=25) as resp:
            body = resp.read().decode("utf-8", "replace")
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"x_guard_unreachable: {e}")

    try:
        return json.loads(body)
    except Exception:
        raise HTTPException(status_code=502, detail=f"x_guard_bad_json: {body[:200]}")


class SetXUsernameRequest(BaseModel):
    token: str = Field(..., min_length=8, max_length=128)
    twitter_username: str = Field(..., min_length=1, max_length=128)


@router.post("/set_x_username")
def set_x_username(req: SetXUsernameRequest):
    tok = req.token.strip()
    try:
        uname = _norm_x_username(req.twitter_username)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

    now = _now()
    try:
        with POOL.connection() as c:
            cur = c.execute(
                """
                UPDATE airdrop_users
                   SET twitter_username=%s,
                       updated_at=%s
                 WHERE token=%s
                """,
                (uname, now, tok),
            )
            if cur.rowcount != 1:
                raise HTTPException(status_code=404, detail="token not found")
    except psycopg.errors.UniqueViolation:
        raise HTTPException(status_code=409, detail="twitter_username already bound")

    return status_for_token(tok)


class VerifyXRequest(BaseModel):
    token: str = Field(..., min_length=8, max_length=128)


@router.post("/verify_x")
def verify_x(req: VerifyXRequest):
    tok = req.token.strip()
    now = _now()

    with POOL.connection() as c:
        row = c.execute(
            """
            SELECT token,twitter_username,twitter_checked_at,
                   wallet_bound,telegram_ok,
                   twitter_follow,twitter_like,twitter_retweet,
                   referrals,updated_at
            FROM airdrop_users WHERE token=%s
            """,
            (tok,),
        ).fetchone()

    if not row:
        raise HTTPException(status_code=404, detail="token not found")

    uname = (row.get("twitter_username") or "").strip()
    if not uname:
        raise HTTPException(status_code=400, detail="x_username_required")

    last = int(row.get("twitter_checked_at") or 0)
    if now - last < THROTTLE_SEC:
        return status_for_token(tok)

    res = x_guard_check(uname)

    follow_ok = bool(res.get("follow_ok"))
    like_ok = bool(res.get("like_ok"))
    retweet_ok = bool(res.get("retweet_ok"))

    # sticky: навсегда true если было true хотя бы раз
    new_follow = bool(row.get("twitter_follow")) or follow_ok
    new_like = bool(row.get("twitter_like")) or like_ok
    new_rt = bool(row.get("twitter_retweet")) or retweet_ok

    new_points = compute_points(
        bool(row.get("wallet_bound")),
        bool(row.get("telegram_ok")),
        new_follow, new_like, new_rt,
        int(row.get("referrals") or 0),
    )

    with POOL.connection() as c:
        c.execute(
            """
            UPDATE airdrop_users
               SET twitter_follow=%s,
                   twitter_like=%s,
                   twitter_retweet=%s,
                   twitter_checked_at=%s,
                   points=%s,
                   updated_at=%s
             WHERE token=%s
            """,
            (new_follow, new_like, new_rt, now, new_points, now, tok),
        )

    st = status_for_token(tok)
    st["details"] = {"x_guard": res}
    return st

```

## X Guard Module Source (modules/x_guard)

`/root/logos_lrb/modules/x_guard`


---

### `/root/logos_lrb/modules/x_guard/Cargo.toml`

```toml
[package]
name = "logos_x_guard"
version = "0.1.0"
edition = "2021"

[dependencies]
tokio = { workspace = true }
axum = { workspace = true }
serde = { workspace = true }
serde_json = { workspace = true }
reqwest = { workspace = true }
tracing = { workspace = true }
tracing-subscriber = { workspace = true }
anyhow = { workspace = true }

```

---

### `/root/logos_lrb/modules/x_guard/src/main.rs`

```rust
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{anyhow, Context, Result};
use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use reqwest::{Client, StatusCode as HttpStatus};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::RwLock;
use tracing::{error, info};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

#[derive(Clone, Debug)]
struct XCreds {
    api_key: String,
    api_secret: String,
    bearer_token: String,
    access_token: Option<String>,
    access_token_secret: Option<String>,
}

fn read_env_required(name: &str) -> Result<String> {
    std::env::var(name).with_context(|| format!("missing env {}", name))
}

fn read_env_optional(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.trim().is_empty())
}

fn guard_secret(name: &str, value: &str) -> Result<()> {
    let bad = [
        "CHANGE_ME",
        "changeme",
        "default",
        "",
        "EXAMPLE_X_API_KEY_REPLACE_ME",
    ];
    if bad.iter().any(|b| value.eq_ignore_ascii_case(b)) {
        return Err(anyhow!(
            "{} is default/empty placeholder; refuse to start",
            name
        ));
    }
    Ok(())
}

impl XCreds {
    fn from_env() -> Result<Self> {
        let api_key = read_env_required("X_API_KEY")?;
        let api_secret = read_env_required("X_API_SECRET")?;
        let bearer_token = read_env_required("X_BEARER_TOKEN")?;

        guard_secret("X_API_KEY", &api_key)?;
        guard_secret("X_API_SECRET", &api_secret)?;
        guard_secret("X_BEARER_TOKEN", &bearer_token)?;

        let access_token = read_env_optional("X_ACCESS_TOKEN");
        let access_token_secret = read_env_optional("X_ACCESS_TOKEN_SECRET");

        Ok(Self {
            api_key,
            api_secret,
            bearer_token,
            access_token,
            access_token_secret,
        })
    }
}

#[derive(Clone)]
struct XClient {
    http: Client,
    creds: Arc<XCreds>,
    base_url: String,
}

impl XClient {
    fn new(creds: XCreds) -> Self {
        let http = Client::builder()
            .timeout(Duration::from_secs(25))
            .pool_idle_timeout(Duration::from_secs(90))
            .tcp_keepalive(Duration::from_secs(60))
            .build()
            .expect("failed to build reqwest client");

        Self {
            http,
            creds: Arc::new(creds),
            base_url: std::env::var("X_API_BASE").ok().filter(|v| !v.trim().is_empty()).unwrap_or_else(|| "https://api.twitter.com/2".to_string()),
        }
    }

    async fn get_raw(&self, path: &str, query: Vec<(String, String)>) -> Result<Value> {
        let url = format!("{}{}", self.base_url, path);
        let mut attempt: u32 = 0;

        loop {
            attempt += 1;

            let resp = self
                .http
                .get(&url)
                .query(&query)
                .bearer_auth(&self.creds.bearer_token)
                .send()
                .await
                .with_context(|| format!("request to {}", url))?;

            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();

            if status == HttpStatus::TOO_MANY_REQUESTS && attempt < 5 {
                let sleep_secs = 20 * attempt;
                info!(
                    "rate limited by X on {}, attempt {} -> sleep {}s",
                    url, attempt, sleep_secs
                );
                tokio::time::sleep(Duration::from_secs(sleep_secs as u64)).await;
                continue;
            }

            if status.is_server_error() && attempt < 5 {
                let backoff = 2_u64.pow(attempt);
                info!(
                    "server error from X: {} on {}, retry in {}s",
                    status, url, backoff
                );
                tokio::time::sleep(Duration::from_secs(backoff)).await;
                continue;
            }

            if !status.is_success() {
                return Err(anyhow!(
                    "X API error: status={} body={}",
                    status.as_u16(),
                    text
                ));
            }

            let json: Value =
                serde_json::from_str(&text).with_context(|| format!("bad JSON from {}: {}", url, text))?;
            return Ok(json);
        }
    }

    async fn get_user_by_username(&self, username: &str) -> Result<UserInfo> {
        let path = format!("/users/by/username/{}", username);
        let json = self
            .get_raw(
                &path,
                vec![("user.fields".into(), "created_at,public_metrics".into())],
            )
            .await?;

        let data = match json.get("data") {
            Some(d) => d,
            None => {
                // X часто возвращает {"errors":[...]} без "data" (user not found / auth / policy)
                let err_snip = json.clone();
                return Err(anyhow!("x_user_lookup_failed: {}", err_snip));
            }
        };

        let id = data
            .get("id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("no id in user data"))?
            .to_string();

        let uname = data
            .get("username")
            .and_then(|v| v.as_str())
            .unwrap_or(username)
            .to_string();

        let created_at = data
            .get("created_at")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let followers = data
            .get("public_metrics")
            .and_then(|v| v.get("followers_count"))
            .and_then(|v| v.as_u64());

        Ok(UserInfo {
            id,
            username: uname,
            created_at,
            followers,
        })
    }

    async fn user_follows(&self, source_user_id: &str, target_user_id: &str, max_pages: usize) -> Result<bool> {
        let path = format!("/users/{}/following", source_user_id);
        let mut next: Option<String> = None;

        for _ in 0..max_pages {
            let mut q = vec![
                ("max_results".into(), "1000".into()),
                ("user.fields".into(), "id".into()),
            ];
            if let Some(t) = next.clone() {
                q.push(("pagination_token".into(), t));
            }

            let json = self.get_raw(&path, q).await?;
            let data = json.get("data").and_then(|v| v.as_array()).cloned().unwrap_or_default();

            if data.iter().any(|u| {
                u.get("id")
                    .and_then(|v| v.as_str())
                    .map(|id| id == target_user_id)
                    .unwrap_or(false)
            }) {
                return Ok(true);
            }

            next = json
                .get("meta")
                .and_then(|m| m.get("next_token"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());

            if next.is_none() {
                break;
            }
        }

        Ok(false)
    }

    async fn user_liked_tweet(&self, user_id: &str, tweet_id: &str, max_pages: usize) -> Result<bool> {
        let path = format!("/tweets/{}/liking_users", tweet_id);
        let mut next: Option<String> = None;

        for _ in 0..max_pages {
            let mut q = vec![
                ("max_results".into(), "100".into()),
                ("user.fields".into(), "id".into()),
            ];
            if let Some(t) = next.clone() {
                q.push(("pagination_token".into(), t));
            }

            let json = self.get_raw(&path, q).await?;
            let data = json.get("data").and_then(|v| v.as_array()).cloned().unwrap_or_default();

            if data.iter().any(|u| {
                u.get("id")
                    .and_then(|v| v.as_str())
                    .map(|id| id == user_id)
                    .unwrap_or(false)
            }) {
                return Ok(true);
            }

            next = json
                .get("meta")
                .and_then(|m| m.get("next_token"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());

            if next.is_none() {
                break;
            }
        }

        Ok(false)
    }

    async fn user_retweeted_tweet(&self, user_id: &str, tweet_id: &str, max_pages: usize) -> Result<bool> {
        let path = format!("/tweets/{}/retweeted_by", tweet_id);
        let mut next: Option<String> = None;

        for _ in 0..max_pages {
            let mut q = vec![
                ("max_results".into(), "100".into()),
                ("user.fields".into(), "id".into()),
            ];
            if let Some(t) = next.clone() {
                q.push(("pagination_token".into(), t));
            }

            let json = self.get_raw(&path, q).await?;
            let data = json.get("data").and_then(|v| v.as_array()).cloned().unwrap_or_default();

            if data.iter().any(|u| {
                u.get("id")
                    .and_then(|v| v.as_str())
                    .map(|id| id == user_id)
                    .unwrap_or(false)
            }) {
                return Ok(true);
            }

            next = json
                .get("meta")
                .and_then(|m| m.get("next_token"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());

            if next.is_none() {
                break;
            }
        }

        Ok(false)
    }

    async fn project_recent_tweet_ids(&self, project_user_id: &str, limit: usize) -> Result<Vec<String>> {
        // берём последние limit твитов проекта (исключаем ретвиты/реплаи)
        let path = format!("/users/{}/tweets", project_user_id);

        let max_results = limit.clamp(5, 100).to_string();

        let json = self
            .get_raw(
                &path,
                vec![
                    ("max_results".into(), max_results),
                    ("exclude".into(), "retweets,replies".into()),
                ],
            )
            .await?;

        let data = json.get("data").and_then(|v| v.as_array()).cloned().unwrap_or_default();
        let mut ids: Vec<String> = Vec::with_capacity(data.len());

        for t in data {
            if let Some(id) = t.get("id").and_then(|v| v.as_str()) {
                ids.push(id.to_string());
            }
        }

        Ok(ids)
    }

    async fn user_posted_about(&self, user_id: &str, project_username: &str, limit: usize) -> Result<bool> {
        // "пост" = среди последних твитов юзера есть упоминание @project_username
        let path = format!("/users/{}/tweets", user_id);
        let max_results = limit.clamp(5, 100).to_string();

        let json = self
            .get_raw(
                &path,
                vec![
                    ("max_results".into(), max_results),
                    ("tweet.fields".into(), "text".into()),
                    ("exclude".into(), "retweets".into()),
                ],
            )
            .await?;

        let data = json.get("data").and_then(|v| v.as_array()).cloned().unwrap_or_default();
        let needle = format!("@{}", project_username.to_lowercase());

        for t in data {
            let text = t.get("text").and_then(|v| v.as_str()).unwrap_or("").to_lowercase();
            if text.contains(&needle) {
                return Ok(true);
            }
        }

        Ok(false)
    }
}

#[derive(Clone, Debug)]
struct UserInfo {
    id: String,
    username: String,
    created_at: Option<String>,
    followers: Option<u64>,
}

#[derive(Clone)]
struct Caches {
    tweets: Arc<RwLock<HashMap<String, (Instant, Vec<String>)>>>,
    bools: Arc<RwLock<HashMap<String, (Instant, bool)>>>,
}

impl Caches {
    fn new() -> Self {
        Self {
            tweets: Arc::new(RwLock::new(HashMap::new())),
            bools: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    async fn get_tweets(&self, key: &str, ttl: Duration) -> Option<Vec<String>> {
        let map = self.tweets.read().await;
        let (at, v) = map.get(key)?.clone();
        if at.elapsed() <= ttl {
            Some(v)
        } else {
            None
        }
    }

    async fn put_tweets(&self, key: String, v: Vec<String>) {
        let mut map = self.tweets.write().await;
        map.insert(key, (Instant::now(), v));
    }

    async fn get_bool(&self, key: &str, ttl: Duration) -> Option<bool> {
        let map = self.bools.read().await;
        let (at, v) = map.get(key)?.clone();
        if at.elapsed() <= ttl {
            Some(v)
        } else {
            None
        }
    }

    async fn put_bool(&self, key: String, v: bool) {
        let mut map = self.bools.write().await;
        map.insert(key, (Instant::now(), v));
    }
}

#[derive(Clone)]
struct Config {
    recent_tweets: usize,
    user_posts_scan: usize,
    max_pages: usize,
    tweets_cache_ttl: Duration,
    checks_cache_ttl: Duration,
    bind: SocketAddr,
}

fn env_usize(name: &str, def: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .unwrap_or(def)
}

fn env_addr(name: &str, def: &str) -> SocketAddr {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse::<SocketAddr>().ok())
        .unwrap_or_else(|| def.parse().unwrap())
}

#[derive(Clone)]
struct AppState {
    x: XClient,
    caches: Arc<Caches>,
    cfg: Arc<Config>,
}

#[derive(Serialize)]
struct HealthResponse {
    ok: bool,
    service: &'static str,
}

async fn health(State(_state): State<Arc<AppState>>) -> Json<HealthResponse> {
    Json(HealthResponse {
        ok: true,
        service: "logos_x_guard",
    })
}

#[derive(Deserialize)]
struct CheckRequest {
    user_username: String,
    project_username: String,

    #[serde(default)]
    tweet_id: String, // "any" => любой лайк/ретвит/пост по последним твитам проекта

    #[serde(default = "default_true")]
    require_follow: bool,
    #[serde(default = "default_true")]
    require_like: bool,
    #[serde(default = "default_true")]
    require_retweet: bool,

    #[serde(default = "default_min_age")]
    min_account_age_days: u32,

    #[serde(default = "default_min_followers")]
    min_followers: u32,
}

fn default_true() -> bool {
    true
}
fn default_min_age() -> u32 {
    3
}
fn default_min_followers() -> u32 {
    3
}

#[derive(Serialize)]
struct CheckResponse {
    ok: bool,
    user_username: String,
    project_username: String,
    tweet_id: String,
    mode: String, // "tweet" | "any"

    follow_ok: bool,
    like_ok: bool,
    retweet_ok: bool, // retweet OR post(@project)
    age_ok: bool,
    followers_ok: bool,

    user_info: Value,
    details: Value,
}

async fn check_airdrop(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CheckRequest>,
) -> impl IntoResponse {
    let res = do_check_airdrop(state, req).await;
    match res {
        Ok(resp) => (StatusCode::OK, Json(resp)).into_response(),
        Err(err) => {
            error!("check_airdrop error: {:?}", err);
            let body = serde_json::json!({
                "ok": false,
                "error": "internal_error",
                "message": err.to_string(),
            });
            (StatusCode::BAD_GATEWAY, Json(body)).into_response()
        }
    }
}

async fn cached_project_tweets(state: &Arc<AppState>, project_id: &str) -> Result<Vec<String>> {
    let key = format!("project_tweets:{}", project_id);
    if let Some(v) = state.caches.get_tweets(&key, state.cfg.tweets_cache_ttl).await {
        return Ok(v);
    }

    let ids = state
        .x
        .project_recent_tweet_ids(project_id, state.cfg.recent_tweets)
        .await
        .unwrap_or_default();

    state.caches.put_tweets(key, ids.clone()).await;
    Ok(ids)
}

async fn do_check_airdrop(state: Arc<AppState>, req: CheckRequest) -> Result<CheckResponse> {
    let user = state.x.get_user_by_username(&req.user_username).await?;
    let project = state.x.get_user_by_username(&req.project_username).await?;

    // TODO: можно сделать строгую проверку created_at, но сейчас держим совместимость.
    let age_ok = true;

    let followers_ok = user
        .followers
        .map(|c| c >= req.min_followers as u64)
        .unwrap_or(false);

    let mut follow_ok = true;
    let mut like_ok = !req.require_like;
    let mut retweet_ok = !req.require_retweet;

    let mode_any = {
        let t = req.tweet_id.trim();
        t.is_empty() || t.eq_ignore_ascii_case("any") || t == "*"
    };

    // FOLLOW FIRST
    if req.require_follow {
        let cache_key = format!("follow:{}:{}", user.id, project.id);
        if let Some(v) = state.caches.get_bool(&cache_key, state.cfg.checks_cache_ttl).await {
            follow_ok = v;
        } else {
            follow_ok = state
                .x
                .user_follows(&user.id, &project.id, state.cfg.max_pages)
                .await
                .unwrap_or(false);
            state.caches.put_bool(cache_key, follow_ok).await;
        }
    }

    // если follow обязателен и не выполнен — НЕ считаем лайк/ретвит/пост
    if req.require_follow && !follow_ok {
        if follow_ok && req.require_like {
            like_ok = false;
        }
        if follow_ok && req.require_retweet {
            retweet_ok = false;
        }

        let ok = follow_ok && like_ok && retweet_ok && age_ok && followers_ok;

        let user_info = serde_json::json!({
            "id": user.id,
            "username": user.username,
            "created_at": user.created_at,
            "followers": user.followers,
        });

        let details = serde_json::json!({
            "note": "follow-first: like/retweet/post skipped because follow=false",
        });

        return Ok(CheckResponse {
            ok,
            user_username: req.user_username,
            project_username: req.project_username,
            tweet_id: req.tweet_id,
            mode: if mode_any { "any".into() } else { "tweet".into() },
            follow_ok,
            like_ok,
            retweet_ok,
            age_ok,
            followers_ok,
            user_info,
            details,
        });
    }

    // LIKE
    if follow_ok && req.require_like {
        let cache_key = format!(
            "like:{}:{}:{}",
            user.id,
            project.id,
            if mode_any { "any" } else { req.tweet_id.trim() }
        );
        if let Some(v) = state.caches.get_bool(&cache_key, state.cfg.checks_cache_ttl).await {
            like_ok = v;
        } else {
            if mode_any {
                let ids = cached_project_tweets(&state, &project.id).await.unwrap_or_default();
                let mut found = false;
                for tid in ids {
                    if state
                        .x
                        .user_liked_tweet(&user.id, &tid, state.cfg.max_pages)
                        .await
                        .unwrap_or(false)
                    {
                        found = true;
                        break;
                    }
                }
                like_ok = found;
            } else {
                like_ok = state
                    .x
                    .user_liked_tweet(&user.id, req.tweet_id.trim(), state.cfg.max_pages)
                    .await
                    .unwrap_or(false);
            }
            state.caches.put_bool(cache_key, like_ok).await;
        }
    }

    // RETWEET OR POST(@project)
    if follow_ok && req.require_retweet {
        let cache_key = format!(
            "retweet_or_post:{}:{}:{}",
            user.id,
            project.id,
            if mode_any { "any" } else { req.tweet_id.trim() }
        );
        if let Some(v) = state.caches.get_bool(&cache_key, state.cfg.checks_cache_ttl).await {
            retweet_ok = v;
        } else {
            let mut rt_found = false;

            if mode_any {
                let ids = cached_project_tweets(&state, &project.id).await.unwrap_or_default();
                for tid in ids {
                    if state
                        .x
                        .user_retweeted_tweet(&user.id, &tid, state.cfg.max_pages)
                        .await
                        .unwrap_or(false)
                    {
                        rt_found = true;
                        break;
                    }
                }
            } else {
                rt_found = state
                    .x
                    .user_retweeted_tweet(&user.id, req.tweet_id.trim(), state.cfg.max_pages)
                    .await
                    .unwrap_or(false);
            }

            // "пост" = упоминание @project_username в твитах пользователя
            let post_found = state
                .x
                .user_posted_about(&user.id, &project.username, state.cfg.user_posts_scan)
                .await
                .unwrap_or(false);

            retweet_ok = rt_found || post_found;
            state.caches.put_bool(cache_key, retweet_ok).await;
        }
    }

    let ok = follow_ok && like_ok && retweet_ok && age_ok && followers_ok;

    let user_info = serde_json::json!({
        "id": user.id,
        "username": user.username,
        "created_at": user.created_at,
        "followers": user.followers,
    });

    let details = serde_json::json!({
        "follow_first": true,
        "mode_any": mode_any,
        "note": "retweet_ok counts as (retweet any project tweet) OR (user posted mentioning @project)",
    });

    Ok(CheckResponse {
        ok,
        user_username: req.user_username,
        project_username: req.project_username,
        tweet_id: req.tweet_id,
        mode: if mode_any { "any".into() } else { "tweet".into() },

        follow_ok,
        like_ok,
        retweet_ok,
        age_ok,
        followers_ok,

        user_info,
        details,
    })
}

#[tokio::main]
async fn main() -> Result<()> {
    let filter_layer =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| "info,hyper=warn,reqwest=warn".into());
    let fmt_layer = fmt::layer().with_target(false);

    tracing_subscriber::registry()
        .with(filter_layer)
        .with(fmt_layer)
        .init();

    let creds = XCreds::from_env().context("reading X_* env vars")?;
    info!("X credentials loaded, starting service");

    let recent_tweets = env_usize("X_GUARD_RECENT_TWEETS", 25).clamp(5, 60);
    let user_posts_scan = env_usize("X_GUARD_USER_POSTS_SCAN", 25).clamp(5, 80);
    let max_pages = env_usize("X_GUARD_MAX_PAGES", 15).clamp(1, 50);
    let tweets_cache_sec = env_usize("X_GUARD_TWEETS_CACHE_SEC", 60).clamp(10, 600);
    let checks_cache_sec = env_usize("X_GUARD_CHECKS_CACHE_SEC", 30).clamp(5, 120);

    // SECURITY DEFAULT: bind localhost, override via env if нужно
    let bind = env_addr("X_GUARD_BIND", "127.0.0.1:8091");

    let cfg = Arc::new(Config {
        recent_tweets,
        user_posts_scan,
        max_pages,
        tweets_cache_ttl: Duration::from_secs(tweets_cache_sec as u64),
        checks_cache_ttl: Duration::from_secs(checks_cache_sec as u64),
        bind,
    });

    info!(
        "cfg: bind={} recent_tweets={} user_posts_scan={} max_pages={} tweets_cache={}s checks_cache={}s",
        cfg.bind, cfg.recent_tweets, cfg.user_posts_scan, cfg.max_pages, tweets_cache_sec, checks_cache_sec
    );

    let x_client = XClient::new(creds);
    let state = Arc::new(AppState {
        x: x_client,
        caches: Arc::new(Caches::new()),
        cfg,
    });

    let app = Router::new()
        .route("/health", get(health))
        .route("/healthz", get(health))
        .route("/check_airdrop", post(check_airdrop))
        .with_state(state);

    info!("LOGOS X Guard listening on {}", bind);
    let listener = tokio::net::TcpListener::bind(bind).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

```

## systemd: logos-airdrop-tg-bot.service

### `/etc/systemd/system/logos-airdrop-tg-bot.service`

```ini
[Unit]
Description=LOGOS Airdrop Telegram Bot (subscription verifier)
After=network-online.target logos-airdrop-api.service
Wants=network-online.target

[Service]
User=logos
Group=logos
WorkingDirectory=/opt/logos/airdrop-tg-bot

# Никакие ключи не меняем — только подключаем где они лежат
EnvironmentFile=/etc/logos/logos_tg_bot.env
EnvironmentFile=/etc/logos/airdrop-api.env
EnvironmentFile=/etc/logos/node-main.env

Environment=TG_CHANNEL=@logosblockchain
Environment=AIRDROP_UPDATE_URL=http://127.0.0.1:8092/api/airdrop/update
Environment=AIRDROP_API_KEY_HEADER=X-API-Key
Environment=LOG_LEVEL=INFO

ExecStart=/opt/logos/airdrop-tg-bot/.venv/bin/python /opt/logos/airdrop-tg-bot/bot.py

Restart=always
RestartSec=3
TimeoutStopSec=20
LimitNOFILE=65535

StandardOutput=journal
StandardError=journal

NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target

```

## systemd: logos-airdrop-api.service

### `/etc/systemd/system/logos-airdrop-api.service`

```ini
[Unit]
Description=LOGOS Airdrop API (FastAPI on :8092, Postgres)
After=network.target postgresql.service
Requires=network.target postgresql.service

[Service]
User=logos
Group=logos
WorkingDirectory=/opt/logos/airdrop-api

# Все секреты и DSN лежат здесь
EnvironmentFile=/etc/logos/airdrop-api.env
Environment=PYTHONUNBUFFERED=1

# Uvicorn внутри venv, 4 воркера
ExecStart=/opt/logos/airdrop-api/.venv/bin/uvicorn app:app --host 127.0.0.1 --port 8092 --workers 4 --proxy-headers

Restart=always
RestartSec=3
TimeoutStopSec=20
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target

```

## systemd: logos-x-guard.service

### `/etc/systemd/system/logos-x-guard.service`

```ini
[Unit]
Description=LOGOS X Guard (Twitter airdrop verifier)
After=network-online.target logos-airdrop-api.service
Wants=network-online.target

[Service]
User=logos
Group=logos
WorkingDirectory=/opt/logos

EnvironmentFile=/etc/logos/node-main.env
EnvironmentFile=/etc/logos/airdrop-api.env

# PROD: не светим наружу, nginx/airdrop-api ходят по localhost
Environment=X_GUARD_BIND=127.0.0.1:8091

# Параметры "any лайк/ретвит/пост"
Environment=X_GUARD_RECENT_TWEETS=25
Environment=X_GUARD_USER_POSTS_SCAN=25
Environment=X_GUARD_MAX_PAGES=15
Environment=X_GUARD_TWEETS_CACHE_SEC=60
Environment=X_GUARD_CHECKS_CACHE_SEC=30

ExecStart=/opt/logos/bin/logos_x_guard
Restart=always
RestartSec=2
LimitNOFILE=65535
StandardOutput=journal
StandardError=journal

NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target

```

## nginx: logos.conf

### `/etc/nginx/sites-available/logos.conf`

```ini
# Лимиты запросов к API
limit_req_zone $binary_remote_addr zone=api_zone:10m rate=30r/s;

# WebSocket/upgrade helper
map $http_upgrade $connection_upgrade {
    default upgrade;
    ''      close;
}

# Узел LOGOS (REST API)
upstream logos_node_backend {
    server 127.0.0.1:8080;
    keepalive 32;
}

# Wallet-proxy (депозиты USDT -> rLGN)
upstream logos_wallet_api {
    server 127.0.0.1:9090;
    keepalive 16;
}

# Airdrop API — upstream объявлен в /etc/nginx/conf.d/logos_airdrop_upstream.conf
# upstream logos_airdrop_api { ... }

server {
    listen 80;
    server_name mw-expedition.com www.mw-expedition.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name mw-expedition.com www.mw-expedition.com;

    ssl_certificate     /etc/letsencrypt/live/mw-expedition.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/mw-expedition.com/privkey.pem;

    # По умолчанию — статика кошелька/эксплорера
    root /opt/logos/www;
    index index.html;

    # === Лендинг ===
    location = / {
        root /var/www/logos/landing;
        try_files /index.html =404;
        add_header Cache-Control "no-store" always;
    }

    # Страница аирдропа /airdrop.html
    location = /airdrop.html {
        root /var/www/logos/landing;
        try_files /airdrop.html =404;
        add_header Cache-Control "no-store" always;
    }

    # === Wallet SPA ===
    location /wallet/ {
        try_files $uri /wallet/index.html;
        add_header Cache-Control "no-store" always;
        add_header Content-Security-Policy "default-src 'self'; connect-src 'self' https://mw-expedition.com https://mw-expedition.com/api https://mw-expedition.com/proxy https://vnet.web3games.org https://mainnet.infura.io;" always;
    }

    # === Explorer SPA ===
    location /explorer/ {
        try_files $uri /explorer/index.html;
        add_header Cache-Control "no-store" always;
        # Разрешаем inline-стили и скрипты для explorer, API остаётся только self
        add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self' https://mw-expedition.com https://mw-expedition.com/api;" always;
    }

    # === REST API ноды ===
    location /api/ {
        limit_req zone=api_zone burst=60 nodelay;

        proxy_pass http://logos_node_backend/;
        proxy_http_version 1.1;
        proxy_set_header Connection "";

        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # === Wallet-proxy API ===
    location /proxy/ {
        proxy_pass http://logos_wallet_api/;
        proxy_http_version 1.1;
        proxy_set_header Connection "";

        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # === Airdrop API ===
    location /airdrop-api/ {
        proxy_pass http://logos_airdrop_api/;
        proxy_http_version 1.1;
        proxy_set_header Connection "";

        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # Общая статика (JS/CSS/иконки)
    location ~* \.(?:css|js|ico|png|jpg|jpeg|svg|woff2?)$ {
        try_files $uri =404;
        add_header Cache-Control "no-store" always;
    }
}

```
