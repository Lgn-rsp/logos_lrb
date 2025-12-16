# LOGOS Airdrop Bots Book (TG + X + API + Front + Infra)

_Автогенерация: `2025-12-16 09:44:45Z`_


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
# (БОЕВОЙ app.py с OAuth endpoints + verify последнего твита)
# ВНИМАНИЕ: файл большой; вставляется целиком одним heredoc.
# Если хочешь — я могу разбить на 2 cat-блока, но лучше одним.

from __future__ import annotations

import base64
import json
import logging
import os
import secrets
import time
from collections import deque
from contextlib import contextmanager
from typing import Any, Deque, Dict, Optional

from fastapi import FastAPI, Header, HTTPException, Request, Response
from pydantic import BaseModel, Field
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest
from psycopg_pool import ConnectionPool
from psycopg.rows import dict_row

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from x_oauth import pkce_pair, oauth_authorize_url, token_exchange, token_refresh, enc, dec, x_get


# -------------------- CONFIG --------------------

REF_TARGET = int(os.getenv("AIRDROP_REF_TARGET", "5"))
SITE_ORIGIN = (os.getenv("AIRDROP_SITE_ORIGIN", "https://mw-expedition.com") or "https://mw-expedition.com").rstrip("/")
AIRDROP_API_KEY = (os.getenv("AIRDROP_API_KEY", "") or "").strip()

DB_DSN = (os.getenv("AIRDROP_DB_DSN") or os.getenv("AIRDROP_PG_DSN") or "").strip()
if not DB_DSN:
    raise RuntimeError("AIRDROP_DB_DSN (or AIRDROP_PG_DSN) is required")

DB_POOL_MIN = int(os.getenv("AIRDROP_DB_POOL_MIN", "1"))
DB_POOL_MAX = int(os.getenv("AIRDROP_DB_POOL_MAX", "10"))

WALLET_CHALLENGE_TTL = int(os.getenv("AIRDROP_WALLET_CHALLENGE_TTL", "600"))
RATE_WINDOW_SEC = int(os.getenv("AIRDROP_RATE_WINDOW_SEC", "60"))
RATE_REGISTER_PER_IP = int(os.getenv("AIRDROP_RATE_REGISTER_PER_IP", "12"))
RATE_STATUS_PER_TOKEN = int(os.getenv("AIRDROP_RATE_STATUS_PER_TOKEN", "30"))
RATE_WALLET_PER_TOKEN = int(os.getenv("AIRDROP_RATE_WALLET_PER_TOKEN", "10"))
RATE_UPDATE_PER_TOKEN = int(os.getenv("AIRDROP_RATE_UPDATE_PER_TOKEN", "10"))

# OAuth/X
X_PROJECT_USERNAME = (os.getenv("X_PROJECT_USERNAME", "RspLogos") or "RspLogos").lstrip("@")
X_OAUTH_STATE_TTL = int(os.getenv("X_OAUTH_STATE_TTL", "600"))
X_OAUTH_COOLDOWN = int(os.getenv("X_OAUTH_COOLDOWN", "180"))


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

        # Wallet fields
        cur.execute("ALTER TABLE airdrop_users ADD COLUMN IF NOT EXISTS wallet_rid TEXT;")
        cur.execute("ALTER TABLE airdrop_users ADD COLUMN IF NOT EXISTS wallet_bound_at BIGINT NOT NULL DEFAULT 0;")
        cur.execute("ALTER TABLE airdrop_users ADD COLUMN IF NOT EXISTS wallet_challenge TEXT;")
        cur.execute("ALTER TABLE airdrop_users ADD COLUMN IF NOT EXISTS wallet_challenge_exp BIGINT NOT NULL DEFAULT 0;")

        # X fields
        cur.execute("ALTER TABLE airdrop_users ADD COLUMN IF NOT EXISTS twitter_username TEXT;")
        cur.execute("ALTER TABLE airdrop_users ADD COLUMN IF NOT EXISTS twitter_checked_at BIGINT NOT NULL DEFAULT 0;")

        # OAuth state
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS airdrop_oauth_state (
              state         TEXT PRIMARY KEY,
              token         TEXT NOT NULL,
              code_verifier TEXT NOT NULL,
              created_at    BIGINT NOT NULL,
              exp_at        BIGINT NOT NULL
            );
            """
        )
        cur.execute("CREATE INDEX IF NOT EXISTS idx_oauth_state_exp ON airdrop_oauth_state(exp_at);")

        # OAuth tokens (encrypted)
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS airdrop_x_oauth (
              token           TEXT PRIMARY KEY,
              x_user_id       TEXT NOT NULL,
              access_token_e  TEXT NOT NULL,
              refresh_token_e TEXT,
              expires_at      BIGINT NOT NULL DEFAULT 0,
              updated_at      BIGINT NOT NULL
            );
            """
        )

        # Indexes
        cur.execute("CREATE INDEX IF NOT EXISTS idx_airdrop_points ON airdrop_users(points DESC);")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_airdrop_token ON airdrop_users(token);")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_airdrop_ref_token ON airdrop_users(ref_token);")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_airdrop_twitter_username ON airdrop_users(twitter_username);")

        # Unique wallet rid
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
UPDATE_TOTAL = Counter("airdrop_update_total", "Update calls", ["result"])


# -------------------- RATE LIMIT --------------------

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
    flags = int(wallet_bound) + int(telegram_ok) + int(twitter_like) + int(twitter_retweet)
    refs = min(int(referrals or 0), REF_TARGET)
    return flags * 20 + refs * 10

def _norm_x_username(s: str) -> str:
    s = (s or "").strip()
    if s.startswith("@"):
        s = s[1:]
    s = s.replace("https://x.com/", "").replace("http://x.com/", "")
    s = s.replace("https://twitter.com/", "").replace("http://twitter.com/", "")
    s = s.split("?")[0].split("/")[0].strip().lower()
    if not s or len(s) > 32:
        raise ValueError("bad twitter_username")
    return s

def _now() -> int:
    return int(time.time())


# -------------------- MODELS --------------------

class RegisterRequest(BaseModel):
    ref_token: Optional[str] = None

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

class SetXUsernameRequest(BaseModel):
    token: str = Field(..., min_length=8, max_length=128)
    twitter_username: str = Field(..., min_length=1, max_length=128)

class VerifyXRequest(BaseModel):
    token: str = Field(..., min_length=8, max_length=128)

class OAuthStartReq(BaseModel):
    token: str = Field(..., min_length=8, max_length=128)


# -------------------- APP --------------------

app = FastAPI(title="LOGOS Airdrop API", version="1.3.0-oauth-per-user")


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
            cur.execute("UPDATE airdrop_users SET points=%s, updated_at=%s WHERE token=%s", (points, _now(), token))
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

    now = _now()
    token = secrets.token_urlsafe(16)

    with get_cursor() as (conn, cur):
        cur.execute(
            "INSERT INTO airdrop_users(token, ref_token, created_at, updated_at) VALUES (%s, %s, %s, %s)",
            (token, (req.ref_token or None), now, now),
        )

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

    now = _now()
    with get_cursor() as (conn, cur):
        cur.execute("SELECT * FROM airdrop_users WHERE token=%s FOR UPDATE", (tok,))
        row = cur.fetchone()
        if not row:
            UPDATE_TOTAL.labels(result="not_found").inc()
            raise HTTPException(status_code=404, detail="token not found")

        wallet_bound = bool(row.get("wallet_bound"))
        telegram_ok = bool(row.get("telegram_ok"))
        twitter_follow = bool(row.get("twitter_follow"))
        twitter_like = bool(row.get("twitter_like"))
        twitter_retweet = bool(row.get("twitter_retweet"))
        referrals = int(row.get("referrals") or 0)

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
            SET telegram_ok=%s,
                twitter_follow=%s,
                twitter_like=%s,
                twitter_retweet=%s,
                referrals=%s,
                points=%s,
                updated_at=%s
            WHERE token=%s
            """,
            (telegram_ok, twitter_follow, twitter_like, twitter_retweet, referrals, points, now, tok),
        )
        conn.commit()

    UPDATE_TOTAL.labels(result="ok").inc()
    return _status_for_token(tok)


# -------------------- OAuth endpoints --------------------

@app.post("/api/x/oauth/start")
def x_oauth_start(req: OAuthStartReq):
    tok = req.token.strip()
    now = _now()

    with get_cursor() as (conn, cur):
        cur.execute("SELECT token FROM airdrop_users WHERE token=%s", (tok,))
        if not cur.fetchone():
            raise HTTPException(status_code=404, detail="token_not_found")

        state = secrets.token_urlsafe(24)
        verifier, challenge = pkce_pair()
        exp = now + X_OAUTH_STATE_TTL

        cur.execute(
            "INSERT INTO airdrop_oauth_state(state, token, code_verifier, created_at, exp_at) VALUES (%s,%s,%s,%s,%s)",
            (state, tok, enc(verifier), now, exp),
        )
        conn.commit()

    return {"ok": True, "auth_url": oauth_authorize_url(state, challenge)}


@app.get("/api/x/oauth/callback")
def x_oauth_callback(state: str, code: str):
    now = _now()

    with get_cursor() as (conn, cur):
        cur.execute("SELECT * FROM airdrop_oauth_state WHERE state=%s", (state,))
        st = cur.fetchone()
        if not st:
            raise HTTPException(status_code=400, detail="bad_state")
        if int(st.get("exp_at") or 0) < now:
            cur.execute("DELETE FROM airdrop_oauth_state WHERE state=%s", (state,))
            conn.commit()
            raise HTTPException(status_code=400, detail="state_expired")

        tok = st["token"]
        verifier = dec(st["code_verifier"])
        cur.execute("DELETE FROM airdrop_oauth_state WHERE state=%s", (state,))
        conn.commit()

    tr = token_exchange(code, verifier)
    access = tr.get("access_token")
    refresh = tr.get("refresh_token")
    expires_in = int(tr.get("expires_in") or 0)
    if not access:
        raise HTTPException(status_code=502, detail="oauth_token_exchange_failed")

    me = x_get("/2/users/me", access)
    x_user_id = (((me or {}).get("data") or {}) or {}).get("id")
    if not x_user_id:
        raise HTTPException(status_code=502, detail="x_me_failed")

    exp_at = now + expires_in if expires_in > 0 else 0

    with get_cursor() as (conn, cur):
        cur.execute(
            """
            INSERT INTO airdrop_x_oauth(token, x_user_id, access_token_e, refresh_token_e, expires_at, updated_at)
            VALUES (%s,%s,%s,%s,%s,%s)
            ON CONFLICT(token) DO UPDATE SET
              x_user_id=EXCLUDED.x_user_id,
              access_token_e=EXCLUDED.access_token_e,
              refresh_token_e=EXCLUDED.refresh_token_e,
              expires_at=EXCLUDED.expires_at,
              updated_at=EXCLUDED.updated_at
            """,
            (tok, x_user_id, enc(access), enc(refresh) if refresh else None, exp_at, now),
        )
        conn.commit()

    # return to airdrop page
    return Response(status_code=302, headers={"Location": f"{SITE_ORIGIN}/airdrop?oauth=ok"})


def _get_oauth_access(tok: str) -> Optional[str]:
    now = _now()
    with get_cursor() as (conn, cur):
        cur.execute("SELECT * FROM airdrop_x_oauth WHERE token=%s", (tok,))
        row = cur.fetchone()
        if not row:
            return None
        access = dec(row["access_token_e"])
        refresh_e = row.get("refresh_token_e")
        refresh = dec(refresh_e) if refresh_e else None
        exp_at = int(row.get("expires_at") or 0)

    if refresh and exp_at and exp_at < now + 60:
        tr = token_refresh(refresh)
        new_access = tr.get("access_token")
        new_refresh = tr.get("refresh_token") or refresh
        expires_in = int(tr.get("expires_in") or 0)
        if new_access:
            new_exp = now + expires_in if expires_in > 0 else 0
            with get_cursor() as (conn, cur):
                cur.execute(
                    "UPDATE airdrop_x_oauth SET access_token_e=%s, refresh_token_e=%s, expires_at=%s, updated_at=%s WHERE token=%s",
                    (enc(new_access), enc(new_refresh) if new_refresh else None, new_exp, now, tok),
                )
                conn.commit()
            return new_access
    return access


def _x_me(access: str) -> str:
    me = x_get("/2/users/me", access)
    myid = (((me or {}).get("data") or {}) or {}).get("id")
    if not myid:
        raise RuntimeError("x_me_failed")
    return str(myid)

def _x_user_id_by_username(access: str, username: str) -> str:
    target = x_get(f"/2/users/by/username/{username}", access)
    tid = (((target or {}).get("data") or {}) or {}).get("id")
    if not tid:
        raise RuntimeError("x_user_lookup_failed")
    return str(tid)

def _x_latest_tweet_id(access: str, user_id: str) -> str:
    # last non-reply tweet
    data = x_get(f"/2/users/{user_id}/tweets?max_results=5&exclude=replies", access)
    arr = (data or {}).get("data") or []
    if not arr:
        # fallback: include replies
        data = x_get(f"/2/users/{user_id}/tweets?max_results=5", access)
        arr = (data or {}).get("data") or []
    if not arr:
        raise RuntimeError("no_recent_tweets")
    return str(arr[0].get("id"))

def _x_follow_ok(access: str, myid: str, target_id: str) -> bool:
    pagination = None
    for _ in range(3):
        path = f"/2/users/{myid}/following?max_results=100"
        if pagination:
            path += f"&pagination_token={pagination}"
        data = x_get(path, access)
        arr = (data or {}).get("data") or []
        for u in arr:
            if str(u.get("id")) == str(target_id):
                return True
        meta = (data or {}).get("meta") or {}
        pagination = meta.get("next_token")
        if not pagination:
            break
    return False

def _x_like_ok(access: str, myid: str, tweet_id: str) -> bool:
    pagination = None
    for _ in range(3):
        path = f"/2/users/{myid}/liked_tweets?max_results=100"
        if pagination:
            path += f"&pagination_token={pagination}"
        data = x_get(path, access)
        arr = (data or {}).get("data") or []
        for t in arr:
            if str(t.get("id")) == str(tweet_id):
                return True
        meta = (data or {}).get("meta") or {}
        pagination = meta.get("next_token")
        if not pagination:
            break
    return False

def _x_retweet_ok(access: str, myid: str, tweet_id: str) -> bool:
    pagination = None
    for _ in range(10):
        path = f"/2/tweets/{tweet_id}/retweeted_by?max_results=100"
        if pagination:
            path += f"&pagination_token={pagination}"
        data = x_get(path, access)
        arr = (data or {}).get("data") or []
        for u in arr:
            if str(u.get("id")) == str(myid):
                return True
        meta = (data or {}).get("meta") or {}
        pagination = meta.get("next_token")
        if not pagination:
            break
    return False



@app.post("/api/airdrop/set_x_username")
def set_x_username(req: SetXUsernameRequest):
    tok = req.token.strip()
    uname = _norm_x_username(req.twitter_username)
    now = _now()
    with get_cursor() as (conn, cur):
        cur.execute("UPDATE airdrop_users SET twitter_username=%s, updated_at=%s WHERE token=%s", (uname, now, tok))
        if cur.rowcount != 1:
            raise HTTPException(status_code=404, detail="token_not_found")
        conn.commit()
    return _status_for_token(tok)


@app.post("/api/airdrop/verify_x")
def verify_x(req: VerifyXRequest):
    tok = req.token.strip()
    now = _now()

    with get_cursor() as (conn, cur):
        cur.execute(
            "SELECT token,twitter_checked_at,twitter_follow,twitter_like,twitter_retweet,referrals,wallet_bound,telegram_ok FROM airdrop_users WHERE token=%s",
            (tok,),
        )
        row = cur.fetchone()

    if not row:
        raise HTTPException(status_code=404, detail="token_not_found")

    last = int(row.get("twitter_checked_at") or 0)
    if now - last < X_OAUTH_COOLDOWN:
        st = _status_for_token(tok).dict()
        st["ok"] = True
        st["x_retry_after"] = max(0, X_OAUTH_COOLDOWN - (now - last))
        return st

    access = _get_oauth_access(tok)

    with get_cursor() as (conn, cur):
        cur.execute("UPDATE airdrop_users SET twitter_checked_at=%s, updated_at=%s WHERE token=%s", (now, now, tok))
        conn.commit()

    if not access:
        return {"ok": False, "error": "x_oauth_required", "message": "Connect X first"}

    try:
        myid = _x_me(access)
        target_id = _x_user_id_by_username(access, X_PROJECT_USERNAME)
        last_tweet_id = _x_latest_tweet_id(access, target_id)

        follow_ok = True  # follow disabled (prod)
        like_ok = _x_like_ok(access, myid, last_tweet_id)
        rt_ok = _x_retweet_ok(access, myid, last_tweet_id)
    except Exception as e:
        return {"ok": False, "error": "x_oauth_check_failed", "message": str(e)}

    new_follow = bool(row.get("twitter_follow")) or bool(follow_ok)
    new_like = bool(row.get("twitter_like")) or bool(like_ok)
    new_rt = bool(row.get("twitter_retweet")) or bool(rt_ok)

    referrals = int(row.get("referrals") or 0)
    points = compute_points(bool(row.get("wallet_bound")), bool(row.get("telegram_ok")), new_follow, new_like, new_rt, referrals)

    with get_cursor() as (conn, cur):
        cur.execute(
            "UPDATE airdrop_users SET twitter_follow=%s, twitter_like=%s, twitter_retweet=%s, points=%s, updated_at=%s WHERE token=%s",
            (new_follow, new_like, new_rt, points, now, tok),
        )
        conn.commit()

    st = _status_for_token(tok).dict()
    st["ok"] = True
    st["x_latest_tweet_id"] = last_tweet_id
    return st

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

---

### `/opt/logos/airdrop-api/x_oauth.py`

```python
from __future__ import annotations
import base64, hashlib, json, os, secrets
from typing import Any, Dict, Tuple
from urllib.parse import urlencode
import urllib.request, urllib.error
from cryptography.fernet import Fernet

# IMPORTANT:
# - authorize endpoint is WEB: https://x.com/i/oauth2/authorize
# - token endpoint is API: https://api.x.com/2/oauth2/token

AUTH_BASE = "https://x.com"
TOKEN_BASE = "https://api.x.com"

def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")

def pkce_pair() -> Tuple[str, str]:
    verifier = _b64url(secrets.token_bytes(32))
    challenge = _b64url(hashlib.sha256(verifier.encode()).digest())
    return verifier, challenge

def fernet() -> Fernet:
    key = (os.getenv("AIRDROP_X_TOKEN_KEY") or "").strip()
    if not key:
        raise RuntimeError("AIRDROP_X_TOKEN_KEY is required")
    return Fernet(key.encode())

def enc(s: str) -> str:
    return fernet().encrypt(s.encode()).decode()

def dec(s: str) -> str:
    return fernet().decrypt(s.encode()).decode()

def oauth_authorize_url(state: str, code_challenge: str) -> str:
    cid = (os.getenv("X_OAUTH_CLIENT_ID") or "").strip()
    redir = (os.getenv("X_OAUTH_REDIRECT_URI") or "").strip()
    scopes = (os.getenv("X_OAUTH_SCOPES") or "tweet.read users.read").strip()
    if not cid or not redir:
        raise RuntimeError("X_OAUTH_CLIENT_ID and X_OAUTH_REDIRECT_URI required")
    q = {
        "response_type": "code",
        "client_id": cid,
        "redirect_uri": redir,
        "scope": scopes,
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    return f"{AUTH_BASE}/i/oauth2/authorize?{urlencode(q)}"

def _basic_auth() -> str | None:
    cid = (os.getenv("X_OAUTH_CLIENT_ID") or "").strip()
    sec = (os.getenv("X_OAUTH_CLIENT_SECRET") or "").strip()
    if cid and sec:
        return base64.b64encode(f"{cid}:{sec}".encode()).decode()
    return None

def token_exchange(code: str, code_verifier: str) -> Dict[str, Any]:
    cid = (os.getenv("X_OAUTH_CLIENT_ID") or "").strip()
    redir = (os.getenv("X_OAUTH_REDIRECT_URI") or "").strip()
    if not cid or not redir:
        raise RuntimeError("X_OAUTH_CLIENT_ID and X_OAUTH_REDIRECT_URI required")
    data = urlencode({
        "grant_type": "authorization_code",
        "client_id": cid,
        "code": code,
        "redirect_uri": redir,
        "code_verifier": code_verifier,
    }).encode()
    req = urllib.request.Request(f"{TOKEN_BASE}/2/oauth2/token", data=data, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    b = _basic_auth()
    if b:
        req.add_header("Authorization", f"Basic {b}")
    with urllib.request.urlopen(req, timeout=25) as resp:
        body = resp.read().decode("utf-8", "replace")
    return json.loads(body)

def token_refresh(refresh_token: str) -> Dict[str, Any]:
    cid = (os.getenv("X_OAUTH_CLIENT_ID") or "").strip()
    if not cid:
        raise RuntimeError("X_OAUTH_CLIENT_ID required")
    data = urlencode({
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "client_id": cid,
    }).encode()
    req = urllib.request.Request(f"{TOKEN_BASE}/2/oauth2/token", data=data, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    b = _basic_auth()
    if b:
        req.add_header("Authorization", f"Basic {b}")
    with urllib.request.urlopen(req, timeout=25) as resp:
        body = resp.read().decode("utf-8", "replace")
    return json.loads(body)

def x_get(path: str, access_token: str, timeout: float = 15) -> Dict[str, Any]:
    req = urllib.request.Request(f"{TOKEN_BASE}{path}", method="GET")
    req.add_header("Authorization", f"Bearer {access_token}")
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", "replace")
        return json.loads(body)
    except urllib.error.HTTPError as e:
        body = ""
        try:
            body = e.read().decode("utf-8", "replace")
        except Exception:
            body = ""
        return {"_http_error": int(e.code), "_body": body[:500]}


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

## front: /var/www/logos/landing/airdrop.html

### `/var/www/logos/landing/airdrop.html`

```ini
<!DOCTYPE html>
<html lang="ru">
<head>
  <meta charset="utf-8"/>
  <meta http-equiv="Cache-Control" content="no-store"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>LOGOS Airdrop</title>

  <link rel="stylesheet" href="/shared/wallet-theme.css?v=20251214_01"/>
  <link rel="stylesheet" href="/shared/airdrop.css?v=20251214_01"/>

  <script src="/shared/airdrop.js?v=20251214_01" defer></script>
</head>
<body class="logos-ui">
  <header class="topbar">
    <div class="topbar__inner">
      <div class="brand">
        <div class="brand__mark"><span>LRB</span></div>
        <div class="brand__text">
          <div class="brand__title">LOGOS Airdrop</div>
          <div class="brand__sub">Dashboard · Wallet bind · Social verify</div>
        </div>
      </div>
      <div class="topbar__right">
        <div class="pill">API: <span class="mono">/airdrop-api</span></div>
      </div>
    </div>
  </header>

  <main class="container">
    <div class="stack">

      <section class="card hero">
        <div class="heroGrid">
          <div>
            <h1 class="heroTitle">Airdrop Dashboard</h1>
            <p class="muted heroSub">Выполняй задания → копи поинты → приглашай друзей.</p>
          </div>

          <div class="stats">
            <div class="stat">
              <div class="stat__k muted">Points</div>
              <div class="stat__v" id="s_points">—</div>
            </div>
            <div class="stat">
              <div class="stat__k muted">Rank</div>
              <div class="stat__v" id="s_rank">—</div>
            </div>
            <div class="stat">
              <div class="stat__k muted">Refs</div>
              <div class="stat__v" id="s_refs">—</div>
            </div>
          </div>
        </div>
      </section>

      <div class="grid-2">
        <section class="card">
          <header class="card__head">
            <h2>Токен</h2>
            <p class="muted">Скопируй token и реф‑ссылку (они же используются ботами/верификаторами).</p>
          </header>

          <div class="card__body stack">
            <div class="row2">
              <input id="inpToken" class="mono monoInput" readonly placeholder="token..." />
              <button id="btnCopyToken" class="secondary" type="button">Copy token</button>
            </div>

            <div class="row2">
              <input id="inpRef" class="mono monoInput" readonly placeholder="ref link..." />
              <button id="btnCopyRef" class="secondary" type="button">Copy link</button>
            </div>
          </div>
        </section>

        <section class="card">
          <header class="card__head">
            <h2>Задания</h2>
            <p class="muted">Нажимай “Refresh” после выполнения. Проверка идёт сервером.</p>
          </header>

          <div class="card__body stack">

            <div class="taskRow">
              <div class="taskL">
                <div class="taskTitle">Wallet</div>
                <div class="taskDesc muted">Привязка кошелька через challenge‑подпись.</div>
              </div>
              <div class="taskR">
                <span class="badge no" id="b_wallet">NO</span>
                <button id="btnWallet" class="primary" type="button">Connect</button>
              </div>
            </div>

            <div class="taskRow">
              <div class="taskL">
                <div class="taskTitle">Telegram</div>
                <div class="taskDesc muted">Подписка на канал @logosblockchain.</div>
              </div>
              <div class="taskR">
                <span class="badge wait" id="b_tg">WAIT</span>
                <a class="secondary" href="https://t.me/logosblockchain" target="_blank" rel="noopener noreferrer">Open</a>
              </div>
            </div>

            <div class="taskRow">
              <div class="taskL">
                <div class="taskTitle">X username</div>
                <div class="taskDesc muted">Нужен для автоматической проверки действий.</div>
                <div class="row2">
                  <input id="inpTwUser" class="mono monoInput" placeholder="@yourname" autocomplete="off"/>
                  <button id="btnTwSave" class="secondary" type="button">Save</button>
                </div>
              </div>
              <div class="taskR">
                <span class="badge wait" id="b_tw_user">WAIT</span>
              </div>
            </div>

            <div class="taskRow">
  <div class="taskLeft">
    <div class="taskTitle">X username</div>
    <div class="taskDesc muted">Введи свой @username (нужен для проверки лайков/ретвитов/постов)</div>
  </div>
  <div class="taskRight">
    <input id="inpXUser" class="mono monoInput" placeholder="@yourname" />
    <button id="btnXSave" class="secondary" type="button">Save</button>
    <button id="btnXVerify" class="primary" type="button">Verify</button>
  </div>
</div>

<div class="taskRow">
              <div class="taskL">
                <div class="taskTitle">X follow</div>
                <div class="taskDesc muted">Подписка на @RspLogos.</div>
              </div>
              <div class="taskR">
                <span class="badge wait" id="b_tw_follow">WAIT</span>
                <a class="secondary" href="https://x.com/RspLogos" target="_blank" rel="noopener noreferrer">Open</a>
              </div>
            </div>

            <div class="taskRow">
              <div class="taskL">
                <div class="taskTitle">X like</div>
                <div class="taskDesc muted">Любой лайк по последним постам @RspLogos засчитывается.</div>
              </div>
              <div class="taskR">
                <span class="badge wait" id="b_tw_like">WAIT</span>
                <a class="secondary" href="https://x.com/RspLogos" target="_blank" rel="noopener noreferrer">Open</a>
              </div>
            </div>

            <div class="taskRow">
              <div class="taskL">
                <div class="taskTitle">X repost / post</div>
                <div class="taskDesc muted">Любой ретвит @RspLogos ИЛИ пост с упоминанием @RspLogos.</div>
              </div>
              <div class="taskR">
                <span class="badge wait" id="b_tw_rt">WAIT</span>
                <a class="secondary" href="https://x.com/RspLogos" target="_blank" rel="noopener noreferrer">Open</a>
              </div>
            </div>

            <button id="btnRefresh" class="secondary btnRefresh" type="button">Refresh status</button>

          </div>
        </section>
      </div>

      <section class="card">
        <header class="card__head">
          <h2>Диагностика</h2>
          <p class="muted">Тут видно ответы API/ошибки.</p>
        </header>
        <pre id="out" class="mono outPanel"></pre>
      </section>

    </div>
  </main>
  <script defer src="/shared/airdrop-fix.js??v=20251215"></script>
</body>
</html>

```

## front: /var/www/logos/landing/landing/airdrop.html

### `/var/www/logos/landing/landing/airdrop.html`

```ini
<!doctype html>
<html lang="ru">
<head>
  <meta charset="utf-8" />
  <title>Airdrop LOGOS</title>
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <meta name="description" content="Airdrop LOGOS LRB — задания, статус выполнения и прогресс участия." />
  <link rel="stylesheet" href="styles.v20251124.css" />
  <style>
    body{
      margin:0;
      font-family:system-ui,-apple-system,"Inter",sans-serif;
      background:#05030b;
      color:#f5f0ff;
    }
    a{color:inherit;text-decoration:none}
    .airdrop-bg{
      min-height:100vh;
      background:
        radial-gradient(900px 900px at 15% 10%,rgba(169,107,255,.22),transparent 60%),
        radial-gradient(900px 900px at 85% 90%,rgba(90,60,170,.18),transparent 60%),
        radial-gradient(circle at 50% 50%,rgba(255,255,255,.03) 0,transparent 55%);
      position:relative;
      overflow:hidden;
    }
    .airdrop-grid{
      position:absolute;
      inset:0;
      opacity:.18;
      pointer-events:none;
      background-image:
        radial-gradient(circle at center,transparent 0 48%,rgba(255,255,255,.16) 48% 50%,transparent 50% 100%);
      background-size:120px 120px;
      mix-blend-mode:screen;
    }
    .airdrop-page{
      position:relative;
      max-width:960px;
      margin:0 auto;
      padding:32px 16px 64px;
    }
    .airdrop-header{
      display:flex;
      justify-content:space-between;
      align-items:flex-start;
      gap:16px;
      margin-bottom:24px;
    }
    .airdrop-left{
      flex:1 1 auto;
    }
    .airdrop-breadcrumb{
      font-size:12px;
      text-transform:uppercase;
      letter-spacing:.16em;
      color:#b9afd4;
      margin-bottom:8px;
    }
    .airdrop-title{
      font-size:24px;
      font-weight:700;
      margin:0;
    }
    .airdrop-back{
      font-size:14px;
      color:#b9afd4;
      display:inline-flex;
      align-items:center;
      gap:6px;
      margin-top:8px;
    }
    .airdrop-back::before{
      content:"←";
      font-size:14px;
    }
    .airdrop-lang{
      display:flex;
      gap:6px;
      align-items:center;
      justify-content:flex-end;
      flex:0 0 auto;
    }
    .lang-label{
      font-size:11px;
      color:#b9afd4;
      text-transform:uppercase;
      letter-spacing:.12em;
    }
    .lang-btn{
      border-radius:999px;
      padding:4px 10px;
      border:1px solid rgba(255,255,255,.18);
      background:rgba(11,7,32,.9);
      color:#f5f0ff;
      font-size:11px;
      cursor:pointer;
    }
    .lang-btn--active{
      background:linear-gradient(135deg,#ff7ae0,#a96bff);
      color:#1a102b;
      border-color:transparent;
      font-weight:600;
    }

    .airdrop-card{
      background:rgba(10,6,24,.96);
      border-radius:18px;
      padding:20px 20px 18px;
      box-shadow:0 18px 60px rgba(0,0,0,.6);
      border:1px solid rgba(255,255,255,.06);
      margin-bottom:24px;
    }
    .airdrop-card p{margin:0 0 6px;font-size:14px;color:#d2caee}
    .airdrop-status-text{
      font-size:14px;
      margin-top:8px;
      color:#ff9f9f;
    }

    .tasks-title{
      font-size:18px;
      font-weight:600;
      margin-bottom:16px;
    }
    .task{
      display:flex;
      align-items:flex-start;
      gap:12px;
      padding:14px 14px 12px;
      border-radius:14px;
      background:rgba(16,10,40,.95);
      border:1px solid rgba(255,255,255,.05);
      margin-bottom:10px;
    }
    .task:last-child{margin-bottom:0}
    .task__check{
      width:20px;
      height:20px;
      border-radius:6px;
      border:1px solid rgba(255,255,255,.3);
      display:flex;
      align-items:center;
      justify-content:center;
      flex-shrink:0;
      margin-top:2px;
    }
    .task__check input{
      width:16px;
      height:16px;
      accent-color:#a96bff;
      cursor:default;
    }
    .task__body{
      font-size:14px;
    }
    .task__title{
      font-weight:600;
      margin-bottom:2px;
    }
    .task__desc{
      font-size:13px;
      color:#b9afd4;
    }
    .task--done{
      border-color:rgba(169,107,255,.8);
      background:linear-gradient(135deg,rgba(169,107,255,.16),rgba(16,10,40,.98));
    }
    .task--done .task__title{color:#fdf5ff}
    .task--done .task__check input{accent-color:#42d96b}

    .airdrop-footer{
      display:flex;
      flex-wrap:wrap;
      gap:12px;
      align-items:center;
      margin-top:16px;
      font-size:13px;
      color:#b9afd4;
    }
    .airdrop-footer span{white-space:nowrap}

    .btn-row{
      display:flex;
      flex-wrap:wrap;
      gap:10px;
      margin-top:18px;
    }
    .btn{
      border-radius:999px;
      padding:9px 18px;
      font-size:14px;
      border:1px solid rgba(255,255,255,.18);
      background:rgba(11,7,32,.95);
      color:#f5f0ff;
      cursor:pointer;
      display:inline-flex;
      align-items:center;
      gap:8px;
    }
    .btn--primary{
      background:linear-gradient(135deg,#ff7ae0,#a96bff);
      border:none;
      color:#1a102b;
      font-weight:600;
    }
    .btn:disabled{
      opacity:.6;
      cursor:default;
    }
    .btn-icon{
      width:18px;height:18px;border-radius:999px;background:rgba(0,0,0,.3);
      display:flex;align-items:center;justify-content:center;font-size:11px;
    }

    .ref-block{
      font-size:13px;
      margin-top:18px;
      color:#b9afd4;
    }
    .ref-link{
      display:block;
      margin-top:4px;
      font-size:13px;
      word-break:break-all;
      color:#f5f0ff;
    }
    @media(max-width:600px){
      .airdrop-page{padding:20px 14px 48px}
      .airdrop-title{font-size:20px}
      .airdrop-card{padding:16px 14px 14px}
      .airdrop-header{flex-direction:column;align-items:flex-start}
      .airdrop-lang{align-self:flex-end}
    }
  </style>
</head>
<body>
  <div class="airdrop-bg">
    <div class="airdrop-grid"></div>
    <div class="airdrop-page">
      <header class="airdrop-header">
        <div class="airdrop-left">
          <div class="airdrop-breadcrumb" data-i18n="breadcrumb">LOGOS • РЕЗОНАНСНЫЙ БЛОКЧЕЙН</div>
          <h1 class="airdrop-title" data-i18n="title">🎁 Airdrop LOGOS</h1>
          <a href="/" class="airdrop-back" data-i18n="back">На главную</a>
        </div>
        <div class="airdrop-lang">
          <span class="lang-label" data-i18n="lang_label">Язык</span>
          <button type="button" class="lang-btn lang-btn--active" data-lang-switch="ru">RU</button>
          <button type="button" class="lang-btn" data-lang-switch="en">EN</button>
          <button type="button" class="lang-btn" data-lang-switch="de">DE</button>
        </div>
      </header>

      <div class="airdrop-card">
        <p data-i18n="intro">
          Здесь ты видишь список заданий для участия в airdrop LOGOS LRB и статус их выполнения.
          Все проверки по Twitter, Telegram и кошельку проходят через защищённый бэкенд.
        </p>
        <p class="airdrop-status-text" data-status-text>
          Создаём airdrop‑профиль…
        </p>
      </div>

      <div class="airdrop-card">
        <div class="tasks-title" data-i18n="tasks_title">Задания airdrop</div>

        <div class="task" data-task="wallet">
          <div class="task__check">
            <input type="checkbox" disabled />
          </div>
          <div class="task__body">
            <div class="task__title" data-i18n="task_wallet_title">Привязка LOGOS‑кошелька</div>
            <div class="task__desc" data-i18n="task_wallet_desc">
              Подтверди свой LOGOS‑адрес (RID) в airdrop‑профиле.
            </div>
          </div>
        </div>

        <div class="task" data-task="telegram">
          <div class="task__check">
            <input type="checkbox" disabled />
          </div>
          <div class="task__body">
            <div class="task__title" data-i18n="task_tg_title">Подписка на Telegram</div>
            <div class="task__desc" data-i18n="task_tg_desc">
              Подписка на канал @logosblockchain и подтверждение через бота.
            </div>
          </div>
        </div>

        <div class="task" data-task="twitter_follow">
          <div class="task__check">
            <input type="checkbox" disabled />
          </div>
          <div class="task__body">
            <div class="task__title" data-i18n="task_tw_follow_title">Подписка на X (Twitter)</div>
            <div class="task__desc" data-i18n="task_tw_follow_desc">
              Подписка на аккаунт @OfficiaLogosLRB.
            </div>
          </div>
        </div>

        <div class="task" data-task="twitter_like">
          <div class="task__check">
            <input type="checkbox" disabled />
          </div>
          <div class="task__body">
            <div class="task__title" data-i18n="task_tw_like_title">Лайк твита кампании</div>
            <div class="task__desc" data-i18n="task_tw_like_desc">
              Лайк закреплённого твита airdrop‑кампании.
            </div>
          </div>
        </div>

        <div class="task" data-task="twitter_retweet">
          <div class="task__check">
            <input type="checkbox" disabled />
          </div>
          <div class="task__body">
            <div class="task__title" data-i18n="task_tw_rt_title">Ретвит твита кампании</div>
            <div class="task__desc" data-i18n="task_tw_rt_desc">
              Ретвит закреплённого твита в период airdrop.
            </div>
          </div>
        </div>

        <div class="task" data-task="referrals">
          <div class="task__check">
            <input type="checkbox" disabled />
          </div>
          <div class="task__body">
            <div class="task__title" data-i18n="task_ref_title">Рефералы</div>
            <div class="task__desc" data-i18n="task_ref_desc">
              Приглашение друзей по личной ссылке (до 5 человек с полным выполнением заданий).
            </div>
          </div>
        </div>

        <div class="airdrop-footer">
          <span><span data-i18n="points_label">Очки</span>: <strong data-points>0</strong></span>
          <span>• <span data-i18n="refs_label">Рефералы</span>: <strong data-referrals>0 / 5</strong></span>
          <span>• <span data-i18n="rank_label">Позиция в рейтинге</span>: <strong data-rank>—</strong></span>
        </div>

        <div class="btn-row">
          <button class="btn btn--primary" type="button" data-btn-refresh>
            <span class="btn-icon">⟳</span>
            <span data-i18n="btn_check">Проверить выполнение</span>
          </button>
          <a class="btn" href="https://t.me/logosblockchain" target="_blank" rel="noopener">
            <span class="btn-icon">TG</span>
            <span data-i18n="btn_open_tg">Открыть Telegram‑бота</span>
          </a>
          <a class="btn" href="https://x.com/RspLogos" target="_blank" rel="noopener">
            <span class="btn-icon">X</span>
            <span data-i18n="btn_open_x">Перейти в X (Twitter)</span>
          </a>
        </div>

        <div class="ref-block">
          <span data-i18n="ref_title">Твоя личная ссылка (для приглашения друзей):</span>
          <span data-ref-link-state data-i18n="ref_creating">Создаётся…</span>
          <a class="ref-link" href="#" target="_blank" rel="noopener" style="display:none" data-ref-link></a>
        </div>
      </div>
    </div>
  </div>

  <script>
  (() => {
    const I18N = {
      ru: {
        breadcrumb: "LOGOS • РЕЗОНАНСНЫЙ БЛОКЧЕЙН",
        title: "🎁 Airdrop LOGOS",
        back: "На главную",
        lang_label: "Язык",
        intro: "Здесь ты видишь список заданий для участия в airdrop LOGOS LRB и статус их выполнения. Все проверки по Twitter, Telegram и кошельку проходят через защищённый бэкенд.",
        tasks_title: "Задания airdrop",
        task_wallet_title: "Привязка LOGOS‑кошелька",
        task_wallet_desc: "Подтверди свой LOGOS‑адрес (RID) в airdrop‑профиле.",
        task_tg_title: "Подписка на Telegram",
        task_tg_desc: "Подписка на канал @logosblockchain и подтверждение через бота.",
        task_tw_follow_title: "Подписка на X (Twitter)",
        task_tw_follow_desc: "Подписка на аккаунт @OfficiaLogosLRB.",
        task_tw_like_title: "Лайк твита кампании",
        task_tw_like_desc: "Лайк закреплённого твита airdrop‑кампании.",
        task_tw_rt_title: "Ретвит твита кампании",
        task_tw_rt_desc: "Ретвит закреплённого твита в период airdrop.",
        task_ref_title: "Рефералы",
        task_ref_desc: "Приглашение друзей по личной ссылке (до 5 человек с полным выполнением заданий).",
        points_label: "Очки",
        refs_label: "Рефералы",
        rank_label: "Позиция в рейтинге",
        btn_check: "Проверить выполнение",
        btn_open_tg: "Открыть Telegram‑бота",
        btn_open_x: "Перейти в X (Twitter)",
        ref_title: "Твоя личная ссылка (для приглашения друзей):",
        ref_creating: "Создаётся…",
        status_loading: "Создаём airdrop‑профиль…",
        status_ready: "Профиль airdrop создан. Выполни задания и нажми «Проверить выполнение».",
        status_reg_error: "Не удалось создать airdrop‑профиль. Обнови страницу или попробуй позже.",
        status_status_error: "Не удалось получить статус. Попробуй ещё раз позже."
      },
      en: {
        breadcrumb: "LOGOS • RESONANCE BLOCKCHAIN",
        title: "🎁 LOGOS Airdrop",
        back: "Back to main",
        lang_label: "Language",
        intro: "Here you see the list of tasks for the LOGOS LRB airdrop and your completion status. All checks for Twitter, Telegram and wallet go through a protected backend.",
        tasks_title: "Airdrop tasks",
        task_wallet_title: "Bind your LOGOS wallet",
        task_wallet_desc: "Confirm your LOGOS address (RID) in the airdrop profile.",
        task_tg_title: "Telegram subscription",
        task_tg_desc: "Subscribe to the @logosblockchain channel and confirm via the bot.",
        task_tw_follow_title: "Follow in X (Twitter)",
        task_tw_follow_desc: "Follow the @OfficiaLogosLRB account.",
        task_tw_like_title: "Like the campaign tweet",
        task_tw_like_desc: "Like the pinned airdrop campaign tweet.",
        task_tw_rt_title: "Retweet the campaign tweet",
        task_tw_rt_desc: "Retweet the pinned tweet during the airdrop period.",
        task_ref_title: "Referrals",
        task_ref_desc: "Invite friends via your personal link (up to 5 users who complete all tasks).",
        points_label: "Points",
        refs_label: "Referrals",
        rank_label: "Rank",
        btn_check: "Check progress",
        btn_open_tg: "Open Telegram bot",
        btn_open_x: "Open X (Twitter)",
        ref_title: "Your personal link (to invite friends):",
        ref_creating: "Creating…",
        status_loading: "Creating your airdrop profile…",
        status_ready: "Airdrop profile created. Complete tasks and click “Check progress”.",
        status_reg_error: "Failed to create airdrop profile. Refresh the page or try again later.",
        status_status_error: "Failed to fetch status. Please try again later."
      },
      de: {
        breadcrumb: "LOGOS • RESONANZ BLOCKCHAIN",
        title: "🎁 LOGOS Airdrop",
        back: "Zur Startseite",
        lang_label: "Sprache",
        intro: "Hier siehst du die Aufgaben für den LOGOS LRB Airdrop und deinen Fortschritt. Alle Prüfungen für Twitter, Telegram und Wallet laufen über ein geschütztes Backend.",
        tasks_title: "Airdrop‑Aufgaben",
        task_wallet_title: "LOGOS‑Wallet verknüpfen",
        task_wallet_desc: "Bestätige deine LOGOS‑Adresse (RID) im Airdrop‑Profil.",
        task_tg_title: "Telegram‑Abonnement",
        task_tg_desc: "Abonniere den Kanal @logosblockchain und bestätige über den Bot.",
        task_tw_follow_title: "Follow in X (Twitter)",
        task_tw_follow_desc: "Folge dem Account @OfficiaLogosLRB.",
        task_tw_like_title: "Like des Kampagnen‑Tweets",
        task_tw_like_desc: "Like den angehefteten Airdrop‑Kampagnen‑Tweet.",
        task_tw_rt_title: "Retweet des Kampagnen‑Tweets",
        task_tw_rt_desc: "Retweete den angehefteten Tweet während der Airdrop‑Phase.",
        task_ref_title: "Referrals",
        task_ref_desc: "Lade Freunde über deinen persönlichen Link ein (bis zu 5 Nutzer mit vollständigen Aufgaben).",
        points_label: "Punkte",
        refs_label: "Referrals",
        rank_label: "Rang",
        btn_check: "Fortschritt prüfen",
        btn_open_tg: "Telegram‑Bot öffnen",
        btn_open_x: "X (Twitter) öffnen",
        ref_title: "Dein persönlicher Link (zum Einladen von Freunden):",
        ref_creating: "Wird erstellt…",
        status_loading: "Airdrop‑Profil wird erstellt…",
        status_ready: "Airdrop‑Profil erstellt. Erledige die Aufgaben und klicke „Fortschritt prüfen“.",
        status_reg_error: "Airdrop‑Profil konnte nicht erstellt werden. Seite neu laden oder später erneut versuchen.",
        status_status_error: "Status konnte nicht abgerufen werden. Bitte später erneut versuchen."
      }
    };

    const TOKEN_KEY = "logos_airdrop_token";
    const LANG_KEY = "logos_airdrop_lang";
    const API_BASE = "/api/airdrop";

    const els = {
      statusText: document.querySelector("[data-status-text]"),
      tasks: {
        wallet: document.querySelector('[data-task="wallet"]'),
        telegram: document.querySelector('[data-task="telegram"]'),
        twitter_follow: document.querySelector('[data-task="twitter_follow"]'),
        twitter_like: document.querySelector('[data-task="twitter_like"]'),
        twitter_retweet: document.querySelector('[data-task="twitter_retweet"]'),
        referrals: document.querySelector('[data-task="referrals"]'),
      },
      points: document.querySelector("[data-points]"),
      refs: document.querySelector("[data-referrals]"),
      rank: document.querySelector("[data-rank]"),
      refLinkState: document.querySelector("[data-ref-link-state]"),
      refLink: document.querySelector("[data-ref-link]"),
      btnRefresh: document.querySelector("[data-btn-refresh]"),
    };

    let currentLang = "ru";

    function detectLang() {
      try {
        const saved = localStorage.getItem(LANG_KEY);
        if (saved && I18N[saved]) return saved;
      } catch {}
      const nav = (navigator.language || navigator.userLanguage || "").slice(0,2).toLowerCase();
      if (I18N[nav]) return nav;
      return "en";
    }

    function applyLang(lang) {
      if (!I18N[lang]) lang = "en";
      currentLang = lang;
      try { localStorage.setItem(LANG_KEY, lang); } catch {}

      const dict = I18N[lang];

      document.documentElement.lang = lang;

      document.querySelectorAll("[data-lang-switch]").forEach(btn => {
        btn.classList.toggle("lang-btn--active", btn.dataset.langSwitch === lang);
      });

      document.querySelectorAll("[data-i18n]").forEach(node => {
        const key = node.dataset.i18n;
        if (key && dict[key]) node.textContent = dict[key];
      });

      if (els.statusText) {
        const key = els.statusText.dataset.statusKey || "status_ready";
        if (dict[key]) els.statusText.textContent = dict[key];
      }

      if (els.refLinkState) {
        const key = els.refLinkState.dataset.i18n;
        if (key && dict[key]) els.refLinkState.textContent = dict[key];
      }
    }

    function setStatusKey(key) {
      if (!els.statusText) return;
      els.statusText.dataset.statusKey = key;
      const dict = I18N[currentLang];
      if (dict && dict[key]) {
        els.statusText.textContent = dict[key];
      }
    }

    function setTask(name, done) {
      const el = els.tasks[name];
      if (!el) return;
      el.classList.toggle("task--done", !!done);
      const cb = el.querySelector("input[type=checkbox]");
      if (cb) cb.checked = !!done;
    }

    async function apiRegister(refToken) {
      const payload = refToken ? { ref_token: refToken } : {};
      const r = await fetch(API_BASE + "/register_web", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
        credentials: "same-origin",
      });
      if (!r.ok) throw new Error("register failed");
      return r.json();
    }

    async function apiStatus(token) {
      const r = await fetch(API_BASE + "/status?token=" + encodeURIComponent(token), {
        credentials: "same-origin",
      });
      if (!r.ok) throw new Error("status failed");
      return r.json();
    }

    function updateFromStatus(s) {
      if (!s || s.error || s.ok === false) {
        setStatusKey("status_status_error");
        return;
      }

      setTask("wallet", s.wallet_bound);
      setTask("telegram", s.telegram_ok);
      setTask("twitter_follow", s.twitter_follow);
      setTask("twitter_like", s.twitter_like);
      setTask("twitter_retweet", s.twitter_retweet);
      setTask("referrals", (s.referrals || 0) >= (s.referrals_target || 5));

      if (els.points) els.points.textContent = s.points ?? 0;
      if (els.refs) els.refs.textContent = (s.referrals || 0) + " / " + (s.referrals_target || 5);
      if (els.rank) {
        els.rank.textContent = s.rank && s.total
          ? s.rank + " / " + s.total
          : "—";
      }

      if (s.referral_url && els.refLink && els.refLinkState) {
        els.refLinkState.style.display = "none";
        els.refLink.style.display = "block";
        els.refLink.href = s.referral_url;
        els.refLink.textContent = s.referral_url;
      }

      setStatusKey("status_ready");
    }

    function getUrlRefParam() {
      try {
        const url = new URL(window.location.href);
        const r = url.searchParams.get("ref");
        return r || null;
      } catch {
        return null;
      }
    }

    function stripRefFromUrl() {
      try {
        const url = new URL(window.location.href);
        if (url.searchParams.has("ref")) {
          url.searchParams.delete("ref");
          window.history.replaceState({}, "", url.toString());
        }
      } catch {}
    }

    async function init() {
      const initialLang = detectLang();
      applyLang(initialLang);

      if (els.statusText) {
        setStatusKey("status_loading");
      }

      let token = null;
      try {
        token = localStorage.getItem(TOKEN_KEY);
      } catch {}

      const refToken = getUrlRefParam();

      if (!token) {
        try {
          const data = await apiRegister(refToken);
          token = data.token;
          if (!token) throw new Error("no token in response");
          try { localStorage.setItem(TOKEN_KEY, token); } catch {}
        } catch (e) {
          console.error(e);
          setStatusKey("status_reg_error");
          return;
        }
      }

      stripRefFromUrl();

      try {
        const st = await apiStatus(token);
        updateFromStatus(st);
      } catch (e) {
        console.error(e);
        setStatusKey("status_status_error");
      }

      if (els.btnRefresh) {
        els.btnRefresh.addEventListener("click", async (ev) => {
          ev.preventDefault();
          let currentToken = null;
          try { currentToken = localStorage.getItem(TOKEN_KEY); } catch {}
          if (!currentToken) return;
          els.btnRefresh.disabled = true;
          try {
            const st = await apiStatus(currentToken);
            updateFromStatus(st);
          } catch (e) {
            console.error(e);
            setStatusKey("status_status_error");
          } finally {
            els.btnRefresh.disabled = false;
          }
        });
      }

      document.querySelectorAll("[data-lang-switch]").forEach(btn => {
        btn.addEventListener("click", () => {
          applyLang(btn.dataset.langSwitch);
        });
      });
    }

    document.addEventListener("DOMContentLoaded", init);
  })();
  </script>
  <script defer src="/shared/airdrop-fix.js??v=20251215"></script>
</body>
</html>

```

## shared: airdrop.css

### `/opt/logos/www/shared/airdrop.css`

```ini
/* LOGOS Airdrop UI (CSP-safe) */

.heroTitle{ margin:0 0 6px; }
.heroSub{ margin:0; }

.heroGrid{
  display:flex;
  gap:18px;
  justify-content:space-between;
  align-items:flex-start;
  flex-wrap:wrap;
}

.stats{
  display:flex;
  gap:10px;
  flex-wrap:wrap;
}

.stat{
  padding:10px 12px;
  border-radius:14px;
  border:1px solid rgba(255,255,255,.10);
  background:rgba(0,0,0,.18);
  min-width:120px;
}

.stat__k{ font-size:12px; }
.stat__v{ font-size:18px; font-weight:700; margin-top:2px; }

.row2{
  display:flex;
  gap:10px;
  align-items:center;
  flex-wrap:wrap;
}

.stack{ display:flex; flex-direction:column; gap:14px; }

.monoInput{
  width:100%;
  min-width:260px;
  padding:12px 12px;
  border-radius:14px;
  border:1px solid rgba(255,255,255,.10);
  background:rgba(0,0,0,.22);
  color:var(--text);
  font-family:var(--mono);
  font-size:13px;
  outline:none;
}

.monoInput:focus{
  border-color:rgba(77,163,255,.35);
  box-shadow:0 0 0 4px rgba(77,163,255,.10);
}

.taskRow{
  display:flex;
  justify-content:space-between;
  align-items:flex-start;
  gap:12px;
  padding:12px 12px;
  border-radius:16px;
  border:1px solid rgba(255,255,255,.08);
  background:rgba(0,0,0,.16);
}

.taskL{ flex:1; min-width:260px; }
.taskR{ display:flex; gap:10px; align-items:center; flex-wrap:wrap; }

.taskTitle{ font-weight:700; }
.taskDesc{ margin-top:4px; font-size:12.5px; color:var(--muted2); }

.btnRefresh{ margin-top:12px; }
.outPanel{ min-height:320px; max-height:420px; overflow:auto; }

.badge{
  padding:6px 10px;
  border-radius:999px;
  border:1px solid rgba(255,255,255,.12);
  font-size:12px;
  font-weight:700;
}
.badge.ok{ border-color:rgba(45,227,138,.35); color:rgba(45,227,138,.95); }
.badge.no{ border-color:rgba(255,77,109,.35); color:rgba(255,77,109,.95); }
.badge.wait{ border-color:rgba(255,255,255,.18); color:rgba(233,238,248,.75); }

```

## shared: airdrop.js

### `/opt/logos/www/shared/airdrop.js`

```ini
/* LOGOS Airdrop Front (CSP-safe) */

(function(){
  const API = "/airdrop-api/api/airdrop";
  const LS_TOKEN = "logos_airdrop_token";
  const LS_REF   = "logos_airdrop_ref";
  const LS_XUSER = "logos_airdrop_xuser";

  const $ = (s)=>document.querySelector(s);

  function out(msg){
    const el = $("#out");
    if(!el) return;
    el.textContent = String(msg || "");
  }

  function badge(sel, state){
    const el = $(sel);
    if(!el) return;
    el.classList.remove("ok","no","wait");
    if(state === "ok"){ el.classList.add("ok"); el.textContent = "OK"; return; }
    if(state === "no"){ el.classList.add("no"); el.textContent = "NO"; return; }
    el.classList.add("wait"); el.textContent = "WAIT";
  }

  function normX(u){
    u = (u||"").trim();
    if(u.startsWith("@")) u = u.slice(1);
    u = u.replace("https://x.com/","").replace("http://x.com/","");
    u = u.replace("https://twitter.com/","").replace("http://twitter.com/","");
    u = u.split("?")[0].split("/")[0].trim();
    return u.toLowerCase();
  }

  async function apiPost(path, body){
    const r = await fetch(API + path, {
      method: "POST",
      headers: {"content-type":"application/json"},
      body: JSON.stringify(body || {})
    });
    const txt = await r.text();
    let j = null;
    try { j = JSON.parse(txt); } catch(e) {}
    if(!r.ok){
      throw new Error("API " + r.status + ": " + (j?.message || txt || "error"));
    }
    return j;
  }

  async function status(){
    const tok = localStorage.getItem(LS_TOKEN) || "";
    if(!tok){
      out("Нет token. Зарегистрируйся заново на airdrop (register_web).");
      return;
    }
    const st = await apiPost("/status", {token: tok});
    $("#s_points").textContent = String(st.points ?? "—");
    $("#s_rank").textContent   = String(st.rank ?? "—");
    $("#s_refs").textContent   = String(st.referrals ?? st.refs ?? "—");

    badge("#b_wallet", st.wallet_bound ? "ok" : "no");
    badge("#b_tg", st.telegram_ok ? "ok" : "wait");
    badge("#b_tw_follow", st.twitter_follow ? "ok" : "wait");
    badge("#b_tw_like", st.twitter_like ? "ok" : "wait");
    badge("#b_tw_rt", st.twitter_retweet ? "ok" : "wait");

    const x = localStorage.getItem(LS_XUSER) || "";
    if(x) badge("#b_tw_user","ok"); else badge("#b_tw_user","wait");
    const inp = $("#inpTwUser");
    if(inp && x && !inp.value) inp.value = x;

    const tokenEl = $("#inpToken");
    if(tokenEl) tokenEl.value = tok;

    const ref = localStorage.getItem(LS_REF) || "";
    const refEl = $("#inpRef");
    if(refEl) refEl.value = ref;

    out(JSON.stringify(st, null, 2));
  }

  async function verifyX(){
    const tok = localStorage.getItem(LS_TOKEN) || "";
    if(!tok) throw new Error("no token");
    const res = await apiPost("/verify_x", {token: tok});
    out(JSON.stringify(res, null, 2));
  }

  async function saveXUser(){
    const tok = localStorage.getItem(LS_TOKEN) || "";
    if(!tok) throw new Error("no token");
    const inp = $("#inpTwUser");
    const u = normX(inp ? inp.value : "");
    if(!u) throw new Error("Введите X username");
    await apiPost("/set_x_username", {token: tok, twitter_username: u});
    localStorage.setItem(LS_XUSER, u);
    badge("#b_tw_user","ok");
  }

  async function walletConnect(){
    const tok = localStorage.getItem(LS_TOKEN) || "";
    if(!tok) throw new Error("no token");
    // wallet flow уже сделан у тебя, тут оставляем как есть:
    const ch = await apiPost("/wallet_challenge", {token: tok});
    const url = "/wallet/auth.html?connect=1&challenge=" + encodeURIComponent(ch.challenge || "");
    window.open(url, "_blank", "noopener,noreferrer");
    out("Открыл wallet для подписи challenge.");
  }

  function copy(id){
    const el = $(id);
    if(!el) return;
    el.select && el.select();
    try{ document.execCommand("copy"); }catch(e){}
  }

  function bind(){
    const b1=$("#btnCopyToken"); if(b1) b1.addEventListener("click", ()=>copy("#inpToken"));
    const b2=$("#btnCopyRef");   if(b2) b2.addEventListener("click", ()=>copy("#inpRef"));

    const bw=$("#btnWallet"); if(bw) bw.addEventListener("click", ()=>walletConnect().catch(e=>out(e.message||e)));
    const bs=$("#btnTwSave"); if(bs) bs.addEventListener("click", ()=>saveXUser().then(()=>status()).catch(e=>out(e.message||e)));

    const br=$("#btnRefresh"); if(br) br.addEventListener("click", async ()=>{
      try{
        await verifyX();
        await status();
      }catch(e){
        out(e.message||e);
      }
    });

    status().catch(e=>out(e.message||e));
  }

  document.addEventListener("DOMContentLoaded", bind);
})();

// --- X username UI wiring (fallback) ----------------------------------------
(() => {
  const inp = document.getElementById("inpXUser");
  const btnSave = document.getElementById("btnXSave");
  const btnVerify = document.getElementById("btnXVerify");
  if (!inp || !btnSave || !btnVerify) return;

  // защита от двойного бинда
  if (btnSave.dataset && btnSave.dataset.boundXUser === "1") return;
  if (btnSave.dataset) btnSave.dataset.boundXUser = "1";

  const getTok = () => {
    const el = document.getElementById("inpToken");
    const t = (el && el.value ? el.value : (localStorage.getItem("airdrop_token") || "")).trim();
    return t;
  };

  btnSave.addEventListener("click", async () => {
    try {
      const tok = getTok();
      if (!tok) return alert("Нет token. Сначала registration/refresh.");
      const u = (inp.value || "").trim();
      if (!u) return alert("Введи @username.");
      await apiPost("/set_x_username", { token: tok, twitter_username: u });
      location.reload();
    } catch (e) {
      console.error(e);
      alert("Save failed (см. console).");
    }
  });

  btnVerify.addEventListener("click", async () => {
    try {
      const tok = getTok();
      if (!tok) return alert("Нет token. Сначала registration/refresh.");
      await apiPost("/verify_x", { token: tok });
      location.reload();
    } catch (e) {
      console.error(e);
      alert("Verify failed (см. console).");
    }
  });
})();
// ---------------------------------------------------------------------------


```

## shared: airdrop-fix.js

### `/opt/logos/www/shared/airdrop-fix.js`

```ini
(() => {
  'use strict';
  const API='/airdrop-api/api/airdrop';
  const K_T='logos_airdrop_token_v1', K_X='logos_airdrop_xu_v1';

  const qs = (k)=>{ try{return new URL(location.href).searchParams.get(k);}catch{return null;} };

  const post = async (path, body) => {
    const r = await fetch(API+path, {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify(body||{}),
      credentials:'same-origin',
    });
    const ct=r.headers.get('content-type')||'';
    const data = ct.includes('application/json') ? await r.json().catch(()=>({})) : await r.text().catch(()=> '');
    return {ok:r.ok, status:r.status, data};
  };

  const findInput = (re)=> Array.from(document.querySelectorAll('input')).find(i => re.test((i.placeholder||'')+' '+(i.name||'')+' '+(i.id||''))) || null;
  const findBtn = (t)=> Array.from(document.querySelectorAll('button,a')).find(b => ((b.textContent||'').trim().toLowerCase()===t)) || null;

  async function ensureToken(){
    let t=(localStorage.getItem(K_T)||'').trim();
    const ti = findInput(/token/i);
    if (ti && (ti.value||'').trim().length>=8) { t=(ti.value||'').trim(); localStorage.setItem(K_T,t); return t; }
    if (!t){
      const ref = (qs('ref')||qs('ref_token')||'').trim();
      const rr = await post('/register_web', ref ? {ref_token:ref}:{});
      if(!rr.ok || !rr.data || !rr.data.token) throw new Error('register_web failed');
      t=String(rr.data.token); localStorage.setItem(K_T,t);
      if (ti) ti.value=t;
    }
    return t;
  }

  function setRef(token, siteOrigin){
    const ri = findInput(/ref/i);
    if(!ri) return;
    const origin=(siteOrigin||'https://mw-expedition.com').replace(/\/+$/,'');
    ri.value = `${origin}/airdrop?ref=${encodeURIComponent(token)}`;
    const copy = findBtn('copy link') || findBtn('copy');
    if(copy && !copy.__l){ copy.__l=true; copy.addEventListener('click', async (e)=>{ e.preventDefault(); try{ await navigator.clipboard.writeText(ri.value);}catch{} }); }
  }

  function setTG(token){
    const url=`https://t.me/Logos_lrb_bot?start=airdrop_${encodeURIComponent(token)}`;
    for(const a of Array.from(document.querySelectorAll('a'))){
      const href=(a.getAttribute('href')||'');
      if(href.includes('t.me') && href.toLowerCase().includes('logos')) a.href=url;
      if(((a.textContent||'').trim().toLowerCase()==='open') && (a.closest('*')?.textContent||'').toLowerCase().includes('telegram')) a.href=url;
    }
  }

  function patchBadges(s){
    const set = (k, ok)=>{
      const blocks = Array.from(document.querySelectorAll('div,li,section'));
      const b = blocks.find(x => (x.textContent||'').toLowerCase().includes(k) && /(wait|ok)/i.test(x.textContent||''));
      if(!b) return;
      const badge = Array.from(b.querySelectorAll('span,div')).find(x => /^(wait|ok)$/i.test((x.textContent||'').trim()));
      if(badge) badge.textContent = ok ? 'OK':'WAIT';
    };
    set('wallet', !!s.wallet_bound);
    set('telegram', !!s.telegram_ok);
    set('follow', !!s.twitter_follow);
    set('like', !!s.twitter_like);
    set('repost', !!s.twitter_retweet);
    set('retweet', !!s.twitter_retweet);
  }

  async function refresh(){
    let t = await ensureToken();
    let r = await post('/status', {token:t});
    if(!r.ok && r.status===404){
      localStorage.removeItem(K_T);
      t = await ensureToken();
      r = await post('/status', {token:t});
    }
    if(!r.ok) return null;
    const s=r.data||{};
    setRef(t, s.site_origin);
    setTG(t);
    patchBadges(s);
    return s;
  }

  function wireX(){
    const xu = findInput(/yourname|username|twitter|x/i);
    const saved=(localStorage.getItem(K_X)||'').trim();
    if(xu && saved && !(xu.value||'').trim()) xu.value=saved;

    for(const b of Array.from(document.querySelectorAll('button')).filter(x => (x.textContent||'').trim().toLowerCase()==='save')){
      if(b.__xs) continue; b.__xs=true;
      b.addEventListener('click', async (e)=>{
        e.preventDefault();
        const t=await ensureToken();
        const inp = findInput(/yourname|username|twitter|x/i);
        let v=(inp?.value||'').trim().replace(/^@/,'');
        if(!v) return;
        localStorage.setItem(K_X,v);
        // ВАЖНО: поле именно twitter_username
        await post('/set_x_username', {token:t, twitter_username:v});
        await refresh();
      });
    }

    const vb=findBtn('verify');
    if(vb && !vb.__xv){ vb.__xv=true;
      vb.addEventListener('click', async (e)=>{
        e.preventDefault();
        const t=await ensureToken();
        await post('/verify_x', {token:t});
        await refresh();
      });
    }
  }

  function wireRefresh(){
    const b=findBtn('refresh status') || findBtn('refresh');
    if(!b || b.__rs) return;
    b.__rs=true;
    b.addEventListener('click', async (e)=>{ e.preventDefault(); await refresh(); });
  }

  async function boot(){
    try{
      await ensureToken();
      wireRefresh();
      wireX();
      await refresh();
    }catch(e){ console.error('airdrop-fix boot', e); }
  }

  if(document.readyState==='loading') document.addEventListener('DOMContentLoaded', boot);
  else boot();

  function setLatestTweetLink(st) {
    try {
      const id = st && (st.x_latest_tweet_id || st.x_latest_tweet || st.latest_tweet_id);
      if (!id) return;
      const url = `https://x.com/RspLogos/status/${id}`;
      const el = document.querySelector('[data-task="x_repost"], #task_x_repost, #xRepostLink') || null;
      // fallback: find by text
      let container = el;
      if (!container) {
        const nodes = Array.from(document.querySelectorAll("div,section,li,p"));
        container = nodes.find(n => (n.textContent||"").toLowerCase().includes("x repost") || (n.textContent||"").toLowerCase().includes("ретвит"));
      }
      if (!container) return;
      let a = document.getElementById("x_latest_tweet_a");
      if (!a) {
        a = document.createElement("a");
        a.id = "x_latest_tweet_a";
        a.target = "_blank";
        a.rel = "noopener noreferrer";
        a.style.display = "inline-block";
        a.style.marginLeft = "10px";
        a.textContent = "Открыть проверяемый пост";
        container.appendChild(a);
      }
      a.href = url;
    } catch {}
  }

})();

;

```

## shared: airdrop-x.js

### `/opt/logos/www/shared/airdrop-x.js`

```ini
(function(){
  const API = "/airdrop-api/api/airdrop";
  const LS_TOKEN = "logos_airdrop_token";

  const $ = (s)=>document.querySelector(s);

  function getToken(){
    const t = (localStorage.getItem(LS_TOKEN) || "").trim();
    if (t) return t;
    const inp = $("#inpToken");
    return (inp && inp.value ? String(inp.value).trim() : "");
  }

  async function post(path, body){
    const r = await fetch(API + path, {
      method: "POST",
      headers: {"content-type":"application/json"},
      body: JSON.stringify(body),
    });
    const txt = await r.text();
    let data = {};
    try { data = txt ? JSON.parse(txt) : {}; } catch(e){ data = { ok:false, error:"bad_json", message: txt }; }
    if (!r.ok) {
      const msg = (data && (data.detail || data.message || data.error)) || ("HTTP " + r.status);
      throw new Error(msg);
    }
    return data;
  }

  function out(msg){
    const el = $("#out");
    if (el) el.textContent = String(msg);
  }

  function refresh(){
    const b = $("#btnRefresh");
    if (b) b.click();
  }

  async function saveX(){
    const tok = getToken();
    if (!tok) throw new Error("Нет token (сначала зарегистрируйся на airdrop)");
    const inp = $("#inpXUser");
    const uname = (inp && inp.value ? String(inp.value).trim() : "");
    if (!uname) throw new Error("Введи X username (@name или ссылку)");
    const st = await post("/set_x_username", { token: tok, twitter_username: uname });
    out("X username сохранён: " + (st.twitter_username || uname));
    refresh();
  }

  async function verifyX(){
    const tok = getToken();
    if (!tok) throw new Error("Нет token");
    const st = await post("/verify_x", { token: tok });
    out("X verify OK: follow=" + st.twitter_follow + " like=" + st.twitter_like + " rt=" + st.twitter_retweet);
    refresh();
  }

  window.addEventListener("DOMContentLoaded", ()=>{
    const s = $("#btnXSave");
    const v = $("#btnXVerify");
    if (s) s.addEventListener("click", ()=>saveX().catch(e=>out("Ошибка: " + e.message)));
    if (v) v.addEventListener("click", ()=>verifyX().catch(e=>out("Ошибка: " + e.message)));
  });
})();

```

## shared: i18n.js

### `/opt/logos/www/shared/i18n.js`

```ini
(() => {
  const SUPPORTED = [
    'ru','en','de',
    'es','fr','it','pt',
    'id','vi','hi',
    'ja','ko','zh',
    'ar','cs'
  ];
  const DEFAULT = 'en';

  const DICT = {
    en: {
      'wallet.title': 'LOGOS Wallet — Secure',
      'wallet.subtitle': 'WebCrypto + IndexedDB + 16-word backup phrase',
      'wallet.login_existing': 'Log in to existing wallet',
      'wallet.create_new': 'Create a new wallet',
      'wallet.restore': 'Restore wallet from phrase'
    },
    ru: {
      'wallet.title': 'LOGOS Wallet — Кошелёк',
      'wallet.subtitle': 'WebCrypto + IndexedDB + резервная фраза из 16 слов',
      'wallet.login_existing': 'Вход в существующий кошелёк',
      'wallet.create_new': 'Создать новый кошелёк',
      'wallet.restore': 'Восстановить кошелёк по фразе'
    },
    de: {
      'wallet.title': 'LOGOS Wallet — Wallet',
      'wallet.subtitle': 'WebCrypto + IndexedDB + 16‑Wörter‑Backup',
      'wallet.login_existing': 'Bestehendes Wallet öffnen',
      'wallet.create_new': 'Neues Wallet erstellen',
      'wallet.restore': 'Wallet mit Phrase wiederherstellen'
    },

    # остальные языки пока пустые — для них будет fallback на EN
    es: {}, fr: {}, it: {}, pt: {},
    id: {}, vi: {}, hi: {},
    ja: {}, ko: {}, zh: {},
    ar: {}, cs: {}
  };

  function pickLang() {
    try {
      const stored = localStorage.getItem('logos_lang');
      if (stored && SUPPORTED.includes(stored)) return stored;
    } catch (_) {}

    const nav = (navigator.language || navigator.userLanguage || '')
      .slice(0, 2).toLowerCase();
    if (SUPPORTED.includes(nav)) return nav;
    return DEFAULT;
  }

  function applyLang(lang) {
    const dict = DICT[lang] || DICT[DEFAULT] || {};
    document.querySelectorAll('[data-i18n]').forEach(el => {
      const key = el.getAttribute('data-i18n');
      const value = dict[key]
        || (DICT[DEFAULT] && DICT[DEFAULT][key])
        || '';
      if (value) el.textContent = value;
    });
    document.documentElement.lang = lang;
  }

  function renderSwitcher(containerSelector) {
    const cont = document.querySelector(containerSelector);
    if (!cont) return;

    cont.classList.add('logos-lang-switcher');

    SUPPORTED.forEach(code => {
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.textContent = code.toUpperCase();
      btn.dataset.lang = code;
      btn.addEventListener('click', () => {
        const lang = btn.dataset.lang;
        try { localStorage.setItem('logos_lang', lang); } catch (_) {}
        applyLang(lang);
        cont.querySelectorAll('button').forEach(b =>
          b.classList.toggle('active', b === btn)
        );
      });
      cont.appendChild(btn);
    });
  }

  window.LOGOS_I18N = {
    init(containerSelector) {
      const lang = pickLang();
      try { localStorage.setItem('logos_lang', lang); } catch (_) {}
      applyLang(lang);
      if (containerSelector) renderSwitcher(containerSelector);
    }
  };
})();

```

## shared: tweetnacl.min.js

### `/opt/logos/www/shared/tweetnacl.min.js`

```ini
!function(i){"use strict";var m=function(r,n){this.hi=0|r,this.lo=0|n},v=function(r){var n,e=new Float64Array(16);if(r)for(n=0;n<r.length;n++)e[n]=r[n];return e},a=function(){throw new Error("no PRNG")},o=new Uint8Array(16),e=new Uint8Array(32);e[0]=9;var c=v(),w=v([1]),g=v([56129,1]),y=v([30883,4953,19914,30187,55467,16705,2637,112,59544,30585,16505,36039,65139,11119,27886,20995]),l=v([61785,9906,39828,60374,45398,33411,5274,224,53552,61171,33010,6542,64743,22239,55772,9222]),t=v([54554,36645,11616,51542,42930,38181,51040,26924,56412,64982,57905,49316,21502,52590,14035,8553]),f=v([26200,26214,26214,26214,26214,26214,26214,26214,26214,26214,26214,26214,26214,26214,26214,26214]),s=v([41136,18958,6951,50414,58488,44335,6150,12099,55207,15867,153,11085,57099,20417,9344,11139]);function h(r,n){return r<<n|r>>>32-n}function b(r,n){var e=255&r[n+3];return(e=(e=e<<8|255&r[n+2])<<8|255&r[n+1])<<8|255&r[n+0]}function B(r,n){var e=r[n]<<24|r[n+1]<<16|r[n+2]<<8|r[n+3],t=r[n+4]<<24|r[n+5]<<16|r[n+6]<<8|r[n+7];return new m(e,t)}function p(r,n,e){var t;for(t=0;t<4;t++)r[n+t]=255&e,e>>>=8}function S(r,n,e){r[n]=e.hi>>24&255,r[n+1]=e.hi>>16&255,r[n+2]=e.hi>>8&255,r[n+3]=255&e.hi,r[n+4]=e.lo>>24&255,r[n+5]=e.lo>>16&255,r[n+6]=e.lo>>8&255,r[n+7]=255&e.lo}function u(r,n,e,t,o){var i,a=0;for(i=0;i<o;i++)a|=r[n+i]^e[t+i];return(1&a-1>>>8)-1}function A(r,n,e,t){return u(r,n,e,t,16)}function _(r,n,e,t){return u(r,n,e,t,32)}function U(r,n,e,t,o){var i,a,f,u=new Uint32Array(16),c=new Uint32Array(16),w=new Uint32Array(16),y=new Uint32Array(4);for(i=0;i<4;i++)c[5*i]=b(t,4*i),c[1+i]=b(e,4*i),c[6+i]=b(n,4*i),c[11+i]=b(e,16+4*i);for(i=0;i<16;i++)w[i]=c[i];for(i=0;i<20;i++){for(a=0;a<4;a++){for(f=0;f<4;f++)y[f]=c[(5*a+4*f)%16];for(y[1]^=h(y[0]+y[3]|0,7),y[2]^=h(y[1]+y[0]|0,9),y[3]^=h(y[2]+y[1]|0,13),y[0]^=h(y[3]+y[2]|0,18),f=0;f<4;f++)u[4*a+(a+f)%4]=y[f]}for(f=0;f<16;f++)c[f]=u[f]}if(o){for(i=0;i<16;i++)c[i]=c[i]+w[i]|0;for(i=0;i<4;i++)c[5*i]=c[5*i]-b(t,4*i)|0,c[6+i]=c[6+i]-b(n,4*i)|0;for(i=0;i<4;i++)p(r,4*i,c[5*i]),p(r,16+4*i,c[6+i])}else for(i=0;i<16;i++)p(r,4*i,c[i]+w[i]|0)}function E(r,n,e,t){U(r,n,e,t,!1)}function x(r,n,e,t){return U(r,n,e,t,!0),0}var d=new Uint8Array([101,120,112,97,110,100,32,51,50,45,98,121,116,101,32,107]);function K(r,n,e,t,o,i,a){var f,u,c=new Uint8Array(16),w=new Uint8Array(64);if(!o)return 0;for(u=0;u<16;u++)c[u]=0;for(u=0;u<8;u++)c[u]=i[u];for(;64<=o;){for(E(w,c,a,d),u=0;u<64;u++)r[n+u]=(e?e[t+u]:0)^w[u];for(f=1,u=8;u<16;u++)f=f+(255&c[u])|0,c[u]=255&f,f>>>=8;o-=64,n+=64,e&&(t+=64)}if(0<o)for(E(w,c,a,d),u=0;u<o;u++)r[n+u]=(e?e[t+u]:0)^w[u];return 0}function Y(r,n,e,t,o){return K(r,n,null,0,e,t,o)}function L(r,n,e,t,o){var i=new Uint8Array(32);return x(i,t,o,d),Y(r,n,e,t.subarray(16),i)}function T(r,n,e,t,o,i,a){var f=new Uint8Array(32);return x(f,i,a,d),K(r,n,e,t,o,i.subarray(16),f)}function k(r,n){var e,t=0;for(e=0;e<17;e++)t=t+(r[e]+n[e]|0)|0,r[e]=255&t,t>>>=8}var z=new Uint32Array([5,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,252]);function R(r,n,e,t,o,i){var a,f,u,c,w=new Uint32Array(17),y=new Uint32Array(17),l=new Uint32Array(17),s=new Uint32Array(17),h=new Uint32Array(17);for(u=0;u<17;u++)y[u]=l[u]=0;for(u=0;u<16;u++)y[u]=i[u];for(y[3]&=15,y[4]&=252,y[7]&=15,y[8]&=252,y[11]&=15,y[12]&=252,y[15]&=15;0<o;){for(u=0;u<17;u++)s[u]=0;for(u=0;u<16&&u<o;++u)s[u]=e[t+u];for(s[u]=1,t+=u,o-=u,k(l,s),f=0;f<17;f++)for(u=w[f]=0;u<17;u++)w[f]=w[f]+l[u]*(u<=f?y[f-u]:320*y[f+17-u]|0)|0;for(f=0;f<17;f++)l[f]=w[f];for(u=c=0;u<16;u++)c=c+l[u]|0,l[u]=255&c,c>>>=8;for(c=c+l[16]|0,l[16]=3&c,c=5*(c>>>2)|0,u=0;u<16;u++)c=c+l[u]|0,l[u]=255&c,c>>>=8;c=c+l[16]|0,l[16]=c}for(u=0;u<17;u++)h[u]=l[u];for(k(l,z),a=0|-(l[16]>>>7),u=0;u<17;u++)l[u]^=a&(h[u]^l[u]);for(u=0;u<16;u++)s[u]=i[u+16];for(s[16]=0,k(l,s),u=0;u<16;u++)r[n+u]=l[u];return 0}function P(r,n,e,t,o,i){var a=new Uint8Array(16);return R(a,0,e,t,o,i),A(r,n,a,0)}function M(r,n,e,t,o){var i;if(e<32)return-1;for(T(r,0,n,0,e,t,o),R(r,16,r,32,e-32,r),i=0;i<16;i++)r[i]=0;return 0}function N(r,n,e,t,o){var i,a=new Uint8Array(32);if(e<32)return-1;if(L(a,0,32,t,o),0!==P(n,16,n,32,e-32,a))return-1;for(T(r,0,n,0,e,t,o),i=0;i<32;i++)r[i]=0;return 0}function O(r,n){var e;for(e=0;e<16;e++)r[e]=0|n[e]}function C(r){var n,e;for(e=0;e<16;e++)r[e]+=65536,n=Math.floor(r[e]/65536),r[(e+1)*(e<15?1:0)]+=n-1+37*(n-1)*(15===e?1:0),r[e]-=65536*n}function F(r,n,e){for(var t,o=~(e-1),i=0;i<16;i++)t=o&(r[i]^n[i]),r[i]^=t,n[i]^=t}function Z(r,n){var e,t,o,i=v(),a=v();for(e=0;e<16;e++)a[e]=n[e];for(C(a),C(a),C(a),t=0;t<2;t++){for(i[0]=a[0]-65517,e=1;e<15;e++)i[e]=a[e]-65535-(i[e-1]>>16&1),i[e-1]&=65535;i[15]=a[15]-32767-(i[14]>>16&1),o=i[15]>>16&1,i[14]&=65535,F(a,i,1-o)}for(e=0;e<16;e++)r[2*e]=255&a[e],r[2*e+1]=a[e]>>8}function G(r,n){var e=new Uint8Array(32),t=new Uint8Array(32);return Z(e,r),Z(t,n),_(e,0,t,0)}function q(r){var n=new Uint8Array(32);return Z(n,r),1&n[0]}function D(r,n){var e;for(e=0;e<16;e++)r[e]=n[2*e]+(n[2*e+1]<<8);r[15]&=32767}function I(r,n,e){var t;for(t=0;t<16;t++)r[t]=n[t]+e[t]|0}function V(r,n,e){var t;for(t=0;t<16;t++)r[t]=n[t]-e[t]|0}function X(r,n,e){var t,o,i=new Float64Array(31);for(t=0;t<31;t++)i[t]=0;for(t=0;t<16;t++)for(o=0;o<16;o++)i[t+o]+=n[t]*e[o];for(t=0;t<15;t++)i[t]+=38*i[t+16];for(t=0;t<16;t++)r[t]=i[t];C(r),C(r)}function j(r,n){X(r,n,n)}function H(r,n){var e,t=v();for(e=0;e<16;e++)t[e]=n[e];for(e=253;0<=e;e--)j(t,t),2!==e&&4!==e&&X(t,t,n);for(e=0;e<16;e++)r[e]=t[e]}function J(r,n){var e,t=v();for(e=0;e<16;e++)t[e]=n[e];for(e=250;0<=e;e--)j(t,t),1!==e&&X(t,t,n);for(e=0;e<16;e++)r[e]=t[e]}function Q(r,n,e){var t,o,i=new Uint8Array(32),a=new Float64Array(80),f=v(),u=v(),c=v(),w=v(),y=v(),l=v();for(o=0;o<31;o++)i[o]=n[o];for(i[31]=127&n[31]|64,i[0]&=248,D(a,e),o=0;o<16;o++)u[o]=a[o],w[o]=f[o]=c[o]=0;for(f[0]=w[0]=1,o=254;0<=o;--o)F(f,u,t=i[o>>>3]>>>(7&o)&1),F(c,w,t),I(y,f,c),V(f,f,c),I(c,u,w),V(u,u,w),j(w,y),j(l,f),X(f,c,f),X(c,u,y),I(y,f,c),V(f,f,c),j(u,f),V(c,w,l),X(f,c,g),I(f,f,w),X(c,c,f),X(f,w,l),X(w,u,a),j(u,y),F(f,u,t),F(c,w,t);for(o=0;o<16;o++)a[o+16]=f[o],a[o+32]=c[o],a[o+48]=u[o],a[o+64]=w[o];var s=a.subarray(32),h=a.subarray(16);return H(s,s),X(h,h,s),Z(r,h),0}function W(r,n){return Q(r,n,e)}function $(r,n){return a(n,32),W(r,n)}function rr(r,n,e){var t=new Uint8Array(32);return Q(t,e,n),x(r,o,t,d)}var nr=M,er=N;function tr(){var r,n,e,t=0,o=0,i=0,a=0,f=65535;for(e=0;e<arguments.length;e++)t+=(r=arguments[e].lo)&f,o+=r>>>16,i+=(n=arguments[e].hi)&f,a+=n>>>16;return new m((i+=(o+=t>>>16)>>>16)&f|(a+=i>>>16)<<16,t&f|o<<16)}function or(r,n){return new m(r.hi>>>n,r.lo>>>n|r.hi<<32-n)}function ir(){var r,n=0,e=0;for(r=0;r<arguments.length;r++)n^=arguments[r].lo,e^=arguments[r].hi;return new m(e,n)}function ar(r,n){var e,t,o=32-n;return n<32?(e=r.hi>>>n|r.lo<<o,t=r.lo>>>n|r.hi<<o):n<64&&(e=r.lo>>>n|r.hi<<o,t=r.hi>>>n|r.lo<<o),new m(e,t)}var fr=[new m(1116352408,3609767458),new m(1899447441,602891725),new m(3049323471,3964484399),new m(3921009573,2173295548),new m(961987163,4081628472),new m(1508970993,3053834265),new m(2453635748,2937671579),new m(2870763221,3664609560),new m(3624381080,2734883394),new m(310598401,1164996542),new m(607225278,1323610764),new m(1426881987,3590304994),new m(1925078388,4068182383),new m(2162078206,991336113),new m(2614888103,633803317),new m(3248222580,3479774868),new m(3835390401,2666613458),new m(4022224774,944711139),new m(264347078,2341262773),new m(604807628,2007800933),new m(770255983,1495990901),new m(1249150122,1856431235),new m(1555081692,3175218132),new m(1996064986,2198950837),new m(2554220882,3999719339),new m(2821834349,766784016),new m(2952996808,2566594879),new m(3210313671,3203337956),new m(3336571891,1034457026),new m(3584528711,2466948901),new m(113926993,3758326383),new m(338241895,168717936),new m(666307205,1188179964),new m(773529912,1546045734),new m(1294757372,1522805485),new m(1396182291,2643833823),new m(1695183700,2343527390),new m(1986661051,1014477480),new m(2177026350,1206759142),new m(2456956037,344077627),new m(2730485921,1290863460),new m(2820302411,3158454273),new m(3259730800,3505952657),new m(3345764771,106217008),new m(3516065817,3606008344),new m(3600352804,1432725776),new m(4094571909,1467031594),new m(275423344,851169720),new m(430227734,3100823752),new m(506948616,1363258195),new m(659060556,3750685593),new m(883997877,3785050280),new m(958139571,3318307427),new m(1322822218,3812723403),new m(1537002063,2003034995),new m(1747873779,3602036899),new m(1955562222,1575990012),new m(2024104815,1125592928),new m(2227730452,2716904306),new m(2361852424,442776044),new m(2428436474,593698344),new m(2756734187,3733110249),new m(3204031479,2999351573),new m(3329325298,3815920427),new m(3391569614,3928383900),new m(3515267271,566280711),new m(3940187606,3454069534),new m(4118630271,4000239992),new m(116418474,1914138554),new m(174292421,2731055270),new m(289380356,3203993006),new m(460393269,320620315),new m(685471733,587496836),new m(852142971,1086792851),new m(1017036298,365543100),new m(1126000580,2618297676),new m(1288033470,3409855158),new m(1501505948,4234509866),new m(1607167915,987167468),new m(1816402316,1246189591)];function ur(r,n,e){var t,o,i,a=[],f=[],u=[],c=[];for(o=0;o<8;o++)a[o]=u[o]=B(r,8*o);for(var w,y,l,s,h,v,g,b,p,A,_,U,E,x,d=0;128<=e;){for(o=0;o<16;o++)c[o]=B(n,8*o+d);for(o=0;o<80;o++){for(i=0;i<8;i++)f[i]=u[i];for(t=tr(u[7],ir(ar(x=u[4],14),ar(x,18),ar(x,41)),(p=u[4],A=u[5],_=u[6],0,U=p.hi&A.hi^~p.hi&_.hi,E=p.lo&A.lo^~p.lo&_.lo,new m(U,E)),fr[o],c[o%16]),f[7]=tr(t,ir(ar(b=u[0],28),ar(b,34),ar(b,39)),(l=u[0],s=u[1],h=u[2],0,v=l.hi&s.hi^l.hi&h.hi^s.hi&h.hi,g=l.lo&s.lo^l.lo&h.lo^s.lo&h.lo,new m(v,g))),f[3]=tr(f[3],t),i=0;i<8;i++)u[(i+1)%8]=f[i];if(o%16==15)for(i=0;i<16;i++)c[i]=tr(c[i],c[(i+9)%16],ir(ar(y=c[(i+1)%16],1),ar(y,8),or(y,7)),ir(ar(w=c[(i+14)%16],19),ar(w,61),or(w,6)))}for(o=0;o<8;o++)u[o]=tr(u[o],a[o]),a[o]=u[o];d+=128,e-=128}for(o=0;o<8;o++)S(r,8*o,a[o]);return e}var cr=new Uint8Array([106,9,230,103,243,188,201,8,187,103,174,133,132,202,167,59,60,110,243,114,254,148,248,43,165,79,245,58,95,29,54,241,81,14,82,127,173,230,130,209,155,5,104,140,43,62,108,31,31,131,217,171,251,65,189,107,91,224,205,25,19,126,33,121]);function wr(r,n,e){var t,o=new Uint8Array(64),i=new Uint8Array(256),a=e;for(t=0;t<64;t++)o[t]=cr[t];for(ur(o,n,e),e%=128,t=0;t<256;t++)i[t]=0;for(t=0;t<e;t++)i[t]=n[a-e+t];for(i[e]=128,i[(e=256-128*(e<112?1:0))-9]=0,S(i,e-8,new m(a/536870912|0,a<<3)),ur(o,i,e),t=0;t<64;t++)r[t]=o[t];return 0}function yr(r,n){var e=v(),t=v(),o=v(),i=v(),a=v(),f=v(),u=v(),c=v(),w=v();V(e,r[1],r[0]),V(w,n[1],n[0]),X(e,e,w),I(t,r[0],r[1]),I(w,n[0],n[1]),X(t,t,w),X(o,r[3],n[3]),X(o,o,l),X(i,r[2],n[2]),I(i,i,i),V(a,t,e),V(f,i,o),I(u,i,o),I(c,t,e),X(r[0],a,f),X(r[1],c,u),X(r[2],u,f),X(r[3],a,c)}function lr(r,n,e){var t;for(t=0;t<4;t++)F(r[t],n[t],e)}function sr(r,n){var e=v(),t=v(),o=v();H(o,n[2]),X(e,n[0],o),X(t,n[1],o),Z(r,t),r[31]^=q(e)<<7}function hr(r,n,e){var t,o;for(O(r[0],c),O(r[1],w),O(r[2],w),O(r[3],c),o=255;0<=o;--o)lr(r,n,t=e[o/8|0]>>(7&o)&1),yr(n,r),yr(r,r),lr(r,n,t)}function vr(r,n){var e=[v(),v(),v(),v()];O(e[0],t),O(e[1],f),O(e[2],w),X(e[3],t,f),hr(r,e,n)}function gr(r,n,e){var t,o=new Uint8Array(64),i=[v(),v(),v(),v()];for(e||a(n,32),wr(o,n,32),o[0]&=248,o[31]&=127,o[31]|=64,vr(i,o),sr(r,i),t=0;t<32;t++)n[t+32]=r[t];return 0}var br=new Float64Array([237,211,245,92,26,99,18,88,214,156,247,162,222,249,222,20,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,16]);function pr(r,n){var e,t,o,i;for(t=63;32<=t;--t){for(e=0,o=t-32,i=t-12;o<i;++o)n[o]+=e-16*n[t]*br[o-(t-32)],e=Math.floor((n[o]+128)/256),n[o]-=256*e;n[o]+=e,n[t]=0}for(o=e=0;o<32;o++)n[o]+=e-(n[31]>>4)*br[o],e=n[o]>>8,n[o]&=255;for(o=0;o<32;o++)n[o]-=e*br[o];for(t=0;t<32;t++)n[t+1]+=n[t]>>8,r[t]=255&n[t]}function Ar(r){var n,e=new Float64Array(64);for(n=0;n<64;n++)e[n]=r[n];for(n=0;n<64;n++)r[n]=0;pr(r,e)}function _r(r,n,e,t){var o,i,a=new Uint8Array(64),f=new Uint8Array(64),u=new Uint8Array(64),c=new Float64Array(64),w=[v(),v(),v(),v()];wr(a,t,32),a[0]&=248,a[31]&=127,a[31]|=64;var y=e+64;for(o=0;o<e;o++)r[64+o]=n[o];for(o=0;o<32;o++)r[32+o]=a[32+o];for(wr(u,r.subarray(32),e+32),Ar(u),vr(w,u),sr(r,w),o=32;o<64;o++)r[o]=t[o];for(wr(f,r,e+64),Ar(f),o=0;o<64;o++)c[o]=0;for(o=0;o<32;o++)c[o]=u[o];for(o=0;o<32;o++)for(i=0;i<32;i++)c[o+i]+=f[o]*a[i];return pr(r.subarray(32),c),y}function Ur(r,n,e,t){var o,i=new Uint8Array(32),a=new Uint8Array(64),f=[v(),v(),v(),v()],u=[v(),v(),v(),v()];if(e<64)return-1;if(function(r,n){var e=v(),t=v(),o=v(),i=v(),a=v(),f=v(),u=v();if(O(r[2],w),D(r[1],n),j(o,r[1]),X(i,o,y),V(o,o,r[2]),I(i,r[2],i),j(a,i),j(f,a),X(u,f,a),X(e,u,o),X(e,e,i),J(e,e),X(e,e,o),X(e,e,i),X(e,e,i),X(r[0],e,i),j(t,r[0]),X(t,t,i),G(t,o)&&X(r[0],r[0],s),j(t,r[0]),X(t,t,i),G(t,o))return 1;q(r[0])===n[31]>>7&&V(r[0],c,r[0]),X(r[3],r[0],r[1])}(u,t))return-1;for(o=0;o<e;o++)r[o]=n[o];for(o=0;o<32;o++)r[o+32]=t[o];if(wr(a,r,e),Ar(a),hr(f,u,a),vr(u,n.subarray(32)),yr(f,u),sr(i,f),e-=64,_(n,0,i,0)){for(o=0;o<e;o++)r[o]=0;return-1}for(o=0;o<e;o++)r[o]=n[o+64];return e}function Er(r,n){if(32!==r.length)throw new Error("bad key size");if(24!==n.length)throw new Error("bad nonce size")}function xr(){for(var r=0;r<arguments.length;r++)if(!(arguments[r]instanceof Uint8Array))throw new TypeError("unexpected type, use Uint8Array")}function dr(r){for(var n=0;n<r.length;n++)r[n]=0}i.lowlevel={crypto_core_hsalsa20:x,crypto_stream_xor:T,crypto_stream:L,crypto_stream_salsa20_xor:K,crypto_stream_salsa20:Y,crypto_onetimeauth:R,crypto_onetimeauth_verify:P,crypto_verify_16:A,crypto_verify_32:_,crypto_secretbox:M,crypto_secretbox_open:N,crypto_scalarmult:Q,crypto_scalarmult_base:W,crypto_box_beforenm:rr,crypto_box_afternm:nr,crypto_box:function(r,n,e,t,o,i){var a=new Uint8Array(32);return rr(a,o,i),nr(r,n,e,t,a)},crypto_box_open:function(r,n,e,t,o,i){var a=new Uint8Array(32);return rr(a,o,i),er(r,n,e,t,a)},crypto_box_keypair:$,crypto_hash:wr,crypto_sign:_r,crypto_sign_keypair:gr,crypto_sign_open:Ur,crypto_secretbox_KEYBYTES:32,crypto_secretbox_NONCEBYTES:24,crypto_secretbox_ZEROBYTES:32,crypto_secretbox_BOXZEROBYTES:16,crypto_scalarmult_BYTES:32,crypto_scalarmult_SCALARBYTES:32,crypto_box_PUBLICKEYBYTES:32,crypto_box_SECRETKEYBYTES:32,crypto_box_BEFORENMBYTES:32,crypto_box_NONCEBYTES:24,crypto_box_ZEROBYTES:32,crypto_box_BOXZEROBYTES:16,crypto_sign_BYTES:64,crypto_sign_PUBLICKEYBYTES:32,crypto_sign_SECRETKEYBYTES:64,crypto_sign_SEEDBYTES:32,crypto_hash_BYTES:64,gf:v,D:y,L:br,pack25519:Z,unpack25519:D,M:X,A:I,S:j,Z:V,pow2523:J,add:yr,set25519:O,modL:pr,scalarmult:hr,scalarbase:vr},i.randomBytes=function(r){var n=new Uint8Array(r);return a(n,r),n},i.secretbox=function(r,n,e){xr(r,n,e),Er(e,n);for(var t=new Uint8Array(32+r.length),o=new Uint8Array(t.length),i=0;i<r.length;i++)t[i+32]=r[i];return M(o,t,t.length,n,e),o.subarray(16)},i.secretbox.open=function(r,n,e){xr(r,n,e),Er(e,n);for(var t=new Uint8Array(16+r.length),o=new Uint8Array(t.length),i=0;i<r.length;i++)t[i+16]=r[i];return t.length<32||0!==N(o,t,t.length,n,e)?null:o.subarray(32)},i.secretbox.keyLength=32,i.secretbox.nonceLength=24,i.secretbox.overheadLength=16,i.scalarMult=function(r,n){if(xr(r,n),32!==r.length)throw new Error("bad n size");if(32!==n.length)throw new Error("bad p size");var e=new Uint8Array(32);return Q(e,r,n),e},i.scalarMult.base=function(r){if(xr(r),32!==r.length)throw new Error("bad n size");var n=new Uint8Array(32);return W(n,r),n},i.scalarMult.scalarLength=32,i.scalarMult.groupElementLength=32,i.box=function(r,n,e,t){var o=i.box.before(e,t);return i.secretbox(r,n,o)},i.box.before=function(r,n){xr(r,n),function(r,n){if(32!==r.length)throw new Error("bad public key size");if(32!==n.length)throw new Error("bad secret key size")}(r,n);var e=new Uint8Array(32);return rr(e,r,n),e},i.box.after=i.secretbox,i.box.open=function(r,n,e,t){var o=i.box.before(e,t);return i.secretbox.open(r,n,o)},i.box.open.after=i.secretbox.open,i.box.keyPair=function(){var r=new Uint8Array(32),n=new Uint8Array(32);return $(r,n),{publicKey:r,secretKey:n}},i.box.keyPair.fromSecretKey=function(r){if(xr(r),32!==r.length)throw new Error("bad secret key size");var n=new Uint8Array(32);return W(n,r),{publicKey:n,secretKey:new Uint8Array(r)}},i.box.publicKeyLength=32,i.box.secretKeyLength=32,i.box.sharedKeyLength=32,i.box.nonceLength=24,i.box.overheadLength=i.secretbox.overheadLength,i.sign=function(r,n){if(xr(r,n),64!==n.length)throw new Error("bad secret key size");var e=new Uint8Array(64+r.length);return _r(e,r,r.length,n),e},i.sign.open=function(r,n){if(xr(r,n),32!==n.length)throw new Error("bad public key size");var e=new Uint8Array(r.length),t=Ur(e,r,r.length,n);if(t<0)return null;for(var o=new Uint8Array(t),i=0;i<o.length;i++)o[i]=e[i];return o},i.sign.detached=function(r,n){for(var e=i.sign(r,n),t=new Uint8Array(64),o=0;o<t.length;o++)t[o]=e[o];return t},i.sign.detached.verify=function(r,n,e){if(xr(r,n,e),64!==n.length)throw new Error("bad signature size");if(32!==e.length)throw new Error("bad public key size");var t,o=new Uint8Array(64+r.length),i=new Uint8Array(64+r.length);for(t=0;t<64;t++)o[t]=n[t];for(t=0;t<r.length;t++)o[t+64]=r[t];return 0<=Ur(i,o,o.length,e)},i.sign.keyPair=function(){var r=new Uint8Array(32),n=new Uint8Array(64);return gr(r,n),{publicKey:r,secretKey:n}},i.sign.keyPair.fromSecretKey=function(r){if(xr(r),64!==r.length)throw new Error("bad secret key size");for(var n=new Uint8Array(32),e=0;e<n.length;e++)n[e]=r[32+e];return{publicKey:n,secretKey:new Uint8Array(r)}},i.sign.keyPair.fromSeed=function(r){if(xr(r),32!==r.length)throw new Error("bad seed size");for(var n=new Uint8Array(32),e=new Uint8Array(64),t=0;t<32;t++)e[t]=r[t];return gr(n,e,!0),{publicKey:n,secretKey:e}},i.sign.publicKeyLength=32,i.sign.secretKeyLength=64,i.sign.seedLength=32,i.sign.signatureLength=64,i.hash=function(r){xr(r);var n=new Uint8Array(64);return wr(n,r,r.length),n},i.hash.hashLength=64,i.verify=function(r,n){return xr(r,n),0!==r.length&&0!==n.length&&(r.length===n.length&&0===u(r,0,n,0,r.length))},i.setPRNG=function(r){a=r},function(){var o="undefined"!=typeof self?self.crypto||self.msCrypto:null;if(o&&o.getRandomValues){i.setPRNG(function(r,n){var e,t=new Uint8Array(n);for(e=0;e<n;e+=65536)o.getRandomValues(t.subarray(e,e+Math.min(n-e,65536)));for(e=0;e<n;e++)r[e]=t[e];dr(t)})}else"undefined"!=typeof require&&(o=require("crypto"))&&o.randomBytes&&i.setPRNG(function(r,n){var e,t=o.randomBytes(n);for(e=0;e<n;e++)r[e]=t[e];dr(t)})}()}("undefined"!=typeof module&&module.exports?module.exports:self.nacl=self.nacl||{});
```

## landing shared copy: airdrop-fix.js

### `/var/www/logos/landing/shared/airdrop-fix.js`

```ini
(() => {
  'use strict';
  const API='/airdrop-api/api/airdrop';
  const K_T='logos_airdrop_token_v1', K_X='logos_airdrop_xu_v1';

  const qs = (k)=>{ try{return new URL(location.href).searchParams.get(k);}catch{return null;} };

  const post = async (path, body) => {
    const r = await fetch(API+path, {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify(body||{}),
      credentials:'same-origin',
    });
    const ct=r.headers.get('content-type')||'';
    const data = ct.includes('application/json') ? await r.json().catch(()=>({})) : await r.text().catch(()=> '');
    return {ok:r.ok, status:r.status, data};
  };

  const findInput = (re)=> Array.from(document.querySelectorAll('input')).find(i => re.test((i.placeholder||'')+' '+(i.name||'')+' '+(i.id||''))) || null;
  const findBtn = (t)=> Array.from(document.querySelectorAll('button,a')).find(b => ((b.textContent||'').trim().toLowerCase()===t)) || null;

  async function ensureToken(){
    let t=(localStorage.getItem(K_T)||'').trim();
    const ti = findInput(/token/i);
    if (ti && (ti.value||'').trim().length>=8) { t=(ti.value||'').trim(); localStorage.setItem(K_T,t); return t; }
    if (!t){
      const ref = (qs('ref')||qs('ref_token')||'').trim();
      const rr = await post('/register_web', ref ? {ref_token:ref}:{});
      if(!rr.ok || !rr.data || !rr.data.token) throw new Error('register_web failed');
      t=String(rr.data.token); localStorage.setItem(K_T,t);
      if (ti) ti.value=t;
    }
    return t;
  }

  function setRef(token, siteOrigin){
    const ri = findInput(/ref/i);
    if(!ri) return;
    const origin=(siteOrigin||'https://mw-expedition.com').replace(/\/+$/,'');
    ri.value = `${origin}/airdrop?ref=${encodeURIComponent(token)}`;
    const copy = findBtn('copy link') || findBtn('copy');
    if(copy && !copy.__l){ copy.__l=true; copy.addEventListener('click', async (e)=>{ e.preventDefault(); try{ await navigator.clipboard.writeText(ri.value);}catch{} }); }
  }

  function setTG(token){
    const url=`https://t.me/Logos_lrb_bot?start=airdrop_${encodeURIComponent(token)}`;
    for(const a of Array.from(document.querySelectorAll('a'))){
      const href=(a.getAttribute('href')||'');
      if(href.includes('t.me') && href.toLowerCase().includes('logos')) a.href=url;
      if(((a.textContent||'').trim().toLowerCase()==='open') && (a.closest('*')?.textContent||'').toLowerCase().includes('telegram')) a.href=url;
    }
  }

  function patchBadges(s){
    const set = (k, ok)=>{
      const blocks = Array.from(document.querySelectorAll('div,li,section'));
      const b = blocks.find(x => (x.textContent||'').toLowerCase().includes(k) && /(wait|ok)/i.test(x.textContent||''));
      if(!b) return;
      const badge = Array.from(b.querySelectorAll('span,div')).find(x => /^(wait|ok)$/i.test((x.textContent||'').trim()));
      if(badge) badge.textContent = ok ? 'OK':'WAIT';
    };
    set('wallet', !!s.wallet_bound);
    set('telegram', !!s.telegram_ok);
    set('follow', !!s.twitter_follow);
    set('like', !!s.twitter_like);
    set('repost', !!s.twitter_retweet);
    set('retweet', !!s.twitter_retweet);
  }

  async function refresh(){
    let t = await ensureToken();
    let r = await post('/status', {token:t});
    if(!r.ok && r.status===404){
      localStorage.removeItem(K_T);
      t = await ensureToken();
      r = await post('/status', {token:t});
    }
    if(!r.ok) return null;
    const s=r.data||{};
    setRef(t, s.site_origin);
    setTG(t);
    patchBadges(s);
    return s;
  }

  function wireX(){
    const xu = findInput(/yourname|username|twitter|x/i);
    const saved=(localStorage.getItem(K_X)||'').trim();
    if(xu && saved && !(xu.value||'').trim()) xu.value=saved;

    for(const b of Array.from(document.querySelectorAll('button')).filter(x => (x.textContent||'').trim().toLowerCase()==='save')){
      if(b.__xs) continue; b.__xs=true;
      b.addEventListener('click', async (e)=>{
        e.preventDefault();
        const t=await ensureToken();
        const inp = findInput(/yourname|username|twitter|x/i);
        let v=(inp?.value||'').trim().replace(/^@/,'');
        if(!v) return;
        localStorage.setItem(K_X,v);
        // ВАЖНО: поле именно twitter_username
        await post('/set_x_username', {token:t, twitter_username:v});
        await refresh();
      });
    }

    const vb=findBtn('verify');
    if(vb && !vb.__xv){ vb.__xv=true;
      vb.addEventListener('click', async (e)=>{
        e.preventDefault();
        const t=await ensureToken();
        await post('/verify_x', {token:t});
        await refresh();
      });
    }
  }

  function wireRefresh(){
    const b=findBtn('refresh status') || findBtn('refresh');
    if(!b || b.__rs) return;
    b.__rs=true;
    b.addEventListener('click', async (e)=>{ e.preventDefault(); await refresh(); });
  }

  async function boot(){
    try{
      await ensureToken();
      wireRefresh();
      wireX();
      await refresh();
    }catch(e){ console.error('airdrop-fix boot', e); }
  }

  if(document.readyState==='loading') document.addEventListener('DOMContentLoaded', boot);
  else boot();

  function setLatestTweetLink(st) {
    try {
      const id = st && (st.x_latest_tweet_id || st.x_latest_tweet || st.latest_tweet_id);
      if (!id) return;
      const url = `https://x.com/RspLogos/status/${id}`;
      const el = document.querySelector('[data-task="x_repost"], #task_x_repost, #xRepostLink') || null;
      // fallback: find by text
      let container = el;
      if (!container) {
        const nodes = Array.from(document.querySelectorAll("div,section,li,p"));
        container = nodes.find(n => (n.textContent||"").toLowerCase().includes("x repost") || (n.textContent||"").toLowerCase().includes("ретвит"));
      }
      if (!container) return;
      let a = document.getElementById("x_latest_tweet_a");
      if (!a) {
        a = document.createElement("a");
        a.id = "x_latest_tweet_a";
        a.target = "_blank";
        a.rel = "noopener noreferrer";
        a.style.display = "inline-block";
        a.style.marginLeft = "10px";
        a.textContent = "Открыть проверяемый пост";
        container.appendChild(a);
      }
      a.href = url;
    } catch {}
  }

})();

;

```

## landing/landing shared copy: airdrop-fix.js

### `/var/www/logos/landing/landing/shared/airdrop-fix.js`

```ini
(() => {
  'use strict';
  const API='/airdrop-api/api/airdrop';
  const K_T='logos_airdrop_token_v1', K_X='logos_airdrop_xu_v1';

  const qs = (k)=>{ try{return new URL(location.href).searchParams.get(k);}catch{return null;} };

  const post = async (path, body) => {
    const r = await fetch(API+path, {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify(body||{}),
      credentials:'same-origin',
    });
    const ct=r.headers.get('content-type')||'';
    const data = ct.includes('application/json') ? await r.json().catch(()=>({})) : await r.text().catch(()=> '');
    return {ok:r.ok, status:r.status, data};
  };

  const findInput = (re)=> Array.from(document.querySelectorAll('input')).find(i => re.test((i.placeholder||'')+' '+(i.name||'')+' '+(i.id||''))) || null;
  const findBtn = (t)=> Array.from(document.querySelectorAll('button,a')).find(b => ((b.textContent||'').trim().toLowerCase()===t)) || null;

  async function ensureToken(){
    let t=(localStorage.getItem(K_T)||'').trim();
    const ti = findInput(/token/i);
    if (ti && (ti.value||'').trim().length>=8) { t=(ti.value||'').trim(); localStorage.setItem(K_T,t); return t; }
    if (!t){
      const ref = (qs('ref')||qs('ref_token')||'').trim();
      const rr = await post('/register_web', ref ? {ref_token:ref}:{});
      if(!rr.ok || !rr.data || !rr.data.token) throw new Error('register_web failed');
      t=String(rr.data.token); localStorage.setItem(K_T,t);
      if (ti) ti.value=t;
    }
    return t;
  }

  function setRef(token, siteOrigin){
    const ri = findInput(/ref/i);
    if(!ri) return;
    const origin=(siteOrigin||'https://mw-expedition.com').replace(/\/+$/,'');
    ri.value = `${origin}/airdrop?ref=${encodeURIComponent(token)}`;
    const copy = findBtn('copy link') || findBtn('copy');
    if(copy && !copy.__l){ copy.__l=true; copy.addEventListener('click', async (e)=>{ e.preventDefault(); try{ await navigator.clipboard.writeText(ri.value);}catch{} }); }
  }

  function setTG(token){
    const url=`https://t.me/Logos_lrb_bot?start=airdrop_${encodeURIComponent(token)}`;
    for(const a of Array.from(document.querySelectorAll('a'))){
      const href=(a.getAttribute('href')||'');
      if(href.includes('t.me') && href.toLowerCase().includes('logos')) a.href=url;
      if(((a.textContent||'').trim().toLowerCase()==='open') && (a.closest('*')?.textContent||'').toLowerCase().includes('telegram')) a.href=url;
    }
  }

  function patchBadges(s){
    const set = (k, ok)=>{
      const blocks = Array.from(document.querySelectorAll('div,li,section'));
      const b = blocks.find(x => (x.textContent||'').toLowerCase().includes(k) && /(wait|ok)/i.test(x.textContent||''));
      if(!b) return;
      const badge = Array.from(b.querySelectorAll('span,div')).find(x => /^(wait|ok)$/i.test((x.textContent||'').trim()));
      if(badge) badge.textContent = ok ? 'OK':'WAIT';
    };
    set('wallet', !!s.wallet_bound);
    set('telegram', !!s.telegram_ok);
    set('follow', !!s.twitter_follow);
    set('like', !!s.twitter_like);
    set('repost', !!s.twitter_retweet);
    set('retweet', !!s.twitter_retweet);
  }

  async function refresh(){
    let t = await ensureToken();
    let r = await post('/status', {token:t});
    if(!r.ok && r.status===404){
      localStorage.removeItem(K_T);
      t = await ensureToken();
      r = await post('/status', {token:t});
    }
    if(!r.ok) return null;
    const s=r.data||{};
    setRef(t, s.site_origin);
    setTG(t);
    patchBadges(s);
    return s;
  }

  function wireX(){
    const xu = findInput(/yourname|username|twitter|x/i);
    const saved=(localStorage.getItem(K_X)||'').trim();
    if(xu && saved && !(xu.value||'').trim()) xu.value=saved;

    for(const b of Array.from(document.querySelectorAll('button')).filter(x => (x.textContent||'').trim().toLowerCase()==='save')){
      if(b.__xs) continue; b.__xs=true;
      b.addEventListener('click', async (e)=>{
        e.preventDefault();
        const t=await ensureToken();
        const inp = findInput(/yourname|username|twitter|x/i);
        let v=(inp?.value||'').trim().replace(/^@/,'');
        if(!v) return;
        localStorage.setItem(K_X,v);
        // ВАЖНО: поле именно twitter_username
        await post('/set_x_username', {token:t, twitter_username:v});
        await refresh();
      });
    }

    const vb=findBtn('verify');
    if(vb && !vb.__xv){ vb.__xv=true;
      vb.addEventListener('click', async (e)=>{
        e.preventDefault();
        const t=await ensureToken();
        await post('/verify_x', {token:t});
        await refresh();
      });
    }
  }

  function wireRefresh(){
    const b=findBtn('refresh status') || findBtn('refresh');
    if(!b || b.__rs) return;
    b.__rs=true;
    b.addEventListener('click', async (e)=>{ e.preventDefault(); await refresh(); });
  }

  async function boot(){
    try{
      await ensureToken();
      wireRefresh();
      wireX();
      await refresh();
    }catch(e){ console.error('airdrop-fix boot', e); }
  }

  if(document.readyState==='loading') document.addEventListener('DOMContentLoaded', boot);
  else boot();

  function setLatestTweetLink(st) {
    try {
      const id = st && (st.x_latest_tweet_id || st.x_latest_tweet || st.latest_tweet_id);
      if (!id) return;
      const url = `https://x.com/RspLogos/status/${id}`;
      const el = document.querySelector('[data-task="x_repost"], #task_x_repost, #xRepostLink') || null;
      // fallback: find by text
      let container = el;
      if (!container) {
        const nodes = Array.from(document.querySelectorAll("div,section,li,p"));
        container = nodes.find(n => (n.textContent||"").toLowerCase().includes("x repost") || (n.textContent||"").toLowerCase().includes("ретвит"));
      }
      if (!container) return;
      let a = document.getElementById("x_latest_tweet_a");
      if (!a) {
        a = document.createElement("a");
        a.id = "x_latest_tweet_a";
        a.target = "_blank";
        a.rel = "noopener noreferrer";
        a.style.display = "inline-block";
        a.style.marginLeft = "10px";
        a.textContent = "Открыть проверяемый пост";
        container.appendChild(a);
      }
      a.href = url;
    } catch {}
  }

})();

;(() => {
  try {
    const kill = () => {
      const nodes = Array.from(document.querySelectorAll("div,li,section,p,span"));
      for (const n of nodes) {
        const t = (n.textContent || "").toLowerCase();
        if (t.includes("follow") && (t.includes("x") || t.includes("twitter"))) {
          n.style.display = "none";
        }
        if (t.includes("подпис") && (t.includes("x") || t.includes("твит"))) {
          n.style.display = "none";
        }
      }
    };
    if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", kill);
    else kill();
  } catch {}
})();

```
