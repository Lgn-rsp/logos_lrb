// Lightweight production SDK for LOGOS LRB (ESM, no deps). Node 18+ (global fetch).
const DEFAULT_TIMEOUT_MS = 10_000;

export class LogosApi {
  /**
   * @param {string} baseURL e.g. "http://127.0.0.1:8080/api" or "http://host:8080"
   * @param {{timeoutMs?: number, adminKey?: string}} [opt]
   */
  constructor(baseURL, opt = {}) {
    this.baseURL = baseURL.replace(/\/$/, "");
    this.timeoutMs = opt.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.adminKey = opt.adminKey;
  }

  _url(path) {
    return this.baseURL + (path.startsWith("/") ? path : `/${path}`);
  }

  async _fetchJSON(method, path, body, headers = {}) {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), this.timeoutMs);
    try {
      const r = await fetch(this._url(path), {
        method,
        headers: {
          "Content-Type": "application/json",
          ...(this.adminKey ? { "X-Admin-Key": this.adminKey } : {}),
          ...headers,
        },
        body: body ? JSON.stringify(body) : undefined,
        signal: ctrl.signal,
      });
      const ct = r.headers.get("content-type") || "";
      let payload = null;
      if (ct.includes("application/json")) {
        payload = await r.json().catch(() => null);
      } else {
        payload = await r.text().catch(() => null);
      }
      if (!r.ok) {
        const err = new Error(`HTTP ${r.status}`);
        err.status = r.status;
        err.payload = payload;
        throw err;
      }
      return payload;
    } finally {
      clearTimeout(t);
    }
  }

  // -------- Public API
  async healthz()        { return this._fetchJSON("GET",  "/healthz"); }
  async livez()          { return this._fetchJSON("GET",  "/livez"); }
  async readyz()         { return this._fetchJSON("GET",  "/readyz"); }
  async head()           { return this._fetchJSON("GET",  "/head"); }
  async balance(rid)     { return this._fetchJSON("GET",  `/balance/${encodeURIComponent(rid)}`); }
  async debugCanon(tx)   { return this._fetchJSON("POST", "/debug_canon", { tx }); }
  async submitBatch(txs) { return this._fetchJSON("POST", "/submit_tx_batch", { txs }); }
  async faucet(rid, amount) { return this._fetchJSON("POST", "/faucet", { rid, amount }); }

  // -------- Admin
  async nodeInfo()       { return this._fetchJSON("GET",  "/node/info"); }
  async snapshot()       { return this._fetchJSON("POST", "/admin/snapshot"); }
  async restore(path)    { return this._fetchJSON("POST", "/admin/restore", { path }); }
}
