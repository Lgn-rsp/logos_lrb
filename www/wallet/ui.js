(() => {
  // Берём API из app.js, если он есть, иначе собираем по origin
  const API_BASE = (window.API ||
                    window.API_ENDPOINT ||
                    (location.origin.replace(/\/$/, '') + '/api'));

  function fmtInt(x) {
    if (x === null || x === undefined) return '—';
    if (typeof x !== 'number') {
      const n = Number(x);
      if (!Number.isFinite(n)) return String(x);
      x = n;
    }
    return x.toLocaleString('en-US');
  }

  function fmtShare(x) {
    if (x === null || x === undefined) return '—';
    if (typeof x !== 'number') {
      const n = Number(x);
      if (!Number.isFinite(n)) return String(x);
      x = n;
    }
    return x.toFixed(6) + ' %';
  }

  function setBalanceWidgets(data) {
    const elLgn   = document.querySelector('#balance-lgn');
    const elRLgn  = document.querySelector('#balance-rlgn');
    const elMicro = document.querySelector('#balance-micro');
    const elShare = document.querySelector('#balance-share');

    const all = [elLgn, elRLgn, elMicro, elShare].filter(Boolean);
    if (!all.length) return;

    if (!data || typeof data !== 'object') {
      all.forEach((el) => { el.textContent = '—'; });
      return;
    }

    if (elLgn) {
      elLgn.textContent = (data.balance !== undefined)
        ? fmtInt(data.balance)
        : '—';
    }

    const rVal = (data.balance_rLGN !== undefined)
      ? data.balance_rLGN
      : data.balance_r_lgn;

    if (elRLgn) {
      elRLgn.textContent = (rVal !== undefined)
        ? fmtInt(rVal)
        : '—';
    }

    if (elMicro) {
      elMicro.textContent = (data.balance_micro !== undefined)
        ? fmtInt(data.balance_micro)
        : '—';
    }

    if (elShare) {
      elShare.textContent = (data.share_of_supply_percent !== undefined)
        ? fmtShare(data.share_of_supply_percent)
        : '—';
    }
  }

  async function fetchBalance(rid) {
    const resp = await fetch(
      `${API_BASE}/balance/${encodeURIComponent(rid)}`,
      { method: 'GET', credentials: 'same-origin', cache: 'no-store' },
    );
    if (!resp.ok) {
      throw new Error(`/balance ${resp.status}`);
    }
    return resp.json();
  }

  async function refreshWidgetsFromApi() {
    try {
      const inp = document.querySelector('#rid-balance');
      const rid = (inp && inp.value.trim()) || (window.RID || '').trim();
      if (!rid) return;
      const data = await fetchBalance(rid);
      setBalanceWidgets(data);
    } catch (e) {
      console.error('ui balance error:', e);
      setBalanceWidgets(null);
    }
  }

  function setup() {
    const btn = document.querySelector('#btn-balance');
    if (!btn) return;

    // При нажатии на "Показать баланс" делаем доп. запрос только для виджетов.
    btn.addEventListener('click', () => {
      // app.js уже делает свой запрос и пишет в <pre>,
      // а мы параллельно обновляем красивые плитки.
      refreshWidgetsFromApi();
    });

    // Можно один раз попробовать подтянуть баланс при загрузке,
    // если RID уже есть в сессии.
    refreshWidgetsFromApi().catch(() => {});
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', setup);
  } else {
    setup();
  }
})();
