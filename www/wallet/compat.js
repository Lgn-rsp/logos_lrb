"use strict";

(function () {
  // Базовый URL API
  const API = location.origin + "/api";

  const $ = (s) => document.querySelector(s);

  async function jsonGet(path) {
    const r = await fetch(API + path, { method: "GET" });
    const txt = await r.text().catch(() => "");
    if (!r.ok) {
      throw new Error(`${path} ${r.status} ${txt}`);
    }
    try {
      return JSON.parse(txt);
    } catch {
      throw new Error(`${path} bad json: ${txt}`);
    }
  }

  // Правильный формат тела для /debug_canon
  async function debugCanon(from, to, amount, nonce) {
    const body = {
      from,
      to,
      amount: Number(amount),
      nonce: Number(nonce),
      // на бэкенде старые и новые типы — шлём оба поля на всякий случай
      sig: "",
      sig_hex: ""
    };

    const r = await fetch(API + "/debug_canon", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body)
    });

    const txt = await r.text().catch(() => "");
    if (!r.ok) {
      throw new Error(`/debug_canon ${r.status} ${txt}`);
    }
    let j;
    try {
      j = JSON.parse(txt);
    } catch {
      throw new Error(`/debug_canon bad json: ${txt}`);
    }
    if (!j.canon_hex) {
      throw new Error("debug_canon: no canon_hex in response");
    }
    return j.canon_hex;
  }

  // Подпись канонического hex; если есть старый signCanon — используем его
  async function signCanonCompat(canonHex) {
    // KEYS и signCanon объявлены в старом app.js (глобальные переменные)
    if (typeof signCanon === "function") {
      return await signCanon(KEYS.privateKey, canonHex);
    }

    if (!KEYS || !KEYS.privateKey) {
      throw new Error("кошелёк заблокирован (нет ключа)");
    }

    const bytes = new Uint8Array(
      canonHex.match(/.{1,2}/g).map((x) => parseInt(x, 16))
    );
    const sig = await crypto.subtle.sign("Ed25519", KEYS.privateKey, bytes);
    return Array.from(new Uint8Array(sig))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  }

  // Отправка batch'а (одна транза внутри массива)
  async function submitTx(tx) {
    const payload = { txs: [tx] };

    const r = await fetch(API + "/submit_tx_batch", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });

    const txt = await r.text().catch(() => "");
    if (!r.ok) {
      throw new Error(`/submit_tx_batch ${r.status} ${txt}`);
    }

    try {
      return JSON.parse(txt);
    } catch {
      return txt;
    }
  }

  // Получаем текущий nonce по RID
  async function autoNonce(rid) {
    const data = await jsonGet("/balance/" + encodeURIComponent(rid));
    return Number(data.nonce || 0);
  }

  window.addEventListener("DOMContentLoaded", () => {
    const btn = $("#btn-send");
    if (!btn) return; // не на той странице

    // выпиливаем старые обработчики: клонируем кнопку
    const newBtn = btn.cloneNode(true);
    btn.parentNode.replaceChild(newBtn, btn);

    const nonceInput = $("#nonce");
    if (nonceInput) {
      nonceInput.readOnly = true;
      nonceInput.placeholder = "авто по сети";
    }
    const nonceBtn = $("#btn-nonce");
    if (nonceBtn) {
      nonceBtn.style.display = "none"; // прячем кнопку nonce
    }

    const out = $("#out-send");
    const show = (v) => {
      if (!out) return;
      out.textContent =
        typeof v === "string" ? v : JSON.stringify(v, null, 2);
    };

    newBtn.addEventListener("click", async () => {
      try {
        // RID и KEYS приходят из старого app.js
        if (typeof RID === "undefined" || !RID) {
          throw new Error("RID не найден (перезайди в кошелёк)");
        }
        if (typeof KEYS === "undefined" || !KEYS || !KEYS.privateKey) {
          throw new Error("кошелёк заблокирован (нет ключа)");
        }

        const toEl = $("#to");
        const amtEl = $("#amount");
        if (!toEl || !amtEl) throw new Error("не найдены поля формы");

        const to = toEl.value.trim();
        const amount = Number(amtEl.value);

        if (!to) throw new Error("укажи RID получателя");
        if (!Number.isFinite(amount) || amount <= 0) {
          throw new Error("сумма должна быть > 0");
        }

        // 1) узнаём nonce из /balance
        const currentNonce = await autoNonce(RID);
        const nonce = currentNonce + 1;
        if (nonceInput) nonceInput.value = String(nonce);

        // 2) получаем канонический hex от /debug_canon
        const canon = await debugCanon(RID, to, amount, nonce);

        // 3) подписываем
        const sigHex = await signCanonCompat(canon);

        // 4) собираем транзакцию под новый ApiSubmitTx
        const tx = {
          from: RID,
          to,
          amount: Number(amount),
          nonce,
          sig: sigHex,
          sig_hex: sigHex
        };

        const resp = await submitTx(tx);
        show(resp);
      } catch (e) {
        console.error(e);
        show(String(e));
      }
    });
  });
})();
