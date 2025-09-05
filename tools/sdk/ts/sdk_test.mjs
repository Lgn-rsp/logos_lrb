import { LogosApi } from "./index.mjs";

// Конфигурация
const HOST = process.env.HOST || "http://127.0.0.1:8080"; // без /api если сервер слушает напрямую
const BASE = process.env.BASE || (HOST.endsWith("/api") ? HOST : HOST + "/api");

async function main() {
  const api = new LogosApi(BASE, { timeoutMs: 10_000 });

  console.log("[*] healthz", await api.healthz());
  console.log("[*] head", await api.head());

  // RID для теста
  // (Можно сгенерить в кошельке; здесь просто smoke по faucet/balance с рандомным RID формально не пройдёт —
  // поэтому делаем только faucet на RID из кошелька, если задан)
  const RID = process.env.RID;
  if (RID) {
    console.log("[*] faucet", await api.faucet(RID, 1000000));
    console.log("[*] balance", await api.balance(RID));
  } else {
    console.log("[i] пропускаю faucet/balance: задайте RID=... в env");
  }

  // submit one (если есть RID и получатель)
  const TO = process.env.TO;
  if (RID && TO) {
    // запрос канона (реальную подпись оставим кошельку; здесь smoke-тест только на 400/401)
    const canon = await api.debugCanon({ from: RID, to: TO, amount: 1, nonce: 1 });
    console.log("[*] canon_hex len", canon.canon_hex.length);
    try {
      const resp = await api.submitBatch([{ from: RID, to: TO, amount: 1, nonce: 1, sig_hex: "00" }]);
      console.log("[*] submit", resp);
    } catch (e) {
      console.log("[*] submit expected error", e.status, e.payload?.results?.[0] ?? e.payload);
    }
  } else {
    console.log("[i] пропускаю submit: задайте RID и TO");
  }
}

main().catch(e => { console.error("ERR", e); process.exit(1); });
