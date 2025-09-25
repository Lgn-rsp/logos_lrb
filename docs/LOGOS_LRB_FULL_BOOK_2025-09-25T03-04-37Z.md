# LOGOS LRB — FULL BOOK (прод-срез, 2025-09-25T03-04-37Z UTC)

**commit:** `ec442d2`  **branch:** `main`

## Архитектура и состояние
… (сюда вставь актуальный раздел, что я писал ранее — можно держать в docs/_partials.md и cat)

## Канон деплоя/сборки
```bash
cd /root/logos_lrb && cargo build --release -p logos_node
sudo systemctl stop logos-node@main || true
sudo install -m 0755 target/release/logos_node /opt/logos/bin/logos_node
sudo chown logos:logos /opt/logos/bin/logos_node
sudo systemctl daemon-reload && sudo systemctl start logos-node@main
sleep 1
curl -s http://127.0.0.1:8080/livez;  echo
curl -s http://127.0.0.1:8080/readyz; echo
```

## Автоподпись и ретраи
```bash
KEY=/var/lib/logos/node_key TO="<RID>" AMOUNT=1000 logos_send
```

## Метрики и алерты
… (приложить фрагмент правил Prometheus/Grafana)
