#!/usr/bin/env bash
set -euo pipefail
DOMAIN="${DOMAIN:-example.com}"
INSTANCE="${INSTANCE:-a}"

sudo apt-get update -y
sudo apt-get install -y git curl jq build-essential pkg-config libssl-dev nginx

/usr/bin/id logos >/dev/null 2>&1 || sudo useradd -r -m -d /var/lib/logos -s /usr/sbin/nologin logos
sudo mkdir -p /opt/logos /etc/logos /var/lib/logos /opt/logos/www/wallet

cd "$(dirname "$0")/.."
cargo build --release -p logos_node
sudo cp ./target/release/logos_node /opt/logos/logos_node
sudo chown logos:logos /opt/logos/logos_node
sudo chmod 755 /opt/logos/logos_node

sudo cp ./infra/systemd/logos-node@.service /etc/systemd/system/logos-node@.service
sudo systemctl daemon-reload

sudo cp ./infra/nginx/logos-api-lb.conf.example /etc/nginx/sites-available/logos-api-lb.conf
sudo sed -i "s/YOUR_DOMAIN/${DOMAIN}/" /etc/nginx/sites-available/logos-api-lb.conf
sudo ln -sf /etc/nginx/sites-available/logos-api-lb.conf /etc/nginx/sites-enabled/logos-api-lb.conf
sudo rm -f /etc/nginx/sites-enabled/default
sudo nginx -t && sudo systemctl reload nginx

sudo cp -r ./www/wallet/* /opt/logos/www/wallet/
sudo chown -R logos:logos /opt/logos/www

if [ ! -f "/etc/logos/node-${INSTANCE}.env" ]; then
  sudo cp ./configs/env/node.env.example "/etc/logos/node-${INSTANCE}.env"
  echo ">>> EDIT /etc/logos/node-${INSTANCE}.env (LRB_NODE_SK_HEX/LRB_ADMIN_KEY/LRB_WALLET_ORIGIN)"
fi

sudo systemctl enable --now "logos-node@${INSTANCE}"
systemctl --no-pager status "logos-node@${INSTANCE}"

echo "API: http://127.0.0.1:8080   Wallet: http://${DOMAIN}/wallet/"
