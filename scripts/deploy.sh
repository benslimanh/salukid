#!/bin/bash
set -e

echo "[*] Building production binary..."
make clean >/dev/null
make >/dev/null

echo "[*] Setting up directories..."
sudo mkdir -p /etc/salukid/ssl
sudo mkdir -p /var/www/salukid
sudo chown nobody:nogroup /var/www/salukid || sudo chown nobody:nobody /var/www/salukid
sudo mkdir -p /var/log/salukid
sudo chown nobody:nogroup /var/log/salukid || sudo chown nobody:nobody /var/log/salukid

echo "[*] Installing binary..."
sudo cp secure_httpd /usr/local/bin/

echo "[*] Installing SSL certificates..."
sudo cp ssl/server.crt /etc/salukid/ssl/
sudo cp ssl/server.key /etc/salukid/ssl/
sudo chmod 600 /etc/salukid/ssl/server.key

echo "[*] Creating default index.html..."
echo "<h1>Welcome to Salukid (Pilot Deployment)</h1><p>Server is running successfully via systemd!</p>" | sudo tee /var/www/salukid/index.html >/dev/null

echo "[*] Installing systemd service..."
sudo cp systemd/salukid.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable salukid
sudo systemctl restart salukid

echo "[*] Verifying deployment..."
sleep 2
sudo systemctl --no-pager status salukid
echo "[*] Testing HTTP (Port 80)..."
curl -s http://127.0.0.1/
echo -e "\n[*] Testing HTTPS (Port 443)..."
curl -sk https://127.0.0.1/
echo -e "\n[*] Pilot Deployment Complete!"
