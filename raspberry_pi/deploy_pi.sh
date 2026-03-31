#!/usr/bin/env bash
# Deploy the log server on the Raspberry Pi.
# Run as root or with sudo.
#
# Usage:
#   sudo ./deploy_pi.sh [--port 5000]

set -euo pipefail

PORT=5000
while [[ $# -gt 0 ]]; do
  case $1 in
    --port) PORT="$2"; shift 2 ;;
    *) echo "Unknown argument: $1"; exit 1 ;;
  esac
done

echo "==> Installing system packages..."
apt-get update -qq
apt-get install -y python3 python3-pip python3-venv

echo "==> Setting up Python virtualenv..."
python3 -m venv .venv
source .venv/bin/activate
pip install --quiet -r requirements.txt

echo "==> Writing systemd service: redblue-pi.service"
WORKDIR="$(pwd)"
SERVICE_FILE="/etc/systemd/system/redblue-pi.service"

cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=RedBlue log server
After=network.target

[Service]
WorkingDirectory=$WORKDIR
ExecStart=$WORKDIR/.venv/bin/python3 $WORKDIR/server.py --port $PORT
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable redblue-pi.service
systemctl start  redblue-pi.service

echo ""
echo "Done. Log server running on port $PORT"
echo "Dashboard: http://$(hostname -I | awk '{print $1}'):$PORT/"
echo ""
echo "Useful commands:"
echo "  sudo systemctl status redblue-pi"
echo "  sudo journalctl -u redblue-pi -f"
