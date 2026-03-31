#!/usr/bin/env bash
# Deploy script for team machines (Kali / Parrot Linux).
# Run as root or with sudo.
#
# Usage:
#   sudo ./deploy.sh --team blue --computer c1
#   sudo ./deploy.sh --team red  --computer c2

set -euo pipefail

TEAM=""
COMPUTER=""

while [[ $# -gt 0 ]]; do
  case $1 in
    --team)     TEAM="$2";     shift 2 ;;
    --computer) COMPUTER="$2"; shift 2 ;;
    *) echo "Unknown argument: $1"; exit 1 ;;
  esac
done

if [[ -z "$TEAM" || -z "$COMPUTER" ]]; then
  echo "Usage: sudo ./deploy.sh --team <blue|red> --computer <c1|c2|...>"
  exit 1
fi

echo "==> Installing dependencies..."
apt-get update -qq
apt-get install -y nmap python3 python3-pip python3-venv

echo "==> Setting up Python virtualenv..."
python3 -m venv .venv
source .venv/bin/activate
pip install --quiet pyyaml requests

echo "==> Writing systemd service: redblue-attack.service"
SERVICE_FILE="/etc/systemd/system/redblue-attack.service"
WORKDIR="$(pwd)"

cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=RedBlue attack agent ($TEAM.$COMPUTER)
After=network.target

[Service]
WorkingDirectory=$WORKDIR
ExecStart=$WORKDIR/.venv/bin/python3 $WORKDIR/attack.py --team $TEAM --computer $COMPUTER --loop
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable redblue-attack.service
systemctl start  redblue-attack.service

echo ""
echo "Done. Service status:"
systemctl status redblue-attack.service --no-pager

echo ""
echo "Useful commands:"
echo "  sudo systemctl status redblue-attack"
echo "  sudo journalctl -u redblue-attack -f"
echo "  sudo systemctl stop   redblue-attack"
