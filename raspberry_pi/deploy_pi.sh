#!/usr/bin/env bash
# One-command setup for the Raspberry Pi.
# Creates a venv, installs deps, and registers a systemd service
# that starts automatically on boot.
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

WORKDIR="$(cd "$(dirname "$0")" && pwd)"
VENV="$WORKDIR/.venv"
SERVICE="redblue-pi"

# ── 1. Virtual environment ────────────────────────────────────────────────────
echo "==> Creating virtual environment..."
python3 -m venv "$VENV"
"$VENV/bin/pip" install --quiet --upgrade pip
"$VENV/bin/pip" install --quiet -r "$WORKDIR/requirements.txt"
echo "    OK — $VENV"

# ── 2. Systemd service ────────────────────────────────────────────────────────
echo "==> Registering systemd service: $SERVICE..."
cat > "/etc/systemd/system/$SERVICE.service" <<EOF
[Unit]
Description=RedBlue log server (dashboard)
After=network-online.target
Wants=network-online.target

[Service]
WorkingDirectory=$WORKDIR
ExecStart=$VENV/bin/python3 $WORKDIR/server.py --port $PORT
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable "$SERVICE"
systemctl restart "$SERVICE"
echo "    OK"

# ── 3. Summary ────────────────────────────────────────────────────────────────
PI_IP="$(hostname -I | awk '{print $1}')"
echo ""
echo "======================================================"
echo "  Raspberry Pi log server is running."
echo "  Service '$SERVICE' is enabled on boot."
echo ""
echo "  Dashboard: http://$PI_IP:$PORT/"
echo ""
echo "  Useful commands:"
echo "    sudo systemctl status  $SERVICE"
echo "    sudo journalctl -u     $SERVICE -f"
echo "    sudo systemctl stop    $SERVICE"
echo "    sudo systemctl restart $SERVICE"
echo ""
echo "  To run manually (outside the service):"
echo "    source $WORKDIR/activate.sh"
echo "    python3 server.py --port $PORT"
echo "======================================================"
