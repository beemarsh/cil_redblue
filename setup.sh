#!/usr/bin/env bash
# One-command setup for team machines (Kali / Parrot Linux).
# Creates a venv, installs deps, and registers a systemd service
# that starts automatically on boot.
#
# Usage:
#   sudo ./setup.sh --team <blue|red> --computer <c1|c2|...>

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
  echo "Usage: sudo ./setup.sh --team <blue|red> --computer <c1|c2|...>"
  exit 1
fi

WORKDIR="$(cd "$(dirname "$0")" && pwd)"
VENV="$WORKDIR/.venv"
SERVICE="redblue-attack"
SERVICE_DASH="redblue-dashboard"

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
Description=RedBlue attack agent ($TEAM.$COMPUTER)
After=network-online.target
Wants=network-online.target

[Service]
WorkingDirectory=$WORKDIR
ExecStart=$VENV/bin/python3 $WORKDIR/attack.py --team $TEAM --computer $COMPUTER --loop
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable "$SERVICE"
systemctl restart "$SERVICE"
echo "    OK"

# ── 3. Operator dashboard service ─────────────────────────────────────────────
echo "==> Registering systemd service: $SERVICE_DASH..."
cat > "/etc/systemd/system/$SERVICE_DASH.service" <<EOF
[Unit]
Description=RedBlue operator dashboard ($TEAM.$COMPUTER)
After=network-online.target
Wants=network-online.target

[Service]
WorkingDirectory=$WORKDIR
ExecStart=$VENV/bin/python3 $WORKDIR/computer_server.py --team $TEAM --computer $COMPUTER --config $WORKDIR/config.yaml
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable "$SERVICE_DASH"
systemctl restart "$SERVICE_DASH"
echo "    OK"

# ── 4. Summary ────────────────────────────────────────────────────────────────
echo ""
echo "======================================================"
echo "  Team machine ready: $TEAM.$COMPUTER"
echo ""
echo "  Services running and enabled on boot:"
echo "    $SERVICE       — automated attack loop"
echo "    $SERVICE_DASH  — operator dashboard (port 8080)"
echo ""
echo "  OPERATOR DASHBOARD:"
echo "    http://$(hostname -I | awk '{print $1}'):8080/"
echo ""
echo "  Useful commands:"
echo "    sudo systemctl status  $SERVICE"
echo "    sudo systemctl status  $SERVICE_DASH"
echo "    sudo journalctl -u     $SERVICE_DASH -f"
echo "    sudo systemctl restart $SERVICE_DASH"
echo ""
echo "  To run dashboard manually:"
echo "    source $WORKDIR/activate.sh"
echo "    python3 computer_server.py --team $TEAM --computer $COMPUTER"
echo "======================================================"
