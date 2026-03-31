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

# ── 3. Summary ────────────────────────────────────────────────────────────────
echo ""
echo "======================================================"
echo "  Team machine ready: $TEAM.$COMPUTER"
echo "  Service '$SERVICE' is running and enabled on boot."
echo ""
echo "  Useful commands:"
echo "    sudo systemctl status  $SERVICE"
echo "    sudo journalctl -u     $SERVICE -f"
echo "    sudo systemctl stop    $SERVICE"
echo "    sudo systemctl restart $SERVICE"
echo ""
echo "  To run manually (outside the service):"
echo "    source $WORKDIR/activate.sh"
echo "    python3 attack.py --team $TEAM --computer $COMPUTER"
echo "======================================================"
