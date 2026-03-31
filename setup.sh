#!/usr/bin/env bash
# Creates a virtual environment and installs dependencies for team machines.
#
# Usage:
#   ./setup.sh

set -euo pipefail

VENV=".venv"

echo "==> Creating virtual environment at $VENV..."
python3 -m venv "$VENV"

echo "==> Installing dependencies..."
"$VENV/bin/pip" install --quiet --upgrade pip
"$VENV/bin/pip" install -r requirements.txt

echo ""
echo "Done. Activate with:"
echo "  source $VENV/bin/activate"
echo ""
echo "Then run attacks with:"
echo "  python3 attack.py --team <blue|red> --computer <c1|c2|...>"
echo "  python3 attack.py --team <blue|red> --computer <c1|c2|...> --loop"
