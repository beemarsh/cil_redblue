#!/usr/bin/env bash
# Activates the project virtual environment in the current shell.
# Must be sourced, not executed:
#   source ./activate.sh   OR   . ./activate.sh

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV="$SCRIPT_DIR/.venv"

if [[ ! -f "$VENV/bin/activate" ]]; then
  echo "ERROR: Virtual environment not found. Run ./deploy_pi.sh first."
  return 1
fi

source "$VENV/bin/activate"
echo "Activated: $VENV"
echo "Python: $(which python3)"
