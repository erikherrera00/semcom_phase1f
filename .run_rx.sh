#!/usr/bin/env bash
set -euo pipefail
PROJECT_DIR="${PROJECT_DIR:-$HOME/semcom_phase1f}"
VENV_PATH="${VENV_PATH:-$PROJECT_DIR/.venv}"

cd "$PROJECT_DIR"
source "$VENV_PATH/bin/activate"
python -u securecomms.py \
  --role recv --ecdh --session_id 7 \
  --profile heavy \
  --bind_port 9001 --peer_port 9000 \
  --once

