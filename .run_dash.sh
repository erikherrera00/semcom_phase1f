#!/usr/bin/env bash
set -euo pipefail

# Resolve project & venv (defaults match your repo)
PROJECT_DIR="${PROJECT_DIR:-$HOME/semcom_phase1f}"
VENV_PATH="${VENV_PATH:-$PROJECT_DIR/.venv}"

cd "$PROJECT_DIR"
source "$VENV_PATH/bin/activate"
python telemetry_dash.py

