#!/usr/bin/env bash
# demo.sh — Launch RX, TX, Dashboard in separate macOS Terminal windows (robust)
set -euo pipefail

### ---- USER SETTINGS ----
PROJECT_DIR="${PROJECT_DIR:-$HOME/semcom_phase1f}"
VENV_PATH="${VENV_PATH:-$PROJECT_DIR/.venv}"

SESSION_ID="${SESSION_ID:-7}"
PROFILE="${PROFILE:-heavy}"
MODE="${MODE:-ecdh}"     # ecdh | psk

# Ports: RX binds to PORT_RX, TX binds to PORT_TX
PORT_RX="${PORT_RX:-9001}"
PORT_TX="${PORT_TX:-9000}"

# Message (or file)
MSG="${MSG:-DARPA demo: ECDH + critical ARQ + telemetry}"
MSG_FILE="${MSG_FILE:-}"   # if non-empty, overrides MSG

# Signed profile (optional)
PROFILE_JSON="${PROFILE_JSON:-}"         # e.g., $PROJECT_DIR/profiles/heavy.json
ENFORCE_SIGNED="${ENFORCE_SIGNED:-false}"
PUBKEY_PEM="${PUBKEY_PEM:-$PROJECT_DIR/keys/ed25519_pub.pem}"

# PSK only used if MODE=psk
PSK_HEX="${PSK_HEX:-00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff}"

### ---- Build common flags ----
PROFILE_FLAGS=()
if [[ -n "${PROFILE_JSON}" ]]; then
  PROFILE_FLAGS+=(--profile_json "$PROFILE_JSON")
  if [[ "$ENFORCE_SIGNED" == "true" ]]; then
    if [[ ! -f "$PUBKEY_PEM" ]]; then
      echo "[ERR] ENFORCE_SIGNED=true but pubkey not found: $PUBKEY_PEM" >&2
      exit 2
    fi
    PROFILE_FLAGS+=(--pubkey "$PUBKEY_PEM" --enforce_signed)
  fi
else
  PROFILE_FLAGS+=(--profile "$PROFILE")
fi

MODE_RX_FLAGS=()
MODE_TX_FLAGS=()
case "$MODE" in
  ecdh) MODE_RX_FLAGS+=(--ecdh); MODE_TX_FLAGS+=(--ecdh) ;;
  psk)  MODE_RX_FLAGS+=(--psk_hex "$PSK_HEX"); MODE_TX_FLAGS+=(--psk_hex "$PSK_HEX") ;;
  *)    echo "[ERR] MODE must be ecdh or psk" >&2; exit 2 ;;
esac

SESSION_FLAGS=(--session_id "$SESSION_ID")
LINK_RX_FLAGS=(--bind_port "$PORT_RX" --peer_port "$PORT_TX")
LINK_TX_FLAGS=(--bind_port "$PORT_TX" --peer_port "$PORT_RX")

### ---- Ensure logs dir ----
mkdir -p "$PROJECT_DIR/logs"

### ---- Write helper scripts (avoid quoting hell in AppleScript) ----
cat > "$PROJECT_DIR/.run_rx.sh" <<EOF
#!/usr/bin/env bash
set -euo pipefail
cd "$PROJECT_DIR"
source "$VENV_PATH/bin/activate"
python -u securecomms.py --role recv ${MODE_RX_FLAGS[*]} ${SESSION_FLAGS[*]} \\
  ${PROFILE_FLAGS[*]} ${LINK_RX_FLAGS[*]} --once | tee logs/rx_demo.log
EOF
chmod +x "$PROJECT_DIR/.run_rx.sh"

if [[ -n "$MSG_FILE" ]]; then
  SEND_MSG="--msg_file \"$MSG_FILE\""
else
  SEND_MSG="--msg \"$MSG\""
fi

cat > "$PROJECT_DIR/.run_tx.sh" <<EOF
#!/usr/bin/env bash
set -euo pipefail
cd "$PROJECT_DIR"
source "$VENV_PATH/bin/activate"
python securecomms.py --role send ${MODE_TX_FLAGS[*]} ${SESSION_FLAGS[*]} \\
  ${PROFILE_FLAGS[*]} ${LINK_TX_FLAGS[*]} $SEND_MSG | tee logs/tx_demo.log
EOF
chmod +x "$PROJECT_DIR/.run_tx.sh"

cat > "$PROJECT_DIR/.run_dash.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
cd "$PROJECT_DIR"
source "$VENV_PATH/bin/activate"
python telemetry_dash.py
EOF
# Patch in actual PROJECT_DIR (since we used a single-quoted heredoc)
sed -i '' "s#\$PROJECT_DIR#${PROJECT_DIR//\//\\/}#g" "$PROJECT_DIR/.run_dash.sh"
chmod +x "$PROJECT_DIR/.run_dash.sh"

### ---- Kill stale port users (optional) ----
if command -v lsof >/dev/null 2>&1; then
  for P in "$PORT_RX" "$PORT_TX"; do
    PIDS=$(lsof -t -iUDP:$P || true)
    if [[ -n "$PIDS" ]]; then
      echo "[info] Killing stale UDP:$P -> $PIDS"
      kill -9 $PIDS || true
    fi
  done
fi

### ---- macOS Terminal launch ----
if [[ "$(uname -s)" == "Darwin" ]] && command -v osascript >/dev/null 2>&1; then
  echo "[info] Launching 3 Terminal windows..."

  osascript <<OSA
tell application "Terminal"
  activate
  do script "cd '$PROJECT_DIR'; ./.run_rx.sh"
end tell
OSA

  sleep 0.8

  osascript <<OSA
tell application "Terminal"
  activate
  do script "cd '$PROJECT_DIR'; ./.run_tx.sh"
end tell
OSA

  osascript <<OSA
tell application "Terminal"
  activate
  do script "cd '$PROJECT_DIR'; ./.run_dash.sh"
end tell
OSA

  echo "[info] RX, TX, Dashboard launched."
  exit 0
fi

### ---- Fallback (non-macOS) ----
echo
echo "Run manually in 3 terminals:"
echo "  $PROJECT_DIR/.run_rx.sh"
echo "  $PROJECT_DIR/.run_tx.sh"
echo "  $PROJECT_DIR/.run_dash.sh"

