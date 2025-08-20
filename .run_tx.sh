#!/usr/bin/env bash
set -euo pipefail
cd "/Users/erikherrera/semcom_phase1f"
source "/Users/erikherrera/semcom_phase1f/.venv/bin/activate"
python securecomms.py --role send --ecdh --session_id 7 \
  --profile heavy --bind_port 9000 --peer_port 9001 --msg "DARPA demo: ECDH + critical ARQ + telemetry" | tee logs/tx_demo.log
