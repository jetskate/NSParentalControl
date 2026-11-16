#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="/home/ai-agent/workspace/projects/switch-parental"
SERVER_DIR="/home/ai-agent/switch-server"
DATA_DIR="${SERVER_DIR}/data"
LOG_FILE="${PROJECT_DIR}/logs/smoke_test.log"

mkdir -p "${PROJECT_DIR}/logs" "${DATA_DIR}"

cleanup_data() {
  rm -f "${DATA_DIR}/state.json" "${DATA_DIR}/poller_view.json" "${DATA_DIR}/events.jsonl" \
        "${DATA_DIR}/commands.json" "${DATA_DIR}/.state.lock" "${DATA_DIR}/.commands.lock" "${DATA_DIR}/.events.lock"
  printf '{"devices": {}, "updated_at": 0}\n' > "${DATA_DIR}/state.json"
  printf '{"config_rev": 1, "seq": 0, "commands": []}\n' > "${DATA_DIR}/commands.json"
  : > "${DATA_DIR}/events.jsonl"
}

SERVER_PID=""
stop_local_server() {
  if [ -n "${SERVER_PID}" ] && kill -0 "${SERVER_PID}" 2>/dev/null; then
    kill "${SERVER_PID}" 2>/dev/null || true
    wait "${SERVER_PID}" 2>/dev/null || true
  fi
}
trap stop_local_server EXIT

{
  echo "=== Switch Server Smoke Test ($(date -Is)) ==="
  cleanup_data

  # Start switch_server.py locally on 127.0.0.1:39107 if port not already bound
  if ! ss -tln | grep -q ':39107 '; then
    python3 "${SERVER_DIR}/switch_server.py" --config "${SERVER_DIR}/config.json" --host 127.0.0.1 --port 39107 &
    SERVER_PID=$!
    sleep 1
  fi

  python3 "${PROJECT_DIR}/tests/fake_client.py" --host 127.0.0.1 --port 39107 --config "${SERVER_DIR}/config.json"

  echo "--- Verify switchctl status ---"
  "${SERVER_DIR}/switchctl" --data-dir "${DATA_DIR}" status

  echo "--- Verify poll_switch.py --source server --dry-run ---"
  python3 "${PROJECT_DIR}/poller/poll_switch.py" \
    --source server \
    --server-view "${DATA_DIR}/poller_view.json" \
    --state-file "${PROJECT_DIR}/logs/poller_smoke_state.json" \
    --dry-run

  echo "--- Verify events.jsonl summary ---"
  cat "${DATA_DIR}/events.jsonl"

  echo "--- Verify make_seed.py PIN preservation & --uid roundtrip ---"
  TMP_SEED_OLD="${PROJECT_DIR}/logs/test_old_settings.bin"
  TMP_SEED_NEW="${PROJECT_DIR}/logs/test_new_settings.bin"
  python3 - <<PY
import sys
sys.path.insert(0, "${PROJECT_DIR}/seed")
from make_seed import TYPE_STRING, TYPE_INTEGER, write_settings_bin, read_settings_bin
write_settings_bin("${TMP_SEED_OLD}", {
    "admin_pin": (TYPE_STRING, "1,2,3,4", True),
    "enabled": (TYPE_INTEGER, 0, False),
})
PY
  python3 "${PROJECT_DIR}/seed/make_seed.py" \
    --in "${TMP_SEED_OLD}" \
    --out "${TMP_SEED_NEW}" \
    --uid "111111:222222"
  python3 - <<PY
import sys
sys.path.insert(0, "${PROJECT_DIR}/seed")
from make_seed import read_settings_bin
d = read_settings_bin("${TMP_SEED_NEW}")
assert d["admin_pin"] == (2, "1,2,3,4", True), f"PIN lost: {d.get('admin_pin')}"
assert d["daily_limit_users"][1] == "111111:222222=60"
assert d["daily_limit_weekend_users"][1] == "111111:222222=120"
assert d["game_start_users"][1] == "111111:222222=420"
assert d["bedtime_users"][1] == "111111:222222=1380"
print("[PASS] make_seed.py preserved admin_pin and preset UID limits cleanly")
PY
  rm -f "${TMP_SEED_OLD}" "${TMP_SEED_NEW}" "${PROJECT_DIR}/logs/poller_smoke_state.json"

  stop_local_server
  SERVER_PID=""

  echo "--- Cleanup fake-client test data in ${DATA_DIR} ---"
  cleanup_data
  echo "=== ALL 7 SCENARIOS + SEED + POLLER CHECKS PASSED ==="
} 2>&1 | tee "${LOG_FILE}"
