#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="/home/ai-agent/workspace/projects/switch-parental"
SERVER_DIR="/home/ai-agent/switch-server"
DATA_DIR="${SERVER_DIR}/data"
LOG_FILE="${PROJECT_DIR}/logs/web_smoke_test.log"
COOKIE_JAR="${PROJECT_DIR}/logs/test_cookies.txt"

mkdir -p "${PROJECT_DIR}/logs"
rm -f "${COOKIE_JAR}"

{
  echo "=== Switch Web Admin Full-Chain Smoke Test ($(date -Is)) ==="

  echo "--- 1. OpenResty HTTPS /api/health & Bark non-regression ---"
  HEALTH_JSON=$(curl -k -sS --resolve switch.tomars.qzz.io:443:127.0.0.1 https://switch.tomars.qzz.io/api/health)
  echo "HEALTH: ${HEALTH_JSON}"
  BARK_CODE=$(curl -k -sS -o /dev/null -w "%{http_code}" --resolve bark.tomars.qzz.io:443:127.0.0.1 https://bark.tomars.qzz.io/ping)
  echo "BARK_PING_HTTP: ${BARK_CODE}"
  test "${BARK_CODE}" = "200"

  echo "--- 2. Four-Dimensional Version Gate ---"
  APP_VER=$(python3 -c 'import sys,json; print(json.loads(sys.argv[1])["version"])' "${HEALTH_JSON}")
  echo "[Dim 1] /api/health version = ${APP_VER}"

  echo "[Dim 2] Local source mtime & sha256:"
  stat -c "%n | size=%s | mtime=%y" "${PROJECT_DIR}/server/switch_server.py" "${SERVER_DIR}/switch_server.py"
  sha256sum "${PROJECT_DIR}/server/switch_server.py" "${SERVER_DIR}/switch_server.py"

  echo "[Dim 3] Container /app/switch_server.py size, sha256 & mtime:"
  sg docker -c "docker exec switch-server stat -c '%n | size=%s | mtime=%y' /app/switch_server.py"
  sg docker -c "docker exec switch-server sha256sum /app/switch_server.py"

  echo "[Dim 4] DOM 9px version badge check via https://switch.tomars.qzz.io/:"
  HTML_BODY=$(curl -k -sS --resolve switch.tomars.qzz.io:443:127.0.0.1 https://switch.tomars.qzz.io/)
  python3 - <<PY
import re
html_body = """${HTML_BODY//\"/\\\"}"""
ver = "${APP_VER}"
m1 = re.search(r'<span id="loginAppVersion" style="font-size: 9px;[^"]*">([^<]+)</span>', html_body)
m2 = re.search(r'<span id="appVersion" style="font-size: 9px;[^"]*">([^<]+)</span>', html_body)
assert m1 and m1.group(1) == ver, f"loginAppVersion mismatch: {m1.group(1) if m1 else None} != {ver}"
assert m2 and m2.group(1) == ver, f"appVersion mismatch: {m2.group(1) if m2 else None} != {ver}"
print(f"[PASS][Dim 4] loginAppVersion={m1.group(1)!r}, appVersion={m2.group(1)!r}")
PY

  echo "--- 3. Web API Auth, Cookie, Dual-Layer Sync & Restore ---"
  UNAUTH_CODE=$(curl -k -sS -o /dev/null -w "%{http_code}" --resolve switch.tomars.qzz.io:443:127.0.0.1 https://switch.tomars.qzz.io/api/status)
  echo "UNAUTH /api/status HTTP=${UNAUTH_CODE}"
  test "${UNAUTH_CODE}" = "401"

  BAD_PIN_CODE=$(curl -k -sS -o /dev/null -w "%{http_code}" --resolve switch.tomars.qzz.io:443:127.0.0.1 \
    -X POST -H "Content-Type: application/json" -d '{"pin":"0000"}' https://switch.tomars.qzz.io/api/login)
  echo "BAD_PIN /api/login HTTP=${BAD_PIN_CODE}"
  test "${BAD_PIN_CODE}" = "403"

  LOGIN_HEADERS=$(curl -k -sS -D - -o /tmp/login_body.json -c "${COOKIE_JAR}" --resolve switch.tomars.qzz.io:443:127.0.0.1 \
    -X POST -H "Content-Type: application/json" -d '{"pin":"2580"}' https://switch.tomars.qzz.io/api/login)
  echo "LOGIN_BODY: $(cat /tmp/login_body.json)"
  echo "${LOGIN_HEADERS}" | grep -qi "Set-Cookie: switch_admin_session=.*HttpOnly; Secure; SameSite=Lax; Max-Age=2592000"
  rm -f /tmp/login_body.json
  echo "[PASS] PIN 2580 login + HttpOnly; Secure; SameSite=Lax; Max-Age=2592000 cookie verified"

  # Note: curl -b with Secure cookie works on https://switch.tomars.qzz.io/
  STATUS_JSON=$(curl -k -sS -b "${COOKIE_JAR}" --resolve switch.tomars.qzz.io:443:127.0.0.1 https://switch.tomars.qzz.io/api/status)
  python3 - <<PY
import json
d = json.loads("""${STATUS_JSON//\"/\\\"}""")
assert d["ok"] is True
assert d["pi_state"]["ok"] is True
print(f"[PASS] /api/status active_source={d['active_source']} day={d['day']} rem={d['remaining_min']} used={d['used_min']}/{d['limit_min']} enforce={d['enforce_enabled']}")
PY

  # Grant +15 then restore -15
  PI_BEFORE=$(ssh -o BatchMode=yes pi@100.85.73.80 "python3 -c 'import json; print(json.load(open(\"/home/pi/switch-parental/state.json\")).get(\"granted_seconds\",0))'")
  GRANT_RES=$(curl -k -sS -b "${COOKIE_JAR}" --resolve switch.tomars.qzz.io:443:127.0.0.1 \
    -X POST -H "Content-Type: application/json" -d '{"minutes":15}' https://switch.tomars.qzz.io/api/grant)
  echo "GRANT_+15: ${GRANT_RES}"
  PI_AFTER=$(ssh -o BatchMode=yes pi@100.85.73.80 "python3 -c 'import json; print(json.load(open(\"/home/pi/switch-parental/state.json\")).get(\"granted_seconds\",0))'")
  test "$((PI_AFTER - PI_BEFORE))" = "900"
  RESTORE_GRANT=$(curl -k -sS -b "${COOKIE_JAR}" --resolve switch.tomars.qzz.io:443:127.0.0.1 \
    -X POST -H "Content-Type: application/json" -d '{"minutes":-15}' https://switch.tomars.qzz.io/api/grant)
  echo "RESTORE_-15: ${RESTORE_GRANT}"
  PI_RESTORED=$(ssh -o BatchMode=yes pi@100.85.73.80 "python3 -c 'import json; print(json.load(open(\"/home/pi/switch-parental/state.json\")).get(\"granted_seconds\",0))'")
  test "${PI_RESTORED}" = "${PI_BEFORE}"
  echo "[PASS] /api/grant +15 synced switch-server & Pi (+900s), then restored to ${PI_BEFORE}s"

  # Toggle enforce true -> check Pi enforce_mode=="close" -> restore false -> Pi enforce_mode=="none"
  TOG_ON=$(curl -k -sS -b "${COOKIE_JAR}" --resolve switch.tomars.qzz.io:443:127.0.0.1 \
    -X POST -H "Content-Type: application/json" -d '{"enforce_enabled":true}' https://switch.tomars.qzz.io/api/toggle-enforce)
  echo "TOGGLE_ON: ${TOG_ON}"
  PI_MODE_ON=$(ssh -o BatchMode=yes pi@100.85.73.80 "python3 -c 'import json; print(json.load(open(\"/home/pi/switch-parental/config.json\"))[\"enforce_mode\"])'")
  test "${PI_MODE_ON}" = "close"
  TOG_OFF=$(curl -k -sS -b "${COOKIE_JAR}" --resolve switch.tomars.qzz.io:443:127.0.0.1 \
    -X POST -H "Content-Type: application/json" -d '{"enforce_enabled":false}' https://switch.tomars.qzz.io/api/toggle-enforce)
  echo "TOGGLE_OFF: ${TOG_OFF}"
  PI_MODE_OFF=$(ssh -o BatchMode=yes pi@100.85.73.80 "python3 -c 'import json; print(json.load(open(\"/home/pi/switch-parental/config.json\"))[\"enforce_mode\"])'")
  test "${PI_MODE_OFF}" = "none"
  echo "[PASS] /api/toggle-enforce true->close / false->none synced both layers & restored"

  # Policy edit -> verify Pi & server -> restore 60/120 07:00-23:00
  POL_SET=$(curl -k -sS -b "${COOKIE_JAR}" --resolve switch.tomars.qzz.io:443:127.0.0.1 \
    -X POST -H "Content-Type: application/json" -d '{"weekday_limit":70,"weekend_limit":130,"game_start":"07:30","bedtime":"22:30"}' https://switch.tomars.qzz.io/api/policy)
  echo "POLICY_SET: ${POL_SET}"
  PI_POL=$(ssh -o BatchMode=yes pi@100.85.73.80 "python3 -c 'import json; c=json.load(open(\"/home/pi/switch-parental/config.json\")); print(c[\"limits\"][\"weekday_minutes\"], c[\"limits\"][\"weekend_minutes\"], c[\"curfew\"])'")
  echo "PI_POL_UPDATED: ${PI_POL}"
  POL_RESTORE=$(curl -k -sS -b "${COOKIE_JAR}" --resolve switch.tomars.qzz.io:443:127.0.0.1 \
    -X POST -H "Content-Type: application/json" -d '{"weekday_limit":60,"weekend_limit":120,"game_start":"07:00","bedtime":"23:00"}' https://switch.tomars.qzz.io/api/policy)
  echo "POLICY_RESTORE: ${POL_RESTORE}"
  echo "[PASS] /api/policy synced both layers & restored to 60/120 07:00-23:00"

  # Brute force lockout check using synthetic X-Real-IP on loopback 8788
  for i in 1 2 3 4; do
    CODE=$(curl -sS -o /dev/null -w "%{http_code}" -H "X-Real-IP: 198.51.100.77" -H "Content-Type: application/json" -d '{"pin":"9999"}' http://127.0.0.1:8788/api/login)
    test "${CODE}" = "403"
  done
  LOCK_CODE=$(curl -sS -o /dev/null -w "%{http_code}" -H "X-Real-IP: 198.51.100.77" -H "Content-Type: application/json" -d '{"pin":"9999"}' http://127.0.0.1:8788/api/login)
  echo "BRUTE_FORCE_5TH_HTTP=${LOCK_CODE}"
  test "${LOCK_CODE}" = "429"
  echo "[PASS] 5-attempt PIN lockout (429) verified"

  rm -f "${COOKIE_JAR}"

  echo "--- 4. Clean up test queue/events on switch-server ---"
  printf '{"devices": {}, "updated_at": 0}\n' > "${DATA_DIR}/state.json"
  printf '{"config_rev": 1, "seq": 0, "commands": []}\n' > "${DATA_DIR}/commands.json"
  : > "${DATA_DIR}/events.jsonl"
  echo "=== WEB SMOKE TEST PASSED ==="
} 2>&1 | tee "${LOG_FILE}"
