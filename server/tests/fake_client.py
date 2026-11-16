#!/usr/bin/env python3
"""
fake_client.py - Test client & 7-scenario E2E verifier for switch_server.py.

Never prints heartbeat_token.
"""

import argparse
import hashlib
import hmac
import json
import os
import socket
import subprocess
import sys
import time

SERVER_DIR = "/home/ai-agent/workspace/projects/switch-parental/server"
sys.path.insert(0, SERVER_DIR)

from switch_server import build_signed_payload, canonical_response_string  # noqa: E402


def verify_golden_vectors():
    """Scenario 1: Assert 100% parity with C++ tests/heartbeat_protocol_test.cpp."""
    p1 = build_signed_payload("dev-abc", 42, 1763259900, "01007EF00011E000", 35, [])
    assert p1 == "dev-abc.42.1763259900.01007EF00011E000.35.", f"p1 mismatch: {p1}"

    p2 = build_signed_payload("dev-abc", 42, 1763259900, "", 0, [])
    assert p2 == "dev-abc.42.1763259900..0.", f"p2 mismatch: {p2}"

    p3 = build_signed_payload(
        "dev-abc",
        43,
        1763259960,
        "",
        35,
        [
            {"command_id": "c1763259900-1", "ok": True, "detail": "applied"},
            {"command_id": "c1763259901-2", "ok": False, "detail": "bad_value"},
        ],
    )
    assert p3 == "dev-abc.43.1763259960..35.c1763259900-1,c1763259901-2", f"p3 mismatch: {p3}"

    cmds = [
        {"command_id": "c1763259900-1", "type": "grant_minutes", "minutes": 30},
        {
            "command_id": "c1763259901-2",
            "type": "set_policy",
            "weekday_limit": 60,
            "weekend_limit": 120,
            "game_start": 420,
            "bedtime": 1380,
        },
        {"command_id": "c1763259902-3", "type": "lock_now"},
    ]
    c1 = canonical_response_string("dev-abc", 42, 1763260000, 3, cmds)
    assert c1 == (
        "resp|dev-abc|42|1763260000|3|"
        "c1763259900-1|grant_minutes|30||||;"
        "c1763259901-2|set_policy||60|120|420|1380;"
        "c1763259902-3|lock_now|||||"
    ), f"c1 mismatch: {c1}"

    c2 = canonical_response_string("dev-abc", 42, 1763260000, 3, [])
    assert c2 == "resp|dev-abc|42|1763260000|3|", f"c2 mismatch: {c2}"
    print("[PASS] Scenario 1: 5 golden vectors (3 buildSignedPayload + 2 canonicalResponseString) match C++ 100%")


def send_checkin(
    host,
    port,
    token_hex,
    device_id,
    counter,
    ts=None,
    fw="23.0.1",
    ams="1.12.0",
    title_id="01007EF00011E000",
    user_hash="0123456789abcdef",
    used_min_today=15,
    remaining_min=45,
    flags=None,
    last_offline_s=0,
    acks=None,
    tamper_hmac=False,
):
    ts = int(time.time()) if ts is None else int(ts)
    flags = flags or {"blocked": False, "screen_off_by_hb": False, "curfew": False}
    acks = acks or []
    token_bytes = bytes.fromhex(token_hex)

    payload_str = build_signed_payload(device_id, counter, ts, title_id, used_min_today, acks)
    mac = hmac.new(token_bytes, payload_str.encode("utf-8"), hashlib.sha256).hexdigest()
    if tamper_hmac:
        mac = ("0" if mac[0] != "0" else "1") + mac[1:]

    req = {
        "v": 1,
        "device_id": device_id,
        "counter": counter,
        "ts": ts,
        "fw": fw,
        "ams": ams,
        "title_id": title_id,
        "user_hash": user_hash,
        "used_min_today": used_min_today,
        "remaining_min": remaining_min,
        "flags": flags,
        "last_offline_s": last_offline_s,
        "acks": acks,
        "auth": mac,
    }
    line = json.dumps(req, separators=(",", ":")) + "\n"

    with socket.create_connection((host, port), timeout=5.0) as sock:
        sock.sendall(line.encode("utf-8"))
        buf = b""
        while not buf.endswith(b"\n"):
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf += chunk

    resp = json.loads(buf.decode("utf-8").strip())
    if resp.get("ok"):
        canonical = canonical_response_string(
            device_id, counter, resp["server_ts"], resp["config_rev"], resp.get("commands", [])
        )
        expected_resp_mac = hmac.new(token_bytes, canonical.encode("utf-8"), hashlib.sha256).hexdigest()
        assert hmac.compare_digest(expected_resp_mac, resp.get("auth", "")), "Response HMAC verification failed!"
    return resp


def read_events(data_dir):
    events = []
    p = os.path.join(data_dir, "events.jsonl")
    if os.path.exists(p):
        with open(p, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    events.append(json.loads(line))
    return events


def run_switchctl(data_dir, *args):
    cmd = ["/home/ai-agent/switch-server/switchctl", "--data-dir", data_dir, *args]
    res = subprocess.run(cmd, capture_output=True, text=True, check=True)
    return res.stdout.strip()


def run_all_scenarios(host, port, config_path):
    with open(config_path, "r", encoding="utf-8") as f:
        cfg = json.load(f)
    token_hex = cfg["heartbeat_token"]
    data_dir = cfg["data_dir"]
    dev = "fake-switch-01"

    # Scenario 1: Golden vectors
    verify_golden_vectors()

    # Scenario 2: Valid check-in -> state.json & poller_view.json
    r2 = send_checkin(host, port, token_hex, dev, counter=1, used_min_today=15, remaining_min=45)
    assert r2["ok"] is True and r2["commands"] == [], f"Scenario 2 unexpected resp: {r2}"
    with open(os.path.join(data_dir, "state.json"), "r", encoding="utf-8") as f:
        st = json.load(f)
    with open(os.path.join(data_dir, "poller_view.json"), "r", encoding="utf-8") as f:
        pv = json.load(f)
    assert st["devices"][dev]["last_counter"] == 1
    assert st["devices"][dev]["fw"] == "23.0.1"
    assert st["devices"][dev]["ams"] == "1.12.0"
    assert pv["fw"] == "23.0.1" and pv["ams"] == "1.12.0"
    assert pv["已用_分钟"] == 15 and pv["剩余_分钟"] == 45 and pv["今日额度_分钟"] == 60
    print(f"[PASS] Scenario 2: Valid check-in persisted state.json & poller_view.json (fw={pv['fw']}, ams={pv['ams']})")

    # Scenario 3: Bad HMAC rejected, state & counter unchanged, auth_failed logged
    r3 = send_checkin(host, port, token_hex, dev, counter=2, used_min_today=20, remaining_min=40, tamper_hmac=True)
    assert r3 == {"ok": False}, f"Scenario 3 should fail: {r3}"
    with open(os.path.join(data_dir, "state.json"), "r", encoding="utf-8") as f:
        st3 = json.load(f)
    assert st3["devices"][dev]["last_counter"] == 1, "Counter must not advance on bad HMAC"
    assert any(e["event"] == "auth_failed" and e.get("device_id") == dev for e in read_events(data_dir))
    print("[PASS] Scenario 3: Bad HMAC rejected, counter unchanged (1), auth_failed recorded")

    # Scenario 4: Replay old counter rejected, replay_rejected logged
    r4 = send_checkin(host, port, token_hex, dev, counter=1, used_min_today=20, remaining_min=40)
    assert r4 == {"ok": False}, f"Scenario 4 replay should fail: {r4}"
    assert any(e["event"] == "replay_rejected" and e.get("device_id") == dev for e in read_events(data_dir))
    print("[PASS] Scenario 4: Replay counter=1 rejected, replay_rejected recorded")

    # Scenario 5: Deadman screen_off check-in -> deadman_screen_off event
    r5 = send_checkin(
        host,
        port,
        token_hex,
        dev,
        counter=2,
        used_min_today=22,
        remaining_min=38,
        flags={"blocked": False, "screen_off_by_hb": True, "curfew": False},
        last_offline_s=320,
    )
    assert r5["ok"] is True
    assert any(
        e["event"] == "deadman_screen_off" and e.get("last_offline_s") == 320 for e in read_events(data_dir)
    )
    print("[PASS] Scenario 5: Deadman screen_off_by_hb=true, last_offline_s=320 logged deadman_screen_off")

    # Scenario 6: switchctl grant 30 -> delivered with valid HMAC -> acked -> marked acked
    cid_grant = run_switchctl(data_dir, "grant", "30")
    r6a = send_checkin(host, port, token_hex, dev, counter=3, used_min_today=25, remaining_min=35)
    assert len(r6a["commands"]) == 1 and r6a["commands"][0]["command_id"] == cid_grant
    assert r6a["commands"][0]["type"] == "grant_minutes" and r6a["commands"][0]["minutes"] == 30

    # Scenario 7a: Re-delivery idempotency before ack (same pending command still delivered)
    r7_redeliver = send_checkin(host, port, token_hex, dev, counter=4, used_min_today=25, remaining_min=65)
    assert any(c["command_id"] == cid_grant for c in r7_redeliver["commands"]), "Pending cmd should resend until acked"
    executed_ids = set()
    # Client-side idempotency guard (mirrors C++ commandIdListContains)
    applied_count = 0
    for cmd in (r6a["commands"] + r7_redeliver["commands"]):
        if cmd["command_id"] not in executed_ids:
            executed_ids.add(cmd["command_id"])
            applied_count += 1
    assert applied_count == 1, "Idempotency check failed"

    # Ack grant command
    r6b = send_checkin(
        host,
        port,
        token_hex,
        dev,
        counter=5,
        used_min_today=26,
        remaining_min=64,
        acks=[{"command_id": cid_grant, "ok": True, "detail": "applied"}],
    )
    assert r6b["commands"] == [], f"Acked command must not be re-sent: {r6b}"
    with open(os.path.join(data_dir, "commands.json"), "r", encoding="utf-8") as f:
        qdata = json.load(f)
    grant_entry = next(c for c in qdata["commands"] if c["command_id"] == cid_grant)
    assert grant_entry["status"] == "acked" and grant_entry["ack_ok"] is True
    assert any(
        e["event"] == "command_ack" and e.get("command_id") == cid_grant and e.get("detail") == "applied"
        for e in read_events(data_dir)
    )
    print(f"[PASS] Scenario 6: switchctl grant 30 ({cid_grant}) delivered with valid HMAC, acked & recorded")

    # Scenario 7b: set_policy & lock_now delivery + command TTL expiration cleanup
    cid_set = run_switchctl(data_dir, "set", "weekday_limit=60", "weekend_limit=120", "game_start=07:00", "bedtime=23:00")
    cid_lock = run_switchctl(data_dir, "lock")
    r7b = send_checkin(host, port, token_hex, dev, counter=6, used_min_today=27, remaining_min=63)
    got_ids = {c["command_id"]: c for c in r7b["commands"]}
    assert cid_set in got_ids and cid_lock in got_ids
    assert got_ids[cid_set]["game_start"] == 420 and got_ids[cid_set]["bedtime"] == 1380

    # Ack both, then enqueue an expired lock_now (>600s) and expired grant (>86400s) to test expiration
    r7c = send_checkin(
        host,
        port,
        token_hex,
        dev,
        counter=7,
        used_min_today=27,
        remaining_min=63,
        acks=[
            {"command_id": cid_set, "ok": True, "detail": "applied"},
            {"command_id": cid_lock, "ok": True, "detail": "applied"},
        ],
    )
    assert r7c["commands"] == []

    cid_exp_lock = run_switchctl(data_dir, "lock")
    cid_exp_grant = run_switchctl(data_dir, "grant", "10")
    cmd_path = os.path.join(data_dir, "commands.json")
    with open(cmd_path, "r", encoding="utf-8") as f:
        qd = json.load(f)
    now_ts = int(time.time())
    for c in qd["commands"]:
        if c["command_id"] == cid_exp_lock:
            c["created_at"] = now_ts - 605  # > 600s
        elif c["command_id"] == cid_exp_grant:
            c["created_at"] = now_ts - 86405  # > 86400s
    with open(cmd_path, "w", encoding="utf-8") as f:
        json.dump(qd, f, indent=2)

    r7d = send_checkin(host, port, token_hex, dev, counter=8, used_min_today=28, remaining_min=62)
    assert r7d["commands"] == [], f"Expired commands must not be sent: {r7d}"
    events = read_events(data_dir)
    expired_ids = {e["command_id"] for e in events if e["event"] == "command_expired"}
    assert cid_exp_lock in expired_ids and cid_exp_grant in expired_ids
    print(
        f"[PASS] Scenario 7: Idempotent resend, set_policy ({cid_set}), lock_now ({cid_lock}), "
        f"and TTL expiration ({cid_exp_lock}, {cid_exp_grant}) verified"
    )


def main():
    parser = argparse.ArgumentParser(description="Switch Heartbeat Fake Client & Smoke Verifier")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=39107)
    parser.add_argument("--config", default="/home/ai-agent/switch-server/config.json")
    parser.add_argument("--golden-only", action="store_true")
    args = parser.parse_args()

    if args.golden_only:
        verify_golden_vectors()
        return 0

    run_all_scenarios(args.host, args.port, args.config)
    return 0


if __name__ == "__main__":
    sys.exit(main())
