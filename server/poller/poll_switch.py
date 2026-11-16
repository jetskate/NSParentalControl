#!/usr/bin/env python3
"""
poll_switch.py - Dual-source Switch parental control status poller.

Supports:
  --source pi       Read http://100.85.73.80:8787/status (read-only)
  --source server   Read /home/ai-agent/switch-server/data/poller_view.json
  --seed            Initialize watermarks from current status without sending alerts
  --dry-run         Evaluate & log decisions without calling Bark API
"""

import argparse
from datetime import datetime, timedelta
import json
import os
import sys
import time
import urllib.request

DEFAULT_PI_URL = "http://100.85.73.80:8787/status"
DEFAULT_SERVER_VIEW = "/home/ai-agent/switch-server/data/poller_view.json"
DEFAULT_VAULT_PATH = "/home/ai-agent/workspace/projects/switch-parental/vault/credentials.vne"
DEFAULT_STATE_PATH = "/home/ai-agent/workspace/projects/switch-parental/poller/poller_state.json"
BARK_URL = "https://bark.tomars.qzz.io/push"


def logical_today(reset_hour=4):
    now = datetime.now().astimezone()
    if now.hour < reset_hour:
        now = now - timedelta(days=1)
    return now.strftime("%Y-%m-%d")


def atomic_write_json(path, data):
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    tmp_path = f"{path}.tmp.{os.getpid()}"
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
        f.write("\n")
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp_path, path)


def load_poller_state(path):
    if not os.path.exists(path):
        return {
            "day": logical_today(),
            "consecutive_failures": 0,
            "error_notified": False,
            "notified": {"warn": False, "exhausted": False, "curfew": False, "deadman": False},
        }
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def fetch_status(source, pi_url, server_view_path):
    if source == "pi":
        req = urllib.request.Request(pi_url, headers={"User-Agent": "SwitchPoller/1.0"})
        with urllib.request.urlopen(req, timeout=8) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        return data

    if not os.path.exists(server_view_path):
        raise FileNotFoundError(f"poller_view.json not found: {server_view_path}")
    with open(server_view_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if not data:
        raise ValueError("poller_view.json is empty")
    return data


def normalize_status(raw):
    day = raw.get("day") or raw.get("日期") or logical_today()
    used_min = int(raw.get("used_min", raw.get("已用_分钟", 0)))
    limit_min = int(raw.get("limit_min", raw.get("今日额度_分钟", 0)))
    remaining_min = int(raw.get("remaining_min", raw.get("剩余_分钟", 0)))
    game = raw.get("game") or raw.get("正在玩") or "空闲"
    flags = raw.get("flags") or {}
    curfew_str = raw.get("宵禁", "无")
    curfew = bool(flags.get("curfew", False)) or (curfew_str not in ("无", "", None))
    deadman = bool(flags.get("screen_off_by_hb", False))
    last_seen = raw.get("last_seen")
    stale = bool(raw.get("stale", False))
    if last_seen is not None:
        stale = (int(time.time()) - int(last_seen)) > 180
    online = bool(raw.get("online", raw.get("在线", False))) and not stale

    return {
        "day": str(day),
        "used_min": used_min,
        "limit_min": limit_min,
        "remaining_min": remaining_min,
        "game": str(game),
        "online": online,
        "stale": stale,
        "curfew": curfew,
        "curfew_str": str(curfew_str),
        "deadman": deadman,
        "last_offline_s": int(raw.get("last_offline_s", 0)),
    }


def load_bark_key(vault_path):
    with open(vault_path, "r", encoding="utf-8") as f:
        vault = json.load(f)
    key = vault.get("bark_device_key", "").strip()
    if not key:
        raise ValueError("bark_device_key missing in vault")
    return key


def send_bark(device_key, title, body, dry_run=False):
    if dry_run:
        print(f"[DRY-RUN][BARK] title={title!r} body={body!r} sound=sherwoodforest group=Alerts")
        return True

    payload = {
        "device_key": device_key,
        "title": title,
        "body": body,
        "sound": "sherwoodforest",
        "group": "Alerts",
    }
    req = urllib.request.Request(
        BARK_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json; charset=utf-8", "User-Agent": "SwitchPoller/1.0"},
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        res = json.loads(resp.read().decode("utf-8"))
        return res.get("code") == 200


def evaluate_events(norm):
    events = []
    rem = norm["remaining_min"]
    if 0 < rem <= 10:
        events.append((
            "warn",
            "Switch 游戏时长即将耗尽",
            f"今日({norm['day']})已用 {norm['used_min']} 分钟，剩余 {rem} 分钟，正在玩：{norm['game']}",
        ))
    if rem <= 0:
        events.append((
            "exhausted",
            "Switch 今日游戏时长已耗尽",
            f"今日({norm['day']})额度 {norm['limit_min']} 分钟已用完（已用 {norm['used_min']} 分钟），正在玩：{norm['game']}",
        ))
    if norm["curfew"]:
        events.append((
            "curfew",
            "Switch 宵禁时段提醒",
            f"当前处于宵禁时段（{norm['curfew_str']}），今日已用 {norm['used_min']} 分钟，正在玩：{norm['game']}",
        ))
    if norm["deadman"]:
        events.append((
            "deadman",
            "Switch 断联死手开关已触发",
            f"设备断联超时触发息屏/管控（last_offline_s={norm['last_offline_s']}s），今日已用 {norm['used_min']} 分钟",
        ))
    return events


def main():
    parser = argparse.ArgumentParser(description="Switch Parental Control Dual-Source Poller")
    parser.add_argument("--source", choices=("pi", "server"), default="pi")
    parser.add_argument("--pi-url", default=DEFAULT_PI_URL)
    parser.add_argument("--server-view", default=DEFAULT_SERVER_VIEW)
    parser.add_argument("--vault", default=DEFAULT_VAULT_PATH)
    parser.add_argument("--state-file", default=DEFAULT_STATE_PATH)
    parser.add_argument("--seed", action="store_true", help="Initialize today's watermarks without notifying")
    parser.add_argument("--dry-run", action="store_true", help="Log alerts without sending Bark requests")
    args = parser.parse_args()

    state = load_poller_state(args.state_file)
    now_iso = datetime.now().astimezone().isoformat(timespec="seconds")

    try:
        raw = fetch_status(args.source, args.pi_url, args.server_view)
        norm = normalize_status(raw)
    except Exception as exc:
        state["consecutive_failures"] = int(state.get("consecutive_failures", 0)) + 1
        print(f"[{now_iso}][{args.source}] fetch failed ({state['consecutive_failures']}): {exc}")
        if state["consecutive_failures"] >= 6 and not state.get("error_notified", False):
            title = "Switch 监控源连续失联告警"
            body = f"数据源 {args.source} 连续失败 {state['consecutive_failures']} 次：{exc}"
            if args.seed:
                print(f"[SEED] suppressing ERROR alert")
            else:
                key = "" if args.dry_run else load_bark_key(args.vault)
                send_bark(key, title, body, dry_run=args.dry_run)
                state["error_notified"] = True
        atomic_write_json(args.state_file, state)
        return 1

    state["consecutive_failures"] = 0
    state["error_notified"] = False

    if state.get("day") != norm["day"]:
        state["day"] = norm["day"]
        state["notified"] = {"warn": False, "exhausted": False, "curfew": False, "deadman": False}

    notified = state.setdefault(
        "notified", {"warn": False, "exhausted": False, "curfew": False, "deadman": False}
    )

    events = evaluate_events(norm)
    triggered = []
    for ev_key, title, body in events:
        if not notified.get(ev_key, False):
            triggered.append((ev_key, title, body))

    if args.seed:
        for ev_key, _, _ in triggered:
            notified[ev_key] = True
        state["last_poll"] = now_iso
        state["last_source"] = args.source
        state["last_snapshot"] = norm
        atomic_write_json(args.state_file, state)
        print(
            f"[{now_iso}][SEED][{args.source}] day={norm['day']} used={norm['used_min']}/{norm['limit_min']} "
            f"rem={norm['remaining_min']} game={norm['game']} seeded_flags={[k for k,_,_ in triggered]}"
        )
        return 0

    key = "" if args.dry_run or not triggered else load_bark_key(args.vault)
    sent_keys = []
    for ev_key, title, body in triggered:
        ok = send_bark(key, title, body, dry_run=args.dry_run)
        if ok:
            notified[ev_key] = True
            sent_keys.append(ev_key)

    state["last_poll"] = now_iso
    state["last_source"] = args.source
    state["last_snapshot"] = norm
    atomic_write_json(args.state_file, state)

    print(
        f"[{now_iso}][{args.source}] day={norm['day']} online={norm['online']} stale={norm['stale']} "
        f"used={norm['used_min']}/{norm['limit_min']} rem={norm['remaining_min']} "
        f"curfew={norm['curfew_str']} game={norm['game']} alerts={sent_keys}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
