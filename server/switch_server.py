#!/usr/bin/env python3
"""
Switch Parental Control Heartbeat Server (switch_server.py).

Implements the jetskate/NSParentalControl v2.5.0 check-in protocol (TCP line-delimited JSON
with HMAC-SHA256 request/response signatures, monotonic counter replay protection,
per-IP rate limiting, command queue with TTL expiration & idempotent acks, and atomic
state/poller_view persistence).

Zero external dependencies (Python 3 stdlib only).
"""

import argparse
from collections import deque
from contextlib import contextmanager
from datetime import datetime, timedelta
import fcntl
import hashlib
import hmac
import json
import os
import signal
import socketserver
import sys
import threading
import time

APP_VERSION = "v2.7 (2026-11-16 16:58)"

GRANT_SET_POLICY_TTL_S = 86400
LOCK_NOW_TTL_S = 600
STALE_AFTER_S = 180
MAX_LINE_BYTES = 8192

TITLE_NAMES = {
    "01007EF00011E000": "塞尔达传说 旷野之息",
    "0100F2C0115B6000": "塞尔达传说 王国之泪",
    "01006A800016E000": "任天堂明星大乱斗 特别版",
    "0100152000022000": "马力欧卡丁车8 豪华版",
    "0100F8F0000A2000": "集合啦！动物森友会",
    "0100000000010000": "超级马力欧 奥德赛",
    "0100C2500FC20000": "斯普拉遁3",
}


def build_signed_payload(device_id, counter, ts, title_id, used_min_today, acks):
    """Build exact request HMAC string matching C++ heartbeat_protocol::buildSignedPayload."""
    title_rendered = "" if not title_id else str(title_id).upper()
    ack_ids = ",".join(str(a.get("command_id", "")) for a in (acks or []))
    return f"{device_id}.{counter}.{ts}.{title_rendered}.{used_min_today}.{ack_ids}"


def _render_field(value):
    if value is None:
        return ""
    ival = int(value)
    return "" if ival < 0 else str(ival)


def canonical_response_string(device_id, request_counter, server_ts, config_rev, commands):
    """Build exact response HMAC string matching C++ heartbeat_protocol::canonicalResponseString."""
    parts = []
    for cmd in commands or []:
        cid = str(cmd.get("command_id", ""))
        ctype = str(cmd.get("type", ""))
        parts.append(
            f"{cid}|{ctype}|"
            f"{_render_field(cmd.get('minutes'))}|"
            f"{_render_field(cmd.get('weekday_limit'))}|"
            f"{_render_field(cmd.get('weekend_limit'))}|"
            f"{_render_field(cmd.get('game_start'))}|"
            f"{_render_field(cmd.get('bedtime'))}"
        )
    cmds_str = ";".join(parts)
    return f"resp|{device_id}|{request_counter}|{server_ts}|{config_rev}|{cmds_str}"


def format_wire_command(cmd):
    """Format a queued command into compact wire object for C++ hand-rolled JSON parser."""
    ctype = cmd["type"]
    out = {"command_id": cmd["command_id"], "type": ctype}
    if ctype == "grant_minutes":
        out["minutes"] = int(cmd["minutes"])
    elif ctype == "set_policy":
        for field in ("weekday_limit", "weekend_limit", "game_start", "bedtime"):
            val = cmd.get(field)
            if val is not None and int(val) >= 0:
                out[field] = int(val)
    return out


def compute_logical_day(now_ts, reset_hour=4):
    """Return (YYYY-MM-DD, weekday_0_mon_to_6_sun) with reset_hour boundary."""
    dt = datetime.fromtimestamp(now_ts).astimezone()
    if dt.hour < reset_hour:
        dt = dt - timedelta(days=1)
    return dt.strftime("%Y-%m-%d"), dt.weekday()


def atomic_write_json(path, data):
    """Write JSON atomically using temp file + fsync + os.replace."""
    parent = os.path.dirname(os.path.abspath(path))
    os.makedirs(parent, exist_ok=True)
    tmp_path = f"{path}.tmp.{os.getpid()}.{threading.get_ident()}"
    content = json.dumps(data, ensure_ascii=False, indent=2) + "\n"
    with open(tmp_path, "w", encoding="utf-8") as f:
        f.write(content)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp_path, path)


def read_json_safe(path, default):
    if not os.path.exists(path):
        return default
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


class ServerContext:
    def __init__(self, config):
        self.config = config
        self.data_dir = config["data_dir"]
        os.makedirs(self.data_dir, exist_ok=True)

        token_hex = str(config["heartbeat_token"]).strip().lower()
        self.token_bytes = bytes.fromhex(token_hex)
        if len(self.token_bytes) != 32:
            raise ValueError("heartbeat_token must be 32 bytes (64 hex chars)")

        self.rate_limit = int(config.get("rate_limit_per_min", 60))
        self.reset_hour = int(config.get("reset_hour", 4))
        self.default_policy = config.get(
            "default_policy",
            {"weekday_limit": 60, "weekend_limit": 120, "game_start": 420, "bedtime": 1380},
        )

        self.state_path = os.path.join(self.data_dir, "state.json")
        self.poller_view_path = os.path.join(self.data_dir, "poller_view.json")
        self.events_path = os.path.join(self.data_dir, "events.jsonl")
        self.commands_path = os.path.join(self.data_dir, "commands.json")

        self._rate_lock = threading.Lock()
        self._ip_hits = {}
        self._state_thread_lock = threading.Lock()
        self._cmd_thread_lock = threading.Lock()
        self._event_thread_lock = threading.Lock()

        self._ensure_initial_files()

    def _ensure_initial_files(self):
        if not os.path.exists(self.state_path):
            atomic_write_json(self.state_path, {"devices": {}, "updated_at": 0})
        if not os.path.exists(self.commands_path):
            atomic_write_json(self.commands_path, {"config_rev": 1, "seq": 0, "commands": []})
        if not os.path.exists(self.events_path):
            with open(self.events_path, "a", encoding="utf-8"):
                pass

    @contextmanager
    def _locked_file(self, lock_name, thread_lock):
        lock_path = os.path.join(self.data_dir, lock_name)
        with thread_lock:
            with open(lock_path, "a+", encoding="utf-8") as lf:
                fcntl.flock(lf.fileno(), fcntl.LOCK_EX)
                try:
                    yield
                finally:
                    fcntl.flock(lf.fileno(), fcntl.LOCK_UN)

    def check_rate_limit(self, client_ip, now_ts):
        with self._rate_lock:
            q = self._ip_hits.setdefault(client_ip, deque())
            cutoff = now_ts - 60.0
            while q and q[0] <= cutoff:
                q.popleft()
            if len(q) >= self.rate_limit:
                return False
            q.append(now_ts)
            return True

    def log_event(self, event_type, **fields):
        now_ts = int(time.time())
        record = {
            "ts": now_ts,
            "iso": datetime.fromtimestamp(now_ts).astimezone().isoformat(),
            "event": event_type,
        }
        record.update(fields)
        line = json.dumps(record, ensure_ascii=False) + "\n"
        with self._locked_file(".events.lock", self._event_thread_lock):
            with open(self.events_path, "a", encoding="utf-8") as f:
                f.write(line)
                f.flush()
                os.fsync(f.fileno())

    def _command_ttl(self, cmd):
        ctype = cmd.get("type")
        if ctype == "lock_now":
            return LOCK_NOW_TTL_S
        return GRANT_SET_POLICY_TTL_S

    def process_commands_on_checkin(self, device_id, acks, now_ts):
        with self._locked_file(".commands.lock", self._cmd_thread_lock):
            qdata = read_json_safe(self.commands_path, {"config_rev": 1, "seq": 0, "commands": []})
            commands = qdata.get("commands", [])
            changed = False

            # 1. Process incoming acks
            if acks:
                by_id = {c.get("command_id"): c for c in commands}
                for ack in acks:
                    if not isinstance(ack, dict):
                        continue
                    cid = str(ack.get("command_id", ""))
                    if not cid or cid not in by_id:
                        continue
                    cmd = by_id[cid]
                    if cmd.get("status") == "pending":
                        cmd["status"] = "acked"
                        cmd["acked_at"] = now_ts
                        cmd["acked_by"] = device_id
                        cmd["ack_ok"] = bool(ack.get("ok", False))
                        cmd["ack_detail"] = str(ack.get("detail", ""))
                        changed = True
                        self.log_event(
                            "command_ack",
                            device_id=device_id,
                            command_id=cid,
                            type=cmd.get("type"),
                            ok=cmd["ack_ok"],
                            detail=cmd["ack_detail"],
                        )

            # 2. Expire stale pending commands
            pending = []
            for cmd in commands:
                if cmd.get("status") != "pending":
                    continue
                created_at = int(cmd.get("created_at", 0))
                expires_at = cmd.get("expires_at")
                expired = (
                    (expires_at is not None and now_ts > int(expires_at))
                    or (now_ts - created_at > self._command_ttl(cmd))
                )
                if expired:
                    cmd["status"] = "expired"
                    cmd["expired_at"] = now_ts
                    changed = True
                    self.log_event(
                        "command_expired",
                        device_id=device_id,
                        command_id=cmd.get("command_id"),
                        type=cmd.get("type"),
                    )
                else:
                    pending.append(cmd)

            if changed:
                atomic_write_json(self.commands_path, qdata)

            config_rev = int(qdata.get("config_rev", 1))
            return config_rev, pending

    def handle_checkin(self, raw_line, client_ip):
        now_f = time.time()
        now_ts = int(now_f)

        if not self.check_rate_limit(client_ip, now_f):
            self.log_event("rate_limited", ip=client_ip)
            return {"ok": False}

        try:
            req = json.loads(raw_line)
        except Exception:
            self.log_event("auth_failed", ip=client_ip, reason="invalid_json")
            return {"ok": False}

        if not isinstance(req, dict) or req.get("v") != 1:
            self.log_event("auth_failed", ip=client_ip, reason="invalid_version")
            return {"ok": False}

        device_id = req.get("device_id")
        counter = req.get("counter")
        ts = req.get("ts")
        used_min_today = req.get("used_min_today")
        remaining_min = req.get("remaining_min", 0)
        title_id = req.get("title_id")
        user_hash = req.get("user_hash")
        fw = req.get("fw", "unknown")
        ams = req.get("ams", "unknown")
        flags = req.get("flags") or {}
        last_offline_s = req.get("last_offline_s", 0)
        acks = req.get("acks") or []
        auth = req.get("auth")

        if (
            not isinstance(device_id, str)
            or not device_id
            or isinstance(counter, bool)
            or not isinstance(counter, int)
            or counter < 1
            or isinstance(ts, bool)
            or not isinstance(ts, int)
            or isinstance(used_min_today, bool)
            or not isinstance(used_min_today, int)
            or used_min_today < 0
            or isinstance(remaining_min, bool)
            or not isinstance(remaining_min, int)
            or not isinstance(flags, dict)
            or isinstance(last_offline_s, bool)
            or not isinstance(last_offline_s, int)
            or not isinstance(acks, list)
            or not isinstance(auth, str)
            or len(auth) != 64
        ):
            self.log_event("auth_failed", ip=client_ip, device_id=str(device_id or ""), reason="invalid_schema")
            return {"ok": False}

        title_norm = str(title_id).upper() if title_id else None
        payload_str = build_signed_payload(device_id, counter, ts, title_norm, used_min_today, acks)
        expected_mac = hmac.new(self.token_bytes, payload_str.encode("utf-8"), hashlib.sha256).hexdigest()

        if not hmac.compare_digest(expected_mac, auth.lower()):
            self.log_event("auth_failed", ip=client_ip, device_id=device_id, counter=counter, reason="bad_hmac")
            return {"ok": False}

        # State validation (replay protection) and update
        with self._locked_file(".state.lock", self._state_thread_lock):
            state = read_json_safe(self.state_path, {"devices": {}, "updated_at": 0})
            devices = state.setdefault("devices", {})
            prev = devices.get(device_id)

            if prev is not None and counter <= int(prev.get("last_counter", 0)):
                self.log_event(
                    "replay_rejected",
                    ip=client_ip,
                    device_id=device_id,
                    counter=counter,
                    last_counter=int(prev.get("last_counter", 0)),
                )
                return {"ok": False}

            # Authenticated & non-replay: now safe to process acks and read pending commands
            config_rev, pending_cmds = self.process_commands_on_checkin(device_id, acks, now_ts)

            norm_flags = {
                "blocked": bool(flags.get("blocked", False)),
                "screen_off_by_hb": bool(flags.get("screen_off_by_hb", False)),
                "curfew": bool(flags.get("curfew", False)),
            }

            was_offline = (
                prev is None
                or (now_ts - int(prev.get("last_seen", 0)) > STALE_AFTER_S)
                or bool(prev.get("flags", {}).get("screen_off_by_hb", False))
            )
            if was_offline and not norm_flags["screen_off_by_hb"]:
                self.log_event(
                    "device_online",
                    device_id=device_id,
                    counter=counter,
                    fw=str(fw),
                    ams=str(ams),
                )

            if norm_flags["screen_off_by_hb"] or last_offline_s > 0:
                self.log_event(
                    "deadman_screen_off",
                    device_id=device_id,
                    counter=counter,
                    screen_off_by_hb=norm_flags["screen_off_by_hb"],
                    last_offline_s=last_offline_s,
                )

            day_str, weekday = compute_logical_day(now_ts, self.reset_hour)
            if used_min_today > 0 or remaining_min > 0:
                limit_min = used_min_today + max(0, remaining_min)
            else:
                limit_min = int(
                    self.default_policy["weekend_limit"]
                    if weekday >= 5
                    else self.default_policy["weekday_limit"]
                )

            game_name = TITLE_NAMES.get(title_norm, title_norm) if title_norm else "空闲"

            device_rec = {
                "device_id": device_id,
                "last_counter": counter,
                "last_ts": ts,
                "last_seen": now_ts,
                "day": day_str,
                "fw": str(fw),
                "ams": str(ams),
                "title_id": title_norm,
                "game": game_name,
                "user_hash": user_hash,
                "used_min_today": used_min_today,
                "remaining_min": remaining_min,
                "limit_min": limit_min,
                "flags": norm_flags,
                "last_offline_s": last_offline_s,
                "online": True,
                "ip": client_ip,
            }
            devices[device_id] = device_rec
            state["updated_at"] = now_ts
            atomic_write_json(self.state_path, state)

            poller_view = {
                "day": day_str,
                "device_id": device_id,
                "used_min": used_min_today,
                "limit_min": limit_min,
                "remaining_min": remaining_min,
                "game": game_name,
                "title_id": title_norm,
                "online": True,
                "stale": False,
                "last_seen": now_ts,
                "fw": str(fw),
                "ams": str(ams),
                "flags": norm_flags,
                "last_offline_s": last_offline_s,
                "日期": day_str,
                "在线": True,
                "正在玩": game_name,
                "今日额度_分钟": limit_min,
                "已用_分钟": used_min_today,
                "剩余_分钟": remaining_min,
                "宵禁": "宵禁中" if norm_flags["curfew"] else "无",
            }
            atomic_write_json(self.poller_view_path, poller_view)

        wire_cmds = [format_wire_command(c) for c in pending_cmds]
        canonical = canonical_response_string(device_id, counter, now_ts, config_rev, pending_cmds)
        resp_auth = hmac.new(self.token_bytes, canonical.encode("utf-8"), hashlib.sha256).hexdigest()

        return {
            "ok": True,
            "server_ts": now_ts,
            "config_rev": config_rev,
            "commands": wire_cmds,
            "auth": resp_auth,
        }


class CheckinTCPHandler(socketserver.StreamRequestHandler):
    def handle(self):
        self.connection.settimeout(5.0)
        try:
            raw = self.rfile.readline(MAX_LINE_BYTES + 1)
            if not raw or len(raw) > MAX_LINE_BYTES:
                resp = {"ok": False}
            else:
                line = raw.decode("utf-8", errors="strict").strip()
                resp = self.server.ctx.handle_checkin(line, self.client_address[0])
        except Exception:
            resp = {"ok": False}

        out = json.dumps(resp, ensure_ascii=False, separators=(",", ":")) + "\n"
        try:
            self.wfile.write(out.encode("utf-8"))
            self.wfile.flush()
        except OSError:
            pass


class HeartbeatTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, server_address, handler_cls, ctx):
        self.ctx = ctx
        super().__init__(server_address, handler_cls)


def load_config(config_path):
    with open(config_path, "r", encoding="utf-8") as f:
        return json.load(f)


def main():
    parser = argparse.ArgumentParser(description="Switch Parental Control Heartbeat Server")
    parser.add_argument(
        "--config",
        default=os.environ.get("SWITCH_SERVER_CONFIG", "/home/ai-agent/switch-server/config.json"),
        help="Path to config.json",
    )
    parser.add_argument("--host", default=None, help="Override listen host")
    parser.add_argument("--port", type=int, default=None, help="Override listen port")
    parser.add_argument("--data-dir", default=None, help="Override data directory")
    parser.add_argument("--web-port", type=int, default=None, help="Override web admin port")
    parser.add_argument("--no-web", action="store_true", help="Disable web admin HTTP server")
    args = parser.parse_args()

    cfg = load_config(args.config)
    if args.host is not None:
        cfg["listen_host"] = args.host
    if args.port is not None:
        cfg["listen_port"] = args.port
    if args.data_dir is not None:
        cfg["data_dir"] = args.data_dir
    if args.web_port is not None:
        cfg["web_listen_port"] = args.web_port

    host = cfg.get("listen_host", "0.0.0.0")
    port = int(cfg.get("listen_port", 39107))

    ctx = ServerContext(cfg)
    srv = HeartbeatTCPServer((host, port), CheckinTCPHandler, ctx)
    httpd = None
    if not args.no_web:
        from web_admin import start_web_admin_server
        httpd = start_web_admin_server(ctx, cfg, args.config, APP_VERSION)

    def _shutdown(signum, frame):
        threading.Thread(target=srv.shutdown, daemon=True).start()
        if httpd is not None:
            threading.Thread(target=httpd.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    print(f"[switch-server] {APP_VERSION} listening on {host}:{port}, data_dir={ctx.data_dir}", flush=True)
    try:
        srv.serve_forever(poll_interval=0.5)
    finally:
        srv.server_close()
        if httpd is not None:
            httpd.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
