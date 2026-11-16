#!/usr/bin/env python3
"""
make_seed.py - Generate & verify NSParentalControl settings.bin (NSPS v1 binary format).

Reads heartbeat_token from /home/ai-agent/switch-server/config.json (never printed),
optionally merges an existing settings.bin (preserving admin_pin and existing user configs),
writes updated settings.bin with chmod 600, and performs a lossless roundtrip read check.
"""

import argparse
import json
import os
import struct
import sys

SETTINGS_MAGIC = 0x4E535053  # "NSPS"
SETTINGS_VERSION = 1

TYPE_INTEGER = 0
TYPE_DOUBLE = 1
TYPE_STRING = 2

DEFAULT_CONFIG_PATH = "/home/ai-agent/switch-server/config.json"
DEFAULT_OUT_PATH = "/home/ai-agent/workspace/projects/switch-parental/dist/sdcard/config/parental_control/settings.bin"

REDACTED_KEYS = {"heartbeat_token", "admin_pin"}


def read_settings_bin(path):
    """Deserialize NSPS v1 settings.bin into {key: (type, value, encrypted)}."""
    with open(path, "rb") as f:
        data = f.read()

    if len(data) < 16:
        raise ValueError(f"settings.bin too small ({len(data)} bytes)")

    magic, version, entry_count = struct.unpack_from("<IIQ", data, 0)
    if magic != SETTINGS_MAGIC:
        raise ValueError(f"invalid magic: 0x{magic:08X} (expected 0x{SETTINGS_MAGIC:08X})")
    if version != SETTINGS_VERSION:
        raise ValueError(f"unsupported version: {version} (expected {SETTINGS_VERSION})")

    offset = 16
    entries = {}
    for idx in range(entry_count):
        if offset + 8 > len(data):
            raise ValueError(f"entry {idx} header out of bounds")
        stype, key_len = struct.unpack_from("<II", data, offset)
        offset += 8
        if offset + key_len > len(data):
            raise ValueError(f"entry {idx} key out of bounds")
        key = data[offset : offset + key_len].decode("utf-8")
        offset += key_len

        if stype == TYPE_INTEGER:
            if offset + 8 > len(data):
                raise ValueError(f"entry {key} int value out of bounds")
            (val,) = struct.unpack_from("<Q", data, offset)
            offset += 8
            entries[key] = (TYPE_INTEGER, val, False)
        elif stype == TYPE_DOUBLE:
            if offset + 8 > len(data):
                raise ValueError(f"entry {key} double value out of bounds")
            (val,) = struct.unpack_from("<d", data, offset)
            offset += 8
            entries[key] = (TYPE_DOUBLE, val, False)
        elif stype == TYPE_STRING:
            if offset + 4 > len(data):
                raise ValueError(f"entry {key} str length out of bounds")
            (val_len,) = struct.unpack_from("<I", data, offset)
            offset += 4
            if offset + val_len + 1 > len(data):
                raise ValueError(f"entry {key} str value out of bounds")
            val = data[offset : offset + val_len].decode("utf-8")
            offset += val_len
            (encrypted_flag,) = struct.unpack_from("<B", data, offset)
            offset += 1
            entries[key] = (TYPE_STRING, val, encrypted_flag != 0)
        else:
            raise ValueError(f"unknown setting type {stype} for key {key}")

    if offset != len(data):
        raise ValueError(f"trailing bytes in settings.bin: parsed {offset}, total {len(data)}")

    return entries


def write_settings_bin(path, entries):
    """Serialize {key: (type, value, encrypted)} to NSPS v1 binary file (sorted by key)."""
    sorted_keys = sorted(entries.keys())
    buf = bytearray(struct.pack("<IIQ", SETTINGS_MAGIC, SETTINGS_VERSION, len(sorted_keys)))

    for key in sorted_keys:
        stype, val, encrypted = entries[key]
        key_bytes = key.encode("utf-8")
        buf += struct.pack("<II", stype, len(key_bytes)) + key_bytes
        if stype == TYPE_INTEGER:
            buf += struct.pack("<Q", int(val))
        elif stype == TYPE_DOUBLE:
            buf += struct.pack("<d", float(val))
        elif stype == TYPE_STRING:
            val_bytes = str(val).encode("utf-8")
            buf += struct.pack("<I", len(val_bytes)) + val_bytes + struct.pack("<B", 1 if encrypted else 0)
        else:
            raise ValueError(f"unsupported setting type {stype} for {key}")

    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    tmp_path = f"{path}.tmp.{os.getpid()}"
    with open(tmp_path, "wb") as f:
        f.write(buf)
        f.flush()
        os.fsync(f.fileno())
    os.chmod(tmp_path, 0o600)
    os.replace(tmp_path, path)
    os.chmod(path, 0o600)
    return len(buf)


def parse_user_map(raw):
    result = {}
    if not raw:
        return result
    for part in raw.split(";"):
        part = part.strip()
        if not part or "=" not in part:
            continue
        uid, val = part.split("=", 1)
        result[uid.strip()] = int(val.strip())
    return result


def serialize_user_map(user_map):
    return ";".join(f"{uid}={int(user_map[uid])}" for uid in sorted(user_map.keys()))


def update_per_user_setting(entries, key, uid, value):
    existing = ""
    if key in entries and entries[key][0] == TYPE_STRING:
        existing = entries[key][1]
    umap = parse_user_map(existing)
    umap[uid] = int(value)
    entries[key] = (TYPE_STRING, serialize_user_map(umap), False)


def verify_roundtrip(path, expected_entries):
    parsed = read_settings_bin(path)
    if set(parsed.keys()) != set(expected_entries.keys()):
        raise AssertionError(
            f"key mismatch after roundtrip: {set(parsed.keys())} != {set(expected_entries.keys())}"
        )
    for k, exp in expected_entries.items():
        got = parsed[k]
        if got != exp:
            if k in REDACTED_KEYS:
                raise AssertionError(f"roundtrip mismatch on redacted key {k} (len {len(str(got[1]))} vs {len(str(exp[1]))})")
            raise AssertionError(f"roundtrip mismatch on {k}: {got} != {exp}")
    return parsed


def main():
    parser = argparse.ArgumentParser(description="Generate NSParentalControl settings.bin seed")
    parser.add_argument("--config", default=DEFAULT_CONFIG_PATH, help="Server config.json with heartbeat_token")
    parser.add_argument("--in", dest="in_path", default=None, help="Existing settings.bin to merge/preserve")
    parser.add_argument("--out", default=DEFAULT_OUT_PATH, help="Output settings.bin path")
    parser.add_argument("--host", default="161.118.161.194", help="Heartbeat server host")
    parser.add_argument("--port", type=int, default=39107, help="Heartbeat server port")
    parser.add_argument("--uid", action="append", default=[], help="Switch user UID (e.g. 123456:7890) to preset limits")
    parser.add_argument("--weekday-limit", type=int, default=60)
    parser.add_argument("--weekend-limit", type=int, default=120)
    parser.add_argument("--game-start", type=int, default=420)
    parser.add_argument("--bedtime", type=int, default=1380)
    parser.add_argument("--verify-only", metavar="FILE", help="Read and print non-sensitive keys from FILE")
    args = parser.parse_args()

    if args.verify_only:
        parsed = read_settings_bin(args.verify_only)
        print(f"Verified NSPS v1: {args.verify_only} ({len(parsed)} entries)")
        for k in sorted(parsed.keys()):
            stype, val, enc = parsed[k]
            display = "<REDACTED>" if k in REDACTED_KEYS else val
            print(f"  {k} [type={stype}, enc={enc}]: {display}")
        return 0

    with open(args.config, "r", encoding="utf-8") as f:
        cfg = json.load(f)
    token = str(cfg["heartbeat_token"]).strip().lower()
    if len(token) != 64:
        raise ValueError("heartbeat_token in config.json must be 64 hex chars")

    entries = {}
    merge_src = args.in_path or (args.out if os.path.exists(args.out) else None)
    if merge_src and os.path.exists(merge_src):
        entries = read_settings_bin(merge_src)
        print(f"Loaded existing settings from {merge_src} ({len(entries)} entries)")

    entries["enabled"] = (TYPE_INTEGER, 1, False)
    entries["working_mode"] = (TYPE_INTEGER, 1, False)
    entries["show_remaining_time"] = (TYPE_INTEGER, 1, False)
    entries["day_start_minutes"] = (TYPE_INTEGER, 240, False)
    entries["heartbeat_enabled"] = (TYPE_INTEGER, 1, False)
    entries["heartbeat_host"] = (TYPE_STRING, args.host, False)
    entries["heartbeat_port"] = (TYPE_INTEGER, args.port, False)
    entries["heartbeat_interval_s"] = (TYPE_INTEGER, 60, False)
    entries["heartbeat_grace_s"] = (TYPE_INTEGER, 300, False)
    entries["heartbeat_boot_grace_s"] = (TYPE_INTEGER, 900, False)
    entries["heartbeat_token"] = (TYPE_STRING, token, False)

    for uid in args.uid:
        uid = uid.strip()
        if not uid:
            continue
        update_per_user_setting(entries, "daily_limit_users", uid, args.weekday_limit)
        update_per_user_setting(entries, "daily_limit_weekend_users", uid, args.weekend_limit)
        update_per_user_setting(entries, "game_start_users", uid, args.game_start)
        update_per_user_setting(entries, "bedtime_users", uid, args.bedtime)

    nbytes = write_settings_bin(args.out, entries)
    parsed = verify_roundtrip(args.out, entries)

    print(f"Wrote {args.out} ({nbytes} bytes, {len(parsed)} entries, mode=600) - roundtrip OK")
    for k in sorted(parsed.keys()):
        stype, val, enc = parsed[k]
        display = "<REDACTED>" if k in REDACTED_KEYS else val
        print(f"  {k} [type={stype}, enc={enc}]: {display}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
