# Heartbeat and remote control

The sysmodule can check in with a small server over the Internet, report
the console state, and — when the connection has been down for too long —
enforce the rules locally (a "dead man's switch"). The server can also
send back signed commands (extra time, policy changes, immediate lock).

Everything in this document is implemented by:

- `sysmodule/source/heartbeat.cpp` — thread, state machine, enforcement
- `sysmodule/source/heartbeat_client.cpp` — transport (one TCP exchange)
- `sysmodule/source/heartbeat_protocol.cpp` — pure protocol logic (unit tested)
- `server/` (in the deployment repository) — the Python server and CLI

## Why

The LAN controller (a Raspberry Pi driving sys-botbase) only works while
the console is on the home network, and it stops working entirely when
the network is down — exactly when enforcement matters. The heartbeat
inverts the direction: the console connects *outbound* to the server, so
it works on any network, and a *missing* connection becomes the signal.

## Check-in

Every `heartbeat_interval_s` seconds (default 60), the sysmodule opens a
short outbound TCP connection to `heartbeat_host`:`heartbeat_port` and
sends one JSON line (a few hundred bytes), then reads one JSON response
line and closes.

Request fields:

| Field | Meaning |
| --- | --- |
| `v` | Protocol version (1) |
| `device_id` | Random ID generated once and stored (`heartbeat_device_id`) |
| `counter` | Monotonic counter, persisted (`heartbeat_counter`) — replay protection |
| `ts` | Console clock (informational; the anti-tamper clock is not used on the wire) |
| `fw`, `ams` | Firmware and Atmosphère versions (from the setsys display version) |
| `title_id` | Running game title ID (hex), `null` in the menu |
| `user_hash` | First 16 hex chars of the SHA-256 of the current user's UID |
| `used_min_today`, `remaining_min` | Today's usage of the current user (effective limit, grants included) |
| `flags.curfew`, `flags.screen_off_by_hb` | Curfew currently active; screen currently off by the heartbeat |
| `last_offline_s` | Duration of the last offline episode that ended in a screen-off (0 = none) |
| `acks` | Execution reports of previously received commands (see below) |
| `auth` | `HMAC-SHA256(token, device_id.counter.ts.title_id.used_min_today.ack_ids)` |

The token is a 32-byte pre-shared key (hex) stored in the settings
(`heartbeat_token`), provisioned with the SD card seed (see the `seed/`
tool of the deployment repository). It is never logged.

## Disconnection enforcement

Failures are accumulated in **awake time**: the loop sleeps in 5 second
slices and compares the monotonic (steady) clock against the wall clock,
so time spent in sleep mode never counts and never triggers anything.

- After `heartbeat_grace_s` (default 300 s) of continuous failure, the
  disconnection is enforced:
  - **Handheld**: a one-minute warning notification, then the backlight
    is switched off (`lbl`, same service sys-botbase uses; the heartbeat
    is the only component that drives the backlight — the LAN controller
    runs in notify-only mode).
  - **Docked** (performance mode *Boost*): the screen cannot be turned
    off usefully, so the game is closed after the same one-minute
    countdown (the existing `showScreenTimeout` path). The performance
    mode is a heuristic — it also occurs briefly while loading in
    handheld mode — so this branch is a stage-3 on-device validation
    item.
- While the screen is off, probing continues every 30 s. The first
  successful check-in turns the backlight back on immediately and
  reports the offline duration with `last_offline_s`.
- After a boot, enforcement is suspended for `heartbeat_boot_grace_s`
  (default 900 s) so a console that starts offline is not punished
  before it had a chance to connect.
- Turning the feature off (`heartbeat_enabled` = 0), or the parental
  control master switch, restores the backlight if the heartbeat had
  switched it off.

## Remote commands (downlink)

The response may carry commands. It is authenticated with
`HMAC-SHA256(token, canonical)` where the canonical string is

```
resp|<device_id>|<request counter>|<server_ts>|<config_rev>|<cmd>;<cmd>;…
<cmd> = <id>|<type>|<minutes>|<weekday_limit>|<weekend_limit>|<game_start>|<bedtime>
```

(absent fields render empty). **A response whose signature does not
verify is dropped entirely** and counts as a failed check-in.

| Type | Effect |
| --- | --- |
| `grant_minutes` (`minutes`) | Adds minutes to the *current logical day* of the current user, on top of the day's base limit. Stored in the settings (`grant_date` / `grant_user` / `grant_minutes`), accumulates within the day, expires by itself at the next logical day. Counts in the monitor, the remaining time and the overlay like a higher limit. |
| `set_policy` (any of `weekday_limit`, `weekend_limit`, `game_start`, `bedtime`) | Updates the existing per-user settings for the current user (daily limits and the play window). Persisted, survives reboots. |
| `lock_now` | Applies the disconnection enforcement once: backlight off in handheld mode (restored by the next successful check-in), game closed after the countdown when docked. |

Reliability rules:

- Every command has a unique `command_id`. The sysmodule persists the
  last 32 executed IDs (`heartbeat_done_commands`); a re-sent command is
  reported as `duplicate` and **not** executed again.
- Every command is reported with the *next* check-in in `acks`
  (`ok` + `applied`, or an error detail: `bad_value`, `no_user`,
  `unknown_type`). The ack IDs are part of the request signature, so
  reports cannot be forged either.
- Commands expire server-side (grants and policy changes after 24 h,
  locks after 10 min) so a console that was away for days does not
  execute stale orders.

## Server

`server/switch_server.py` (Python 3, standard library only) validates
the signature and the counter, rate-limits per source IP (60/min),
silently drops bad packets, and maintains in its data directory:

- `state.json` — latest state per device (atomic writes);
- `poller_view.json` — a single-device view (`day`, `used_min`,
  `limit_min`, `remaining_min`, `game`, `online`, `stale`, `last_seen`,
  `fw`, `ams`, `flags`) for the external poller;
- `events.jsonl` — `device_online`, `deadman_screen_off`,
  `command_ack`, `command_expired`;
- `commands.json` — the command queue, shared with the CLI under a file
  lock.

The server is authoritative for nothing but reporting: the policy lives
on the console, the server only mirrors and alerts.

### CLI

Run on the server host (in the deployment container or next to the data
directory):

```sh
switchctl grant 30                       # +30 minutes today
switchctl set weekday_limit=60 weekend_limit=120
switchctl set game_start=07:00 bedtime=23:00
switchctl lock                           # enforce once, now
switchctl pending                        # what is still queued
switchctl status                         # queue + recent executions
```

Every enqueue prints the `command_id` as confirmation.

## Settings keys

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `heartbeat_enabled` | int | 0 | Master switch of the heartbeat |
| `heartbeat_host` | string | — | Server host or IP |
| `heartbeat_port` | int | 39107 | Server port |
| `heartbeat_interval_s` | int | 60 | Check-in interval |
| `heartbeat_grace_s` | int | 300 | Disconnection grace before enforcement |
| `heartbeat_boot_grace_s` | int | 3 × grace (900 with defaults) | No enforcement right after boot |
| `heartbeat_token` | string | — | Pre-shared key (hex, secret) |
| `heartbeat_device_id` | string | generated | Device ID |
| `heartbeat_counter` | int | 0 | Anti-replay counter (managed) |
| `heartbeat_done_commands` | string | — | Executed command IDs (managed) |
| `grant_date`, `grant_user`, `grant_minutes` | string/string/int | — | Current remote grant (managed) |

## Tests

- `tests/heartbeat_protocol_test.cpp` — golden canonical strings
  (shared with the server smoke tests), response parsing, ID list.
- `tests/playtime_rules_test.cpp` — grant arithmetic.
- `server/smoke_test.sh` — end-to-end: normal check-in, bad HMAC,
  replayed counter, dead-man event, grant delivery + ack, re-sent
  command deduplication.
