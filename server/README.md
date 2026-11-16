# NSParentalControl Companion Server & Mobile Web Admin

Zero-dependency Python 3 heartbeat check-in server (`39107/TCP`), mobile-first HTTPS management UI (`8788/TCP`), CLI (`switchctl`), SD card `settings.bin` seed tool (`make_seed.py`), and Bark status poller (`poll_switch.py`).

## Quick Start

1. Copy `config.example.json` to `config.json` (`chmod 600`) and fill in a 32-byte random hex `heartbeat_token`, `web_session_secret`, and `admin_pin`.
2. Build and start the container:
   ```bash
   docker compose up -d --build
   ```
3. Generate `settings.bin` for the Switch SD card (`/config/parental_control/settings.bin`):
   ```bash
   python3 seed/make_seed.py --config /path/to/config.json --out settings.bin
   ```
4. Manage via CLI (`./switchctl status`, `./switchctl grant 30`, `./switchctl set weekday_limit=60 weekend_limit=120 game_start=07:00 bedtime=23:00`, `./switchctl lock`) or via the mobile Web Admin UI.
