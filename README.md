# gribu.lv Telegram Notifier

[![CI](https://github.com/<OWNER>/gribu-telegram-notifier/actions/workflows/ci.yml/badge.svg)](https://github.com/<OWNER>/gribu-telegram-notifier/actions/workflows/ci.yml)
[![Secret Scan](https://github.com/<OWNER>/gribu-telegram-notifier/actions/workflows/secret-scan.yml/badge.svg)](https://github.com/<OWNER>/gribu-telegram-notifier/actions/workflows/secret-scan.yml)

Telegram-controlled notifier for unread gribu.lv messages.

Replace `<OWNER>` in the badge links above after you create your GitHub repository.

## What It Does

- Watches your gribu.lv messages page on an adaptive schedule.
- Sends Telegram alerts only when unread count increases.
- Supports Telegram commands: `/on`, `/off`, `/status`, `/debug`, `/checknow`, `/reauth`, `/help`.
- Maintains session cookies and retries automatically on session expiry.
- Includes daemon watchdog/supervisor reliability behavior and health checks.

## Quickstart

```bash
git clone https://github.com/<OWNER>/gribu-telegram-notifier.git
cd gribu-telegram-notifier
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
cp .env.example .env
chmod 600 .env
```

Update `.env` with real values:

- `TELEGRAM_BOT_TOKEN`
- `TELEGRAM_CHAT_ID`
- `GRIBU_LOGIN_ID`
- `GRIBU_LOGIN_PASSWORD`

Run daemon:

```bash
source .venv/bin/activate
python app.py daemon
```

## Configuration Reference

Required:

- `TELEGRAM_BOT_TOKEN`
- `TELEGRAM_CHAT_ID`
- `GRIBU_LOGIN_ID`
- `GRIBU_LOGIN_PASSWORD`

Common optional values:

- `GRIBU_BASE_URL` (default: `https://www.gribu.lv`)
- `GRIBU_CHECK_URL` (default: `/lv/messages`)
- `GRIBU_LOGIN_PATH` (default: `/pieslegties`)
- `CHECK_INTERVAL_SEC` (default: `60`)
- `CHECK_INTERVAL_FAST_SEC` (default: `20`)
- `CHECK_INTERVAL_IDLE_SEC` (default: `60`)
- `CHECK_INTERVAL_ERROR_BACKOFF_MAX_SEC` (default: `180`)
- `STATE_FILE` (default: `./state/state.json`)
- `DAEMON_LOCK_FILE` (default: `./state/daemon.lock`)
- `HTTP_TIMEOUT_SEC` (default: `20`)
- `ERROR_ALERT_COOLDOWN_SEC` (default: `1800`)
- `TELEGRAM_NAV_BUTTONS_ENABLED` (default: `true`)
- `WATCHDOG_CHECK_SEC` (default: `10`)
- `WATCHDOG_STALE_SEC` (default: `120`)
- `SUPERVISOR_RESTART_BASE_SEC` (default: `2`)
- `SUPERVISOR_RESTART_MAX_SEC` (default: `30`)
- `PARSE_LOW_CONFIDENCE_DELTA_LIMIT` (default: `20`)

Path behavior:

- Relative `STATE_FILE` and `DAEMON_LOCK_FILE` are resolved relative to the `.env` directory.
- Absolute paths are used as-is.

## Operations

Start daemon:

```bash
python app.py daemon
```

Single check:

```bash
python app.py check-once
```

Local state dump:

```bash
python app.py status-local
```

Health check (`0` healthy, `1` unhealthy):

```bash
python app.py healthcheck
```

## Deployment Guides

- Linux systemd: [docs/deploy-linux-systemd.md](docs/deploy-linux-systemd.md)
- Termux: [docs/deploy-termux.md](docs/deploy-termux.md)
- Docker: [docs/deploy-docker.md](docs/deploy-docker.md)

## Security and Data Hygiene

Before sharing code, docs, logs, screenshots, or terminal output:

- Never publish `.env`, `state/`, `logs/`, raw capture files, real chat IDs, bot tokens, passwords, or cookie headers.
- Treat `GRIBU_COOKIE_HEADER` as a live session secret, even though it is runtime-managed.
- Run the prepublish scanner before every push:

```bash
./scripts/prepublish_secret_check.sh
```

- Use placeholder-only examples in docs, issues, and pull requests.

Safe example format:

```text
TELEGRAM_BOT_TOKEN=123456789:replace_me
TELEGRAM_CHAT_ID=123456789
GRIBU_LOGIN_ID=your_username_or_email
GRIBU_LOGIN_PASSWORD: <REDACTED>
GRIBU_COOKIE_HEADER: <REDACTED>
```

- Follow the redaction workflow in [docs/sensitive-data-scrub.md](docs/sensitive-data-scrub.md).
- See [SECURITY.md](SECURITY.md) for incident response and credential rotation guidance.

## Fresh Installs Only

This repository documents fresh installations only.
