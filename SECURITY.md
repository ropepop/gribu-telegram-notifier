# Security Policy

## Sensitive Data

Treat the following as secrets:

- `TELEGRAM_BOT_TOKEN`
- `TELEGRAM_CHAT_ID`
- `GRIBU_LOGIN_ID`
- `GRIBU_LOGIN_PASSWORD`
- `GRIBU_COOKIE_HEADER`
- Any real content in `.env`, `state/`, and `logs/`

## Safe Handling Rules

- Never commit `.env`, `state/`, `logs/`, or raw capture files.
- Keep `.env` permissions restricted (for example: `chmod 600 .env`).
- Do not paste secrets in issues, pull requests, CI logs, or screenshots.
- Run `./scripts/prepublish_secret_check.sh` before every push.
- Follow [docs/sensitive-data-scrub.md](docs/sensitive-data-scrub.md) before sharing docs, logs, screenshots, or terminal output.
- Keep runtime/state folders local to the device and out of git.

## Incident Response and Rotation

If a secret is exposed:

1. Revoke/regenerate Telegram bot token in BotFather.
2. Change gribu account password immediately.
3. Clear `GRIBU_COOKIE_HEADER` in `.env` and restart daemon to force fresh auth.
4. Rotate any other leaked credentials.
5. Remove leaked material from git history before publishing (if applicable).
6. Review recent pushes and CI logs for additional exposure.

## Reporting

Open a private security report with reproduction steps and impacted files, and avoid posting live secrets in public channels.
