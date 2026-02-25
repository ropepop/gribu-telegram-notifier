# Sensitive Data Scrub Guide

## Purpose and Scope

Use this guide before publishing code, documentation, screenshots, logs, or terminal output from this project.
It defines what must be treated as secret and how to redact safely.

## Sensitive Fields Inventory

Treat the following values as sensitive at all times:

- `TELEGRAM_BOT_TOKEN`
- `TELEGRAM_CHAT_ID`
- `GRIBU_LOGIN_ID`
- `GRIBU_LOGIN_PASSWORD`
- `GRIBU_COOKIE_HEADER`

Also treat any real values in `.env`, `state/`, `logs/`, and raw HTTP capture files as sensitive.

## Redaction Rules

- Docs and markdown: never paste real credentials, chat IDs, cookie headers, or account identifiers.
- Logs and terminal output: replace token, chat ID, password, and cookie values with placeholders.
- Screenshots: blur or remove any secret values before sharing.
- Command examples: use placeholders only; do not include real copied runtime output.
- Use one of these placeholder styles consistently: `replace_me`, `your_username_or_email`, or `<REDACTED>`.

## Before/After Redaction Examples

Before (unsafe):

```text
TELEGRAM_BOT_TOKEN=<LIVE_TOKEN_SHOULD_NOT_BE_SHARED>
TELEGRAM_CHAT_ID=9988776655
GRIBU_LOGIN_PASSWORD: my-real-password
GRIBU_COOKIE_HEADER: disclaimer=accept; DATINGSES=abcdef123456;
```

After (safe):

```text
TELEGRAM_BOT_TOKEN=123456789:replace_me
TELEGRAM_CHAT_ID=123456789
GRIBU_LOGIN_PASSWORD: <REDACTED>
GRIBU_COOKIE_HEADER: <REDACTED>
```

Before (unsafe log line):

```text
token=<live-token-value> chat_id=9988776655 cookie_header=disclaimer=accept; DATINGSES=abcdef123456;
```

After (safe log line):

```text
token=<REDACTED> chat_id=<REDACTED> cookie_header=<REDACTED>
```

## Pre-Push Checklist

1. Run `./scripts/prepublish_secret_check.sh`.
2. Review `git diff` and confirm no secrets appear in tracked files.
3. Confirm all examples use placeholders only.
4. Ensure `.env`, `state/`, and `logs/` are not tracked.

Optional spot-check:

```bash
git ls-files -z | xargs -0 rg -n "TELEGRAM_BOT_TOKEN=|GRIBU_LOGIN_PASSWORD=|GRIBU_COOKIE_HEADER="
```

The only expected matches should be placeholder entries in `.env.example` (and test fixtures if present).

## Incident Steps Summary

If a secret is exposed, rotate credentials immediately and remove the leak from history before publishing.
See [SECURITY.md](../SECURITY.md) for the full incident response and reporting process.
