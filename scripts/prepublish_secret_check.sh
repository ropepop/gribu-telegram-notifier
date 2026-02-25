#!/usr/bin/env bash
set -euo pipefail

if ! command -v rg >/dev/null 2>&1; then
  echo "ripgrep (rg) is required" >&2
  exit 2
fi

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

if [ -z "$(git ls-files)" ]; then
  echo "No tracked files to scan."
  exit 0
fi

TMP_FILE="$(mktemp)"
trap 'rm -f "$TMP_FILE"' EXIT

PATTERN='(AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82,}|xox[baprs]-[A-Za-z0-9-]{10,}|-----BEGIN (RSA|EC|OPENSSH|DSA|PGP) PRIVATE KEY-----|TELEGRAM_BOT_TOKEN\s*=\s*[0-9]{8,10}:[A-Za-z0-9_-]{25,}|GRIBU_LOGIN_PASSWORD\s*=\s*[^[:space:]]{3,}|GRIBU_COOKIE_HEADER\s*=\s*[^[:space:]]{10,})'

if git ls-files -z | xargs -0 rg -nH --pcre2 -e "$PATTERN" > "$TMP_FILE"; then
  if [ -s "$TMP_FILE" ]; then
    FILTERED="$(mktemp)"
    trap 'rm -f "$TMP_FILE" "$FILTERED"' EXIT
    rg -v '^(\.env\.example:|tests/)' "$TMP_FILE" > "$FILTERED" || true
    if [ -s "$FILTERED" ]; then
      echo "Potential secrets found in tracked files:" >&2
      cat "$FILTERED" >&2
      exit 1
    fi
  fi
fi

echo "No obvious secrets found in tracked files."
