#!/data/data/com.termux/files/usr/bin/sh
set -eu

REPO_DIR="${REPO_DIR:-$HOME/gribu-telegram-notifier}"
LOG_DIR="${LOG_DIR:-$REPO_DIR/logs}"

mkdir -p "$LOG_DIR"
cd "$REPO_DIR"

if [ ! -d ".venv" ]; then
  python -m venv .venv
fi

. .venv/bin/activate
python app.py daemon >> "$LOG_DIR/daemon.log" 2>&1
