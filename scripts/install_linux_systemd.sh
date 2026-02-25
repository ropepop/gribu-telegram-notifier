#!/usr/bin/env bash
set -eu

if ! command -v systemctl >/dev/null 2>&1; then
  echo "systemctl is required for Linux systemd setup" >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="${REPO_DIR:-$(cd "$SCRIPT_DIR/.." && pwd)}"
SERVICE_NAME="${SERVICE_NAME:-gribu-telegram-notifier}"
RUN_USER="${RUN_USER:-${SUDO_USER:-$(id -un)}}"
RUN_GROUP="${RUN_GROUP:-$(id -gn "$RUN_USER")}"
PYTHON_BIN="${PYTHON_BIN:-$REPO_DIR/.venv/bin/python}"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"

if [ ! -x "$PYTHON_BIN" ]; then
  echo "Python executable not found: $PYTHON_BIN" >&2
  echo "Create a virtualenv and install dependencies before installing the service." >&2
  exit 1
fi

run_root() {
  if [ "$(id -u)" -eq 0 ]; then
    "$@"
    return
  fi
  sudo "$@"
}

tmp_file="$(mktemp)"
trap 'rm -f "$tmp_file"' EXIT

cat > "$tmp_file" <<EOF2
[Unit]
Description=gribu.lv Telegram notifier daemon
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User=$RUN_USER
Group=$RUN_GROUP
WorkingDirectory=$REPO_DIR
ExecStart=$PYTHON_BIN $REPO_DIR/app.py daemon
Restart=always
RestartSec=5
KillSignal=SIGTERM
TimeoutStopSec=20

[Install]
WantedBy=multi-user.target
EOF2

run_root install -m 644 "$tmp_file" "$SERVICE_FILE"
run_root systemctl daemon-reload
run_root systemctl enable --now "${SERVICE_NAME}.service"

echo "Installed and started ${SERVICE_NAME}.service"
echo "Check status: sudo systemctl status ${SERVICE_NAME}.service"
echo "View logs: sudo journalctl -u ${SERVICE_NAME}.service -f"
