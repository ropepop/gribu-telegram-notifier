#!/data/data/com.termux/files/usr/bin/sh
set -eu

REPO_DIR="${REPO_DIR:-$HOME/gribu-telegram-notifier}"
BOOT_DIR="$HOME/.termux/boot"
BOOT_SCRIPT="$BOOT_DIR/start-gribu-telegram-notifier.sh"

mkdir -p "$BOOT_DIR"

cat > "$BOOT_SCRIPT" <<EOF2
#!/data/data/com.termux/files/usr/bin/sh
export REPO_DIR="$REPO_DIR"
nohup "\$REPO_DIR/scripts/start_daemon.sh" >/dev/null 2>&1 &
EOF2

chmod 700 "$BOOT_SCRIPT"
chmod 700 "$REPO_DIR/scripts/start_daemon.sh"

echo "Installed Termux:Boot script at $BOOT_SCRIPT"
echo "Install Termux:Boot app and reboot to verify autostart."
echo "Daemon logs: $REPO_DIR/logs/daemon.log"
