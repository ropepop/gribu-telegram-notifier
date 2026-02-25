# Termux Deployment

## 1. Setup

```bash
pkg update
pkg install python git

git clone https://github.com/<OWNER>/gribu-telegram-notifier.git
cd gribu-telegram-notifier
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
chmod 600 .env
```

Populate required values in `.env`.

## 2. Start Manually

```bash
source .venv/bin/activate
python app.py daemon
```

## 3. Enable Boot Autostart

Install [Termux:Boot](https://f-droid.org/packages/com.termux.boot/), then:

```bash
chmod 700 scripts/start_daemon.sh scripts/install_termux_autostart.sh
./scripts/install_termux_autostart.sh
```

Logs:

```bash
tail -f ~/gribu-telegram-notifier/logs/daemon.log
```
