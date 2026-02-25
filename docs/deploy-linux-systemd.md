# Linux systemd Deployment

## 1. Setup

```bash
git clone https://github.com/<OWNER>/gribu-telegram-notifier.git
cd gribu-telegram-notifier
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
chmod 600 .env
```

Populate required values in `.env`.

## 2. Install Service

```bash
chmod 700 scripts/install_linux_systemd.sh
./scripts/install_linux_systemd.sh
```

Optional overrides:

```bash
SERVICE_NAME=gribu-telegram-notifier REPO_DIR="$HOME/gribu-telegram-notifier" ./scripts/install_linux_systemd.sh
```

## 3. Operate

```bash
sudo systemctl status gribu-telegram-notifier.service
sudo systemctl restart gribu-telegram-notifier.service
sudo journalctl -u gribu-telegram-notifier.service -f
```
