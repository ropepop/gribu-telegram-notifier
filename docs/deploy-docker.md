# Docker Deployment

## 1. Prepare Environment

```bash
git clone https://github.com/<OWNER>/gribu-telegram-notifier.git
cd gribu-telegram-notifier
cp .env.example .env
chmod 600 .env
```

Populate required values in `.env`.

## 2. Build and Run

```bash
docker compose up -d --build
```

## 3. Operate

```bash
docker compose ps
docker compose logs -f gribu-notifier
docker compose restart gribu-notifier
```

## 4. Stop

```bash
docker compose down
```
