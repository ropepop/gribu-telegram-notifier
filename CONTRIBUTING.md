# Contributing

## Development Setup

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt pytest
```

## Tests

Run the full test suite before submitting changes:

```bash
python -m pytest -q
```

## Secret Hygiene

- Do not commit `.env`, `state/`, `logs/`, or real credentials.
- Keep example values in `.env.example` placeholder-only.
- Run secret checks before push:

```bash
./scripts/prepublish_secret_check.sh
```

## Pull Requests

- Keep PRs focused and include a short change summary.
- Add/adjust tests for behavior changes.
- Call out operational impacts (systemd, Termux, Docker) when relevant.
