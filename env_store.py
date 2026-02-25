from __future__ import annotations

import os
import re
from pathlib import Path


class EnvStoreError(Exception):
    pass


_ENV_KEY_PATTERN = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=")


def upsert_env_value(path: Path, key: str, value: str) -> None:
    if not key or not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", key):
        raise EnvStoreError(f"Invalid env key: {key!r}")

    lines: list[str]
    if path.exists():
        lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
    else:
        lines = []

    replacement = f"{key}={value}\n"
    replaced = False
    new_lines: list[str] = []
    for line in lines:
        match = _ENV_KEY_PATTERN.match(line)
        if match and match.group(1) == key:
            new_lines.append(replacement)
            replaced = True
        else:
            new_lines.append(line)

    if not replaced:
        if new_lines and not new_lines[-1].endswith("\n"):
            new_lines[-1] = new_lines[-1] + "\n"
        new_lines.append(replacement)

    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = path.with_suffix(path.suffix + ".tmp")
    with temp_path.open("w", encoding="utf-8") as fh:
        fh.writelines(new_lines)
    os.replace(temp_path, path)
