from __future__ import annotations

import os
from typing import Optional

_CONFIG_DIR = os.path.expanduser("~/.config/mimir")
_CONFIG_PATH = os.path.join(_CONFIG_DIR, "config")

DEFAULTS: dict[str, str] = {
    "vault": os.path.join(_CONFIG_DIR, "vault.mimir"),
    "session-timeout": "900",
    "branch": "main",
}

# `remote` has no default (it is unset until the user configures one), but it
# is still a settable key.
VALID_KEYS: set[str] = set(DEFAULTS) | {"remote"}


class Config:
    def __init__(self) -> None:
        self._data: dict[str, str] = {}
        self._load()

    def _load(self) -> None:
        if not os.path.exists(_CONFIG_PATH):
            return
        with open(_CONFIG_PATH) as f:
            for line in f:
                line = line.strip()
                if not line or "=" not in line:
                    continue
                key, _, value = line.partition("=")
                self._data[key.strip()] = value.strip()

    def _save(self) -> None:
        os.makedirs(_CONFIG_DIR, exist_ok=True)
        with open(_CONFIG_PATH, "w") as f:
            for key, value in self._data.items():
                f.write(f"{key}={value}\n")

    def get(self, key: str) -> Optional[str]:
        if key in self._data:
            return self._data[key]
        return DEFAULTS.get(key)

    def require(self, key: str) -> str:
        value = self.get(key)
        if value is None:
            raise KeyError(f"Missing config value: {key!r}")
        return value

    def set(self, key: str, value: str) -> None:
        if key not in VALID_KEYS:
            raise KeyError(f"Unknown config key: {key!r}")
        if key == "vault":
            value = os.path.expanduser(value)
        self._data[key] = value
        self._save()

    def list(self) -> dict[str, str]:
        result = dict(DEFAULTS)
        result.update(self._data)
        return result
