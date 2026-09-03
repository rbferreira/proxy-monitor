#!/usr/bin/env python3
"""
settings.py
===========
Runtime-adjustable settings, editable from the dashboard.

Each setting has a default coming from an env var and can be overridden through
the UI. The override is persisted next to the proxy cache and **wins over the
env var** — turning something off because of a problem and watching the service
revert on the next deploy would be the worst possible surprise.

Deleting the state file restores every default.

Only structure lives here (keys, types, bounds, groups). Human-facing text lives
in `i18n.py`, which is what lets the same schema serve several languages.
"""

import json
import os
import threading
from dataclasses import dataclass
from urllib.parse import urlparse

import i18n
import proxy_validator


@dataclass(frozen=True)
class Setting:
    key: str            # identifier in the API and in the state file
    env: str            # env var providing the default
    type: str           # "int" | "float" | "bool" | "list"
    default: object     # used when the env var is unset
    group: str          # group key, translated through i18n
    minimum: float | None = None
    maximum: float | None = None
    unit: str = ""
    # "immediate" = next request; "next_cycle" = only on the next validation
    effect: str = "immediate"
    # "list" only: cap on how many entries are accepted
    max_items: int = 50


SETTINGS: tuple[Setting, ...] = (
    Setting(
        key="proxy_sources", env="PROXY_SOURCES", type="list",
        default=list(proxy_validator.PROXY_SOURCES),
        group="sources", effect="next_cycle", max_items=50,
    ),
    Setting(
        key="interval_seconds", env="INTERVAL_SECONDS", type="int", default=1200,
        minimum=60, maximum=86400, unit="s", group="validation", effect="next_cycle",
    ),
    Setting(
        key="max_latency_seconds", env="MAX_LATENCY_SECONDS", type="float", default=5.0,
        minimum=0.5, maximum=30.0, unit="s", group="validation", effect="next_cycle",
    ),
    Setting(
        key="validator_workers", env="VALIDATOR_WORKERS", type="int", default=100,
        minimum=1, maximum=500, group="validation", effect="next_cycle",
    ),
    Setting(
        key="geolookup", env="GEOLOOKUP", type="bool", default=True,
        group="geo", effect="next_cycle",
    ),
    Setting(
        key="dashboard_rows", env="DASHBOARD_ROWS", type="int", default=100,
        minimum=10, maximum=1000, unit="rows", group="dashboard",
    ),
    Setting(
        key="latency_buckets", env="LATENCY_BUCKETS", type="int", default=12,
        minimum=4, maximum=40, unit="buckets", group="dashboard",
    ),
)

BY_KEY = {s.key: s for s in SETTINGS}


def _from_env(s: Setting):
    """Default for a setting: the env var when set and valid, otherwise the
    hardcoded default. A malformed env var must not crash the boot."""
    raw = os.environ.get(s.env)
    if raw is None or raw.strip() == "":
        return s.default
    raw = raw.strip()
    try:
        if s.type == "list":
            return parse_list(raw)
        if s.type == "bool":
            return raw.lower() not in ("false", "0", "no", "off")
        if s.type == "int":
            return int(raw)
        return float(raw)
    except ValueError:
        return s.default


def parse_list(raw) -> list[str]:
    """Accept a real list or a comma/newline separated string, and drop blanks."""
    if isinstance(raw, list):
        parts = [str(p) for p in raw]
    else:
        parts = str(raw or "").replace(",", "\n").splitlines()
    return [p.strip() for p in parts if p and p.strip()]


def coerce(s: Setting, value, locale: str = i18n.DEFAULT_LOCALE):
    """Convert and validate a value coming from the API. Raises ValueError with
    a message meant to be shown on screen, localized."""
    label = i18n.setting_text(locale, s.key)["label"]

    if s.type == "list":
        entries = parse_list(value)
        if not entries:
            raise ValueError(f"{label}: at least one entry is required")
        if len(entries) > s.max_items:
            raise ValueError(f"{label}: at most {s.max_items} entries")
        for entry in entries:
            parsed = urlparse(entry)
            # Anything but http/https would be handed straight to urlopen, and a
            # file:// or similar scheme there reads the server's own disk.
            if parsed.scheme not in ("http", "https") or not parsed.netloc:
                raise ValueError(f"{label}: not an http(s) URL: {entry[:60]}")
        return entries

    if s.type == "bool":
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            return value.strip().lower() in ("true", "1", "yes", "on")
        raise ValueError(f"{label}: expected true or false")

    try:
        num = int(value) if s.type == "int" else float(value)
    except (TypeError, ValueError):
        expected = "an integer" if s.type == "int" else "a number"
        raise ValueError(f"{label}: expected {expected}") from None

    if s.minimum is not None and num < s.minimum:
        raise ValueError(f"{label}: minimum {_fmt(s, s.minimum)}")
    if s.maximum is not None and num > s.maximum:
        raise ValueError(f"{label}: maximum {_fmt(s, s.maximum)}")
    return num


def _fmt(s: Setting, v) -> str:
    text = str(int(v)) if s.type == "int" or float(v).is_integer() else str(v)
    return f"{text}{s.unit}" if s.unit else text


class Store:
    """Holds the overrides and resolves the effective value of each setting."""

    def __init__(self, path: str):
        self.path = path
        self._overrides: dict[str, object] = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------ persistence

    def load(self) -> None:
        """Read the state file. Missing or corrupt falls back to defaults, and an
        unknown or out-of-range setting is skipped instead of breaking the boot."""
        try:
            with open(self.path, encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, ValueError):
            return
        if not isinstance(data, dict):
            return
        valid = {}
        for key, value in data.items():
            s = BY_KEY.get(key)
            if s is None:
                continue
            try:
                valid[key] = coerce(s, value)
            except ValueError:
                continue
        with self._lock:
            self._overrides = valid

    def save(self) -> str | None:
        """Persist the overrides. Returns an error message, or None on success."""
        with self._lock:
            snapshot = dict(self._overrides)
        try:
            folder = os.path.dirname(self.path)
            if folder:
                os.makedirs(folder, exist_ok=True)
            tmp = self.path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(snapshot, f, indent=2, sort_keys=True)
            os.replace(tmp, self.path)  # atomic: never leaves half a file behind
            return None
        except OSError as exc:
            return str(exc)

    # ----------------------------------------------------------------- access

    def get(self, key: str):
        s = BY_KEY[key]
        with self._lock:
            if key in self._overrides:
                return self._overrides[key]
        return _from_env(s)

    def is_overridden(self, key: str) -> bool:
        with self._lock:
            return key in self._overrides

    def apply(self, changes: dict, locale: str = i18n.DEFAULT_LOCALE) -> tuple[dict, list[str]]:
        """Validate and apply a batch. Returns (applied, errors).

        All or nothing: if any value is invalid nothing is written, so the
        configuration never lands in a half-state nobody asked for.
        """
        errors, staged = [], {}
        for key, value in (changes or {}).items():
            s = BY_KEY.get(key)
            if s is None:
                errors.append(f"unknown setting: {key}")
                continue
            try:
                staged[key] = coerce(s, value, locale)
            except ValueError as exc:
                errors.append(str(exc))
        if errors:
            return {}, errors
        with self._lock:
            self._overrides.update(staged)
        return staged, []

    def reset(self, key: str | None = None) -> None:
        """Drop the override for one setting (or all), back to the env var."""
        with self._lock:
            if key is None:
                self._overrides.clear()
            else:
                self._overrides.pop(key, None)

    def describe(self, locale: str = i18n.DEFAULT_LOCALE) -> list[dict]:
        """Schema plus current values, localized. The UI builds its whole form
        from this, so a new setting needs no HTML change."""
        out = []
        for s in SETTINGS:
            text = i18n.setting_text(locale, s.key)
            out.append({
                "key": s.key,
                "label": text["label"],
                "description": text["description"],
                "group": i18n.group_name(locale, s.group),
                "group_key": s.group,
                "type": s.type,
                "unit": s.unit,
                "minimum": s.minimum,
                "maximum": s.maximum,
                "effect": s.effect,
                "value": self.get(s.key),
                "default": _from_env(s),
                "overridden": self.is_overridden(s.key),
                "env": s.env,
            })
        return out
