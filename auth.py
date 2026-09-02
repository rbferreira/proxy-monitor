#!/usr/bin/env python3
"""
auth.py
=======
Dashboard authentication: single password, cookie-backed session.

The initial password is `admin` and **must be changeable from the UI itself** —
which is why the hash lives on disk (in the data volume) rather than in an env
var. An env var could not be changed without a redeploy.

Reading the dashboard stays open. The session only gates write actions.
"""

import json
import os
import secrets
import threading
import time

from werkzeug.security import check_password_hash, generate_password_hash

INITIAL_PASSWORD = "admin"
MIN_PASSWORD_LENGTH = 4

# Brute-force window. This is an internal-network tool, so the goal is to slow
# down automated guessing, not to withstand a dedicated attacker.
MAX_ATTEMPTS = 8
WINDOW_SECONDS = 300


class AuthStore:
    """Holds the password hash and the session signing key.

    The signing key is generated on first run and persisted: without that, every
    restart would invalidate open sessions and users would be logged out on each
    deploy with no visible reason.
    """

    def __init__(self, path: str):
        self.path = path
        self._lock = threading.Lock()
        self._hash: str | None = None
        self._secret: str | None = None
        self._failures: list[float] = []

    # ------------------------------------------------------------- persistence

    def load(self) -> None:
        data = {}
        try:
            with open(self.path, encoding="utf-8") as f:
                loaded = json.load(f)
            if isinstance(loaded, dict):
                data = loaded
        except (OSError, ValueError):
            pass

        with self._lock:
            h = data.get("password_hash")
            self._hash = h if isinstance(h, str) and h else None
            s = data.get("secret_key")
            self._secret = s if isinstance(s, str) and len(s) >= 32 else None

        # First run (or lost file): default password and a fresh signing key.
        if self._hash is None:
            self.set_password(INITIAL_PASSWORD, save=False)
        if self._secret is None:
            with self._lock:
                self._secret = secrets.token_urlsafe(48)
        self.save()

    def save(self) -> str | None:
        with self._lock:
            body = {"password_hash": self._hash, "secret_key": self._secret}
        try:
            folder = os.path.dirname(self.path)
            if folder:
                os.makedirs(folder, exist_ok=True)
            tmp = self.path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(body, f, indent=2)
            os.replace(tmp, self.path)  # atomic: never leaves half a file behind
            try:
                os.chmod(self.path, 0o600)  # best effort; a no-op on some filesystems
            except OSError:
                pass
            return None
        except OSError as exc:
            return str(exc)

    # ------------------------------------------------------------------ password

    @property
    def secret_key(self) -> str:
        with self._lock:
            return self._secret or secrets.token_urlsafe(48)

    def set_password(self, new: str, save: bool = True) -> None:
        with self._lock:
            self._hash = generate_password_hash(new)
        if save:
            self.save()

    def check(self, password: str) -> bool:
        with self._lock:
            h = self._hash
        if not h:
            return False
        return check_password_hash(h, password or "")

    def is_initial_password(self) -> bool:
        """True while the password is still `admin`. The UI warns on this."""
        return self.check(INITIAL_PASSWORD)

    @staticmethod
    def validate_new(new: str) -> str | None:
        """Returns an error message, or None when the password is acceptable."""
        if not isinstance(new, str) or not new.strip():
            return "enter the new password"
        if len(new) < MIN_PASSWORD_LENGTH:
            return f"the password must be at least {MIN_PASSWORD_LENGTH} characters"
        return None

    # ----------------------------------------------------------- brute force

    def locked_for(self) -> int:
        """Seconds left on the lockout, or 0 when a new attempt is allowed."""
        now = time.time()
        with self._lock:
            self._failures = [t for t in self._failures if now - t < WINDOW_SECONDS]
            if len(self._failures) < MAX_ATTEMPTS:
                return 0
            return int(WINDOW_SECONDS - (now - self._failures[0])) + 1

    def record_failure(self) -> None:
        with self._lock:
            self._failures.append(time.time())

    def clear_failures(self) -> None:
        with self._lock:
            self._failures.clear()
