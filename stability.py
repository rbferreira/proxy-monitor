#!/usr/bin/env python3
"""
stability.py
============
Whether a proxy can be relied on, rather than whether it answered once.

A single check per cycle publishes a proxy that responded one time with exactly
the same confidence as one that has been up for hours. Measured against the
consumer of this service, that showed up as two thirds of the published list
turning over every twenty minutes — churn that says as much about the
measurement as about the proxies.

This keeps a short history per proxy and only calls one stable once it has
earned it: enough checks, a good enough success rate, and a run of consecutive
successes right now.

**Three states, not two.** `unknown` is not `unstable`. A proxy nobody has
measured yet has not failed anything, and reporting it as unstable would be a
claim we cannot support — it would also be indistinguishable, on a dashboard,
from a proxy that genuinely fails. That distinction is the whole reason the
third state exists.

**A sample is a latency or None.** No timestamp: at a fixed re-check cadence, a
window of N samples and a window of N intervals are the same window. The one
job a timestamp would do — noticing the history is stale — is done by a single
`last_seen` on the record, which is also what makes the honesty rule below
cheap to enforce.
"""

import json
import os
import statistics
import threading
import time
from collections import deque
from dataclasses import dataclass, field

# A backstop, not a tuning knob: retention is what normally bounds the file.
# This only matters if retention is misconfigured or a source explodes.
MAX_TRACKED = 5000

# Samples kept per proxy. At a 120s re-check that is half an hour of memory,
# which spans more than one full discovery cycle so no single cycle dominates.
WINDOW = 15

# Records untouched for longer than this are dropped. Free proxies die fast —
# roughly 38% per hour — so an hour-old record is not evidence of anything.
RETENTION_SECONDS = 3600

# History older than this is not reported as fact. Three and a half re-check
# intervals: survives one skipped pass and one full discovery cycle, but not a
# wedged loop, a paused container, or a long restart.
STALE_SECONDS = 420

SCHEMA_VERSION = 1

UNKNOWN = "unknown"
UNSTABLE = "unstable"
STABLE = "stable"


@dataclass
class Policy:
    """What it takes to be called stable."""
    min_checks: int = 5
    min_success_rate: float = 0.8
    min_streak: int = 3
    window: int = WINDOW
    stale_seconds: float = STALE_SECONDS

    def effective_min_checks(self) -> int:
        # A threshold above the window can never be met. Settings are validated
        # one key at a time, so this pairing cannot be rejected at save time;
        # clamping here beats letting the panel accept a config that silently
        # marks everything unknown forever.
        return max(1, min(self.min_checks, self.window))

    def effective_min_streak(self) -> int:
        return max(0, min(self.min_streak, self.window))


@dataclass
class Record:
    """One proxy's recent behaviour."""
    proxy: str
    samples: deque = field(default_factory=lambda: deque(maxlen=WINDOW))
    first_seen: float = 0.0
    last_seen: float = 0.0
    last_ok: float | None = None
    stable_since: float | None = None

    @property
    def checks(self) -> int:
        return len(self.samples)

    @property
    def successes(self) -> int:
        return sum(1 for s in self.samples if s is not None)

    @property
    def success_rate(self) -> float:
        return self.successes / len(self.samples) if self.samples else 0.0

    @property
    def streak(self) -> int:
        """Consecutive successes, counting back from the most recent check.

        Derived rather than stored: a counter kept alongside the window is one
        more thing that can disagree with it after a reload.
        """
        run = 0
        for sample in reversed(self.samples):
            if sample is None:
                break
            run += 1
        return run

    @property
    def median_latency(self) -> float | None:
        measured = [s for s in self.samples if s is not None]
        return round(statistics.median(measured), 3) if measured else None

    @property
    def latency_spread(self) -> float | None:
        """How much the latency moves around. Reported, never a gate: the
        latency cutoff already rejects slow samples, so variance is folded into
        the success rate. A second variance threshold would be a knob nobody
        can tune from a dashboard."""
        measured = [s for s in self.samples if s is not None]
        if len(measured) < 2:
            return None
        return round(statistics.pstdev(measured), 3)


class Store:
    """Per-proxy history, persisted next to the proxy cache.

    Two rules, because breaking either is how this deadlocks the service:
    never touch the app's state while holding this lock, and never call
    `save()` (disk I/O) while holding the app's lock.
    """

    def __init__(self, path: str, policy: Policy | None = None):
        self.path = path
        self.policy = policy or Policy()
        self._records: dict[str, Record] = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------- recording

    def record(self, proxy: str, latency: float | None, now: float | None = None) -> None:
        """Add one observation. `latency is None` means the check failed."""
        now = now or time.time()
        with self._lock:
            rec = self._records.get(proxy)
            if rec is None:
                rec = Record(proxy=proxy,
                             samples=deque(maxlen=self.policy.window),
                             first_seen=now)
                self._records[proxy] = rec
            elif rec.samples.maxlen != self.policy.window:
                rec.samples = deque(rec.samples, maxlen=self.policy.window)
            rec.samples.append(latency)
            rec.last_seen = now
            if latency is not None:
                rec.last_ok = now
            self._track_stability(rec, now)

    def record_batch(self, results: dict[str, float | None], now: float | None = None) -> None:
        now = now or time.time()
        for proxy, latency in results.items():
            self.record(proxy, latency, now)

    def _track_stability(self, rec: Record, now: float) -> None:
        """Remember when a proxy became stable, and forget it when it stops."""
        if self._state_of(rec, now) == STABLE:
            if rec.stable_since is None:
                rec.stable_since = now
        else:
            rec.stable_since = None

    # ------------------------------------------------------------- verdicts

    def _blockers(self, rec: Record, now: float) -> list[str]:
        """Why this proxy is not stable, in the order a reader would ask.

        Not enough recent evidence short-circuits the rest. A rate or a streak
        computed over two samples is not a measurement, and listing "streak too
        short" beside "not enough checks" reads as two problems when it is one:
        the streak is short *because* the checks are few.
        """
        unmeasurable = []
        if now - rec.last_seen > self.policy.stale_seconds:
            unmeasurable.append("stale")
        if rec.checks < self.policy.effective_min_checks():
            unmeasurable.append("checks")
        if unmeasurable:
            return unmeasurable

        reasons = []
        if rec.success_rate < self.policy.min_success_rate:
            reasons.append("rate")
        if rec.streak < self.policy.effective_min_streak():
            reasons.append("streak")
        return reasons

    def _state_of(self, rec: Record, now: float) -> str:
        reasons = self._blockers(rec, now)
        if not reasons:
            return STABLE
        # Too new or too old to judge is not the same as judged and found
        # wanting. `_blockers` returns those alone when they apply, so this is
        # a straight test of which kind of reason came back.
        if reasons[0] in ("stale", "checks"):
            return UNKNOWN
        return UNSTABLE

    def state_of(self, proxy: str, now: float | None = None) -> str:
        now = now or time.time()
        with self._lock:
            rec = self._records.get(proxy)
            return UNKNOWN if rec is None else self._state_of(rec, now)

    def view(self, proxy: str, now: float | None = None) -> dict:
        """Everything worth showing about one proxy."""
        now = now or time.time()
        with self._lock:
            rec = self._records.get(proxy)
            if rec is None:
                return {"state": UNKNOWN, "checks": 0, "success_rate": None,
                        "streak": 0, "median_latency": None, "spread": None,
                        "stable_for": None, "blockers": ["checks"]}
            return {
                "state": self._state_of(rec, now),
                "checks": rec.checks,
                "success_rate": round(rec.success_rate, 3),
                "streak": rec.streak,
                "median_latency": rec.median_latency,
                "spread": rec.latency_spread,
                "stable_for": round(now - rec.stable_since, 1) if rec.stable_since else None,
                "blockers": self._blockers(rec, now),
            }

    def snapshot(self, proxies=None, now: float | None = None) -> dict[str, dict]:
        """Views for many proxies, computed in one pass under one lock."""
        now = now or time.time()
        keys = list(proxies) if proxies is not None else None
        with self._lock:
            if keys is None:
                keys = list(self._records)
        return {p: self.view(p, now) for p in keys}

    def counts(self, proxies=None, now: float | None = None) -> dict[str, int]:
        now = now or time.time()
        tally = {STABLE: 0, UNSTABLE: 0, UNKNOWN: 0}
        for view in self.snapshot(proxies, now).values():
            tally[view["state"]] += 1
        return tally

    def stable_only(self, proxies, now: float | None = None) -> list[str]:
        now = now or time.time()
        return [p for p in proxies if self.state_of(p, now) == STABLE]

    def warming_up(self, proxies, now: float | None = None) -> bool:
        """True while some proxy has not been measured enough to judge.

        The caller uses this to tell "nothing qualifies yet" apart from
        "nothing qualifies" — which is the difference between a service that
        just started and one whose proxies are all dead.
        """
        now = now or time.time()
        return any(self.state_of(p, now) == UNKNOWN for p in proxies)

    # -------------------------------------------------------------- pruning

    def prune(self, now: float | None = None,
              retention: float = RETENTION_SECONDS) -> int:
        """Drop records nothing has touched lately. Returns how many went.

        Keyed on last *checked*, not on absence from the valid list: a proxy
        failing every check for twenty minutes must keep its history, because
        that history is exactly what proves it unreliable. Once it stops being
        probed at all, it ages out on its own.
        """
        now = now or time.time()
        with self._lock:
            dead = [p for p, r in self._records.items()
                    if now - r.last_seen > retention]
            for proxy in dead:
                del self._records[proxy]

            excess = len(self._records) - MAX_TRACKED
            if excess > 0:
                oldest = sorted(self._records.items(), key=lambda kv: kv[1].last_seen)
                for proxy, _ in oldest[:excess]:
                    del self._records[proxy]
                    dead.append(proxy)
        return len(dead)

    def clear(self) -> None:
        with self._lock:
            self._records.clear()

    def __len__(self) -> int:
        with self._lock:
            return len(self._records)

    # ---------------------------------------------------------- persistence

    def save(self) -> str | None:
        """Persist atomically. Returns an error message, or None on success."""
        with self._lock:
            payload = {
                "version": SCHEMA_VERSION,
                "saved_at": time.time(),
                "window": self.policy.window,
                "proxies": {
                    p: {
                        "samples": list(r.samples),
                        "first_seen": r.first_seen,
                        "last_seen": r.last_seen,
                        "last_ok": r.last_ok,
                        "stable_since": r.stable_since,
                    }
                    for p, r in self._records.items()
                },
            }
        try:
            folder = os.path.dirname(self.path)
            if folder:
                os.makedirs(folder, exist_ok=True)
            tmp = self.path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                # No indent: this file is written every couple of minutes and is
                # never read by a person. Pretty-printing it quadruples the size.
                json.dump(payload, f, separators=(",", ":"))
            os.replace(tmp, self.path)
            return None
        except OSError as exc:
            return str(exc)

    def load(self) -> None:
        """Restore history. A missing, corrupt or foreign file starts empty.

        Nothing here decides whether the restored history can be trusted — the
        staleness rule in `_blockers` does, on every read. A service that was
        down for an hour comes back reporting `unknown` rather than asserting a
        verdict from evidence that has expired.
        """
        try:
            with open(self.path, encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, ValueError):
            return
        if not isinstance(data, dict) or data.get("version") != SCHEMA_VERSION:
            return
        entries = data.get("proxies")
        if not isinstance(entries, dict):
            return

        restored: dict[str, Record] = {}
        for proxy, blob in entries.items():
            if not isinstance(blob, dict):
                continue
            raw = blob.get("samples")
            if not isinstance(raw, list):
                continue
            samples = [s for s in raw if s is None or isinstance(s, (int, float))]
            # Truncated to the *current* window: the setting may have shrunk
            # since this file was written.
            rec = Record(
                proxy=proxy,
                samples=deque(samples[-self.policy.window:], maxlen=self.policy.window),
                first_seen=_number(blob.get("first_seen")),
                last_seen=_number(blob.get("last_seen")),
                last_ok=_optional_number(blob.get("last_ok")),
                stable_since=_optional_number(blob.get("stable_since")),
            )
            restored[proxy] = rec

        with self._lock:
            self._records = restored


def _number(value) -> float:
    return float(value) if isinstance(value, (int, float)) else 0.0


def _optional_number(value) -> float | None:
    return float(value) if isinstance(value, (int, float)) else None
