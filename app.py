#!/usr/bin/env python3
"""
PROXY//MONITOR
==============
Flask service that:
  - runs the validator every `interval_seconds` (background scheduler)
  - serves the current list of working proxies over HTTP
  - ships a dashboard at / with live metrics, backed by /api/stats
  - gates every write behind a session login; reading stays open
"""
import json
import os
import secrets
import threading
import time
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

import requests
from flask import Flask, abort, jsonify, render_template_string, request, session

import auth as auth_mod
import i18n
import proxy_validator
import settings as settings_mod

OUTPUT_FILE = os.environ.get("OUTPUT_FILE", "/data/proxies.txt")
DATA_DIR = os.path.dirname(OUTPUT_FILE) or "."

# Machine credential for the data endpoints, used by scripts through the
# X-API-Key header. Generated on first boot and persisted next to the rest of
# the state — no shared default to leak, and it works out of the box. Set the
# API_KEY env var to pin your own.
API_KEY_FILE = os.path.join(DATA_DIR, "api_key")

# Read-only token for consumers that can only fetch a URL and cannot send a
# header. Applies to the plain-text list endpoints only.
#
# It travels in the query string, so it shows up in access logs. That is exactly
# why it is separate from API_KEY: the worst a leak buys is reading the proxy
# list, which the dashboard already shows.
LIST_TOKEN = os.environ.get("LIST_TOKEN", "").strip()
LIST_TOKEN_PATHS = {"/proxy/all.txt"}

# Dashboard readable without logging in. With PUBLIC_DASHBOARD=false, / and
# /api/stats require the session too.
PUBLIC_DASHBOARD = os.environ.get("PUBLIC_DASHBOARD", "true").lower() not in ("false", "0", "no")

# Session cookie over HTTPS only. Off by default because these services are
# commonly reached over plain http on a local network — turned on there, the
# cookie would never be sent and the login would look broken.
SESSION_SECURE = os.environ.get("SESSION_COOKIE_SECURE", "false").lower() in ("true", "1", "yes")

app = Flask(__name__)

_lock = threading.Lock()
_state = {
    "proxies": [],       # list of "protocol://host:port" strings
    "latencies": {},     # proxy -> latency in seconds
    "proxy_data": [],    # dicts with metadata (protocol/ip/port/latency/country)
    "last_run": None,    # ISO 8601 of the last successful validation
    "next_run": None,    # ISO 8601 estimate of the next one
    "duration": None,    # seconds the last validation took
    "source_count": 0,   # raw proxies downloaded from the sources
    "status": "idle",    # idle | running | ok | error
    "message": "",
    "stats": {
        "total": 0,
        "healthy": 0,
        "by_protocol": {},
        "by_country": {},
        "latency_buckets": [],
        "avg_latency": 0,
        "min_latency": 0,
        "max_latency": 0,
    },
}

RUNTIME_FILE = os.path.join(DATA_DIR, "runtime.json")
AUTH_FILE = os.path.join(DATA_DIR, "auth.json")
settings_store = settings_mod.Store(RUNTIME_FILE)
auth_store = auth_mod.AuthStore(AUTH_FILE)


def cfg(key: str):
    """Effective value of a setting: dashboard override, else the env var."""
    return settings_store.get(key)


# Country lookups cached across runs: each IP is queried only once.
_country_cache: dict[str, str] = {}
# One validation at a time (/api/refresh can trigger on demand).
_validation_lock = threading.Lock()

_api_key: str = ""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _log(msg: str) -> None:
    print(f"[{_now()}] {msg}", flush=True)


def _set_state(**kwargs) -> None:
    with _lock:
        _state.update(kwargs)


def load_api_key() -> str:
    """API key from the env var, or generated once and persisted.

    Same pattern as the session signing key: a project that ships a default
    credential in its source ships a working credential to everyone who reads it.
    """
    from_env = os.environ.get("API_KEY", "").strip()
    if from_env:
        return from_env
    try:
        with open(API_KEY_FILE, encoding="utf-8") as f:
            saved = f.read().strip()
        if saved:
            return saved
    except OSError:
        pass

    generated = secrets.token_urlsafe(24)
    try:
        os.makedirs(DATA_DIR, exist_ok=True)
        with open(API_KEY_FILE, "w", encoding="utf-8") as f:
            f.write(generated)
        try:
            os.chmod(API_KEY_FILE, 0o600)
        except OSError:
            pass
        _log(f"Generated an API key and saved it to {API_KEY_FILE}")
    except OSError as exc:
        _log(f"WARNING: could not persist the API key ({exc}); it will change on restart")
    _log(f"API key for this instance: {generated}")
    return generated


def parse_proxy(proxy_str: str) -> dict | None:
    """Split a `protocol://host:port` string into its parts."""
    try:
        parsed = urlparse(proxy_str)
        if not parsed.scheme or not parsed.hostname:
            return None
        return {
            "protocol": parsed.scheme.lower(),
            "ip": parsed.hostname,
            "port": parsed.port,
            "full": proxy_str,
            "latency": None,
            "country": None,
        }
    except ValueError:
        # urlparse raises when .port is not a valid number.
        return None


def fetch_countries(ips: list[str]) -> dict[str, str]:
    """Resolve each IP's country through ip-api.com (batch endpoint, 100 per call).

    Only queries IPs missing from `_country_cache`, so repeated runs cost almost
    nothing. Never raises: whatever fails simply has no country and shows as
    "Unknown".
    """
    known = {ip: _country_cache[ip] for ip in ips if ip in _country_cache}
    if not cfg("geolookup") or not ips:
        return known

    missing = [ip for ip in ips if ip not in _country_cache][:cfg("geolookup_max_ips")]
    batch_size = 100

    for i in range(0, len(missing), batch_size):
        batch = missing[i:i + batch_size]
        try:
            resp = requests.post(
                "http://ip-api.com/batch",
                json=[{"query": ip, "fields": "query,country"} for ip in batch],
                timeout=10,
            )
            if resp.status_code == 200:
                for item in resp.json():
                    country = item.get("country")
                    if country:
                        _country_cache[item["query"]] = country
                        known[item["query"]] = country
        except Exception as exc:
            _log(f"WARNING: country lookup failed: {exc}")

        # ip-api.com allows roughly 15 batch requests per minute.
        if i + batch_size < len(missing):
            time.sleep(4)

    return known


def latency_histogram(values: list[float], buckets: int | None = None) -> list[dict]:
    """Spread latencies into equal buckets from 0 to the latency cutoff.

    Computed server-side over **every** valid proxy: the dashboard only receives
    the fastest `dashboard_rows`, so a histogram built in the browser would be
    skewed toward the fast end of the list.
    """
    buckets = buckets or cfg("latency_buckets")
    width = cfg("max_latency_seconds") / buckets
    counts = [0] * buckets
    for v in values:
        idx = min(int(v / width), buckets - 1) if width > 0 else 0
        counts[max(0, idx)] += 1
    return [
        {"label": f"{i * width:.1f}", "upper": round((i + 1) * width, 2), "count": c}
        for i, c in enumerate(counts)
    ]


def build_snapshot(proxies: list[str], latencies: dict[str, float]) -> tuple[list[dict], dict]:
    """Build per-proxy metadata and the aggregate stats.

    Runs **outside** `_lock` on purpose: it does network I/O (country lookups,
    with sleeps between batches) and must not block HTTP requests meanwhile.
    """
    empty_stats = {
        "total": 0,
        "healthy": 0,
        "by_protocol": {},
        "by_country": {},
        "latency_buckets": latency_histogram([]),
        "avg_latency": 0,
        "min_latency": 0,
        "max_latency": 0,
    }
    if not proxies:
        return [], empty_stats

    proxy_data = []
    for p in proxies:
        parsed = parse_proxy(p)
        if parsed:
            parsed["latency"] = latencies.get(p)
            proxy_data.append(parsed)

    unique_ips = sorted({p["ip"] for p in proxy_data if p["ip"]})
    countries = fetch_countries(unique_ips)
    for p in proxy_data:
        p["country"] = countries.get(p["ip"])

    by_protocol: dict[str, int] = {}
    by_country: dict[str, int] = {}
    latency_values: list[float] = []

    for p in proxy_data:
        by_protocol[p["protocol"]] = by_protocol.get(p["protocol"], 0) + 1
        country = p.get("country") or "Unknown"
        by_country[country] = by_country.get(country, 0) + 1
        if p.get("latency") is not None:
            latency_values.append(p["latency"])

    # Fastest first; the ones with no measurement go last.
    proxy_data.sort(key=lambda p: (p["latency"] is None, p["latency"] or 0))

    stats = {
        "latency_buckets": latency_histogram(latency_values),
        "total": len(proxy_data),
        "healthy": len(proxy_data),
        "by_protocol": dict(sorted(by_protocol.items(), key=lambda kv: -kv[1])),
        "by_country": dict(sorted(by_country.items(), key=lambda kv: -kv[1])),
        "avg_latency": round(sum(latency_values) / len(latency_values), 2) if latency_values else 0,
        "min_latency": round(min(latency_values), 2) if latency_values else 0,
        "max_latency": round(max(latency_values), 2) if latency_values else 0,
    }
    return proxy_data, stats


def write_output_file(proxies: list[str]) -> None:
    """Persist the list to disk so it survives restarts."""
    try:
        if DATA_DIR:
            os.makedirs(DATA_DIR, exist_ok=True)
        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
            f.write("\n".join(proxies) + ("\n" if proxies else ""))
    except OSError as exc:
        _log(f"WARNING: could not write {OUTPUT_FILE}: {exc}")


def load_cached_proxies() -> None:
    """Load the last saved list so the dashboard has content at boot instead of
    sitting empty until the first validation finishes."""
    try:
        with open(OUTPUT_FILE, encoding="utf-8") as f:
            proxies = sorted({line.strip() for line in f if line.strip()})
    except OSError:
        return
    if not proxies:
        return

    proxy_data, stats = build_snapshot(proxies, {})
    _set_state(
        proxies=proxies,
        proxy_data=proxy_data,
        stats=stats,
        message=f"{len(proxies)} proxies loaded from the on-disk cache (awaiting validation)",
    )
    _log(f"On-disk cache loaded: {len(proxies)} proxies")


def run_validation() -> None:
    """Run the validator and publish the result. One run at a time."""
    if not _validation_lock.acquire(blocking=False):
        _log("Validation already running, trigger ignored")
        return
    try:
        started = time.perf_counter()
        _set_state(status="running", message="Validating proxies...")
        _log("Validation started")

        proxies = proxy_validator.fetch_proxies()
        if not proxies:
            raise RuntimeError("no source returned any proxy")

        latencies = proxy_validator.validate_all(
            proxies,
            proxy_validator.DEFAULT_TEST_URLS,
            cfg("max_latency_seconds"),
            cfg("validator_workers"),
        )
        valid = sorted(latencies)
        duration = round(time.perf_counter() - started, 1)

        # Country lookups and aggregation happen outside the lock (network I/O).
        proxy_data, stats = build_snapshot(valid, latencies)

        _set_state(
            proxies=valid,
            latencies=latencies,
            proxy_data=proxy_data,
            stats=stats,
            last_run=_now(),
            next_run=datetime.fromtimestamp(time.time() + cfg("interval_seconds"), timezone.utc).isoformat(),
            duration=duration,
            source_count=len(proxies),
            status="ok",
            message=f"{len(valid)} of {len(proxies)} proxies valid",
        )
        write_output_file(valid)
        _log(f"Validation finished in {duration}s: {len(valid)}/{len(proxies)} proxies valid")
    except Exception as exc:
        _set_state(status="error", message=str(exc))
        _log(f"Validation error: {exc}")
    finally:
        _validation_lock.release()


def scheduler_loop() -> None:
    """Validate immediately, then every `interval_seconds`."""
    run_validation()
    while True:
        # Re-read each pass so changing the interval from the panel applies to
        # the very next cycle, with no restart.
        time.sleep(cfg("interval_seconds"))
        run_validation()


def start_background_worker() -> None:
    """Boot sequence, run at import so it works under both `python app.py` and
    gunicorn with a single worker."""
    global _api_key
    auth_store.load()
    _api_key = load_api_key()
    app.secret_key = auth_store.secret_key
    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,   # unreachable from JS, unlike localStorage
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=SESSION_SECURE,
        PERMANENT_SESSION_LIFETIME=timedelta(days=7),
    )
    if auth_store.is_initial_password():
        _log("WARNING: dashboard password is still the initial one (admin) — change it via the padlock")

    settings_store.load()
    changed = [i["key"] for i in settings_store.describe() if i["overridden"]]
    if changed:
        _log(f"Settings overrides loaded: {', '.join(changed)}")

    # The on-disk cache is loaded even with the scheduler off, otherwise the
    # dashboard comes up empty.
    load_cached_proxies()
    if os.environ.get("DISABLE_SCHEDULER", "").lower() in ("1", "true", "yes"):
        _log("Scheduler disabled by DISABLE_SCHEDULER")
        return
    threading.Thread(target=scheduler_loop, daemon=True, name="proxy-validator").start()


def current_locale() -> str:
    """Locale for this request: explicit choice wins, browser hint as fallback."""
    chosen = request.args.get("lang") or request.cookies.get("lang")
    if chosen:
        return i18n.normalize_locale(chosen)
    return i18n.from_accept_language(request.headers.get("Accept-Language"))


# Always open, no authentication.
_PUBLIC_PATHS = {"/health", "/favicon.ico"}
# Auth routes: they must answer before a session exists.
_AUTH_PATHS = {"/api/login", "/api/auth"}
# Dashboard and the endpoint feeding it move together: either both are public,
# or both need credentials.
_DASHBOARD_PATHS = {"/", "/api/stats"}


def logged_in() -> bool:
    """Session opened from the dashboard (signed, HttpOnly cookie)."""
    return bool(session.get("logged_in"))


@app.before_request
def require_auth():
    path = request.path
    if path in _PUBLIC_PATHS or path in _AUTH_PATHS:
        return
    if PUBLIC_DASHBOARD and path in _DASHBOARD_PATHS:
        return
    # List token: plain-text list endpoints only, and only when configured.
    if LIST_TOKEN and path in LIST_TOKEN_PATHS:
        if secrets.compare_digest(request.args.get("token", ""), LIST_TOKEN):
            return
    # Two doors into the same room, on purpose: people come through the session,
    # scripts through the header. The API key never has to reach a browser.
    if logged_in():
        return
    if not secrets.compare_digest(request.headers.get("X-API-Key", ""), _api_key):
        abort(401, description="Sign in to the dashboard or send the X-API-Key header.")


@app.errorhandler(401)
def unauthorized(err):
    """JSON on 401 — the dashboard calls response.json(), and an HTML error page
    would break the parse with no useful message."""
    return jsonify({"error": "unauthorized", "message": err.description}), 401
