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
import urllib.request
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

        proxies = proxy_validator.fetch_proxies(cfg("proxy_sources"))
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


""" DASHBOARD ------------------------------------------------------------------
Aesthetic: instrument panel / amber phosphor terminal. No rounded cards on a
gradient — 1px frames, hairline rules, tabular numerals and a faint grid.

Every user-facing string comes from `i18n.py` through the `strings` template
variable, so adding a language needs no change here.
"""

DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="{{ locale }}">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PROXY//MONITOR</title>
    <link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'><rect width='32' height='32' fill='%230a0c0b'/><text y='25' x='4' font-size='22' fill='%23ffb000'>&#9679;</text></svg>">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@300;400;500;600&family=IBM+Plex+Sans+Condensed:wght@400;500;600;700&display=swap" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    <style>
        :root {
            --void: #080a09;
            --panel: #0d100f;
            --panel-hi: #121614;
            --rule: #1e2422;
            --rule-hi: #2c3532;
            --ink: #d8dedb;
            --ink-dim: #6d7a76;
            --ink-faint: #414c49;

            --amber: #ffb000;
            --amber-dim: #8a5f00;
            --teal: #3fb8a0;
            --rose: #e0607e;
            --violet: #8f7fd8;
            --red: #ff5757;

            --gap: 14px;
        }

        * { margin: 0; padding: 0; box-sizing: border-box; }

        html { background: var(--void); }

        body {
            font-family: 'IBM Plex Mono', ui-monospace, SFMono-Regular, Consolas, monospace;
            background:
                radial-gradient(1200px 600px at 15% -10%, rgba(255, 176, 0, 0.055), transparent 60%),
                repeating-linear-gradient(0deg, transparent 0 3px, rgba(0, 0, 0, 0.22) 3px 4px),
                linear-gradient(180deg, #0a0d0c 0%, var(--void) 100%);
            background-attachment: fixed;
            color: var(--ink);
            min-height: 100vh;
            font-size: 13px;
            line-height: 1.5;
            -webkit-font-smoothing: antialiased;
        }

        /* Malha técnica de fundo. */
        body::before {
            content: '';
            position: fixed;
            inset: 0;
            pointer-events: none;
            z-index: 0;
            background-image:
                linear-gradient(rgba(120, 150, 140, 0.045) 1px, transparent 1px),
                linear-gradient(90deg, rgba(120, 150, 140, 0.045) 1px, transparent 1px);
            background-size: 56px 56px;
            mask-image: radial-gradient(circle at 50% 0%, #000 0%, transparent 78%);
        }

        .shell { position: relative; z-index: 1; max-width: 1560px; margin: 0 auto; padding: 22px; }

        .label {
            font-family: 'IBM Plex Sans Condensed', sans-serif;
            text-transform: uppercase;
            letter-spacing: 0.14em;
            font-weight: 600;
            font-size: 10px;
            color: var(--ink-dim);
        }

        .num { font-variant-numeric: tabular-nums; font-feature-settings: 'tnum' 1; }

        /* ---------- Barra de topo ---------- */
        .topbar {
            display: flex;
            flex-wrap: wrap;
            align-items: stretch;
            gap: var(--gap);
            border: 1px solid var(--rule);
            background: linear-gradient(180deg, var(--panel-hi), var(--panel));
            margin-bottom: var(--gap);
        }

        .brand {
            padding: 16px 20px;
            border-right: 1px solid var(--rule);
            display: flex;
            align-items: center;
            gap: 14px;
            min-width: 300px;
            flex: 0 0 auto;
        }

        .brand h1 {
            font-family: 'IBM Plex Sans Condensed', sans-serif;
            font-size: 21px;
            font-weight: 700;
            letter-spacing: 0.06em;
            text-transform: uppercase;
            line-height: 1;
        }
        .brand h1 span { color: var(--amber); }
        .brand .tag { font-size: 10px; color: var(--ink-faint); letter-spacing: 0.1em; margin-top: 3px; }

        .led {
            width: 11px; height: 11px; border-radius: 50%;
            background: var(--ink-faint);
            box-shadow: 0 0 0 3px rgba(255, 255, 255, 0.03);
            flex: 0 0 auto;
        }
        .led[data-s="ok"] { background: var(--teal); box-shadow: 0 0 10px var(--teal), 0 0 0 3px rgba(63, 184, 160, 0.12); }
        .led[data-s="running"] { background: var(--amber); box-shadow: 0 0 10px var(--amber); animation: blink 1.05s steps(2, end) infinite; }
        .led[data-s="error"] { background: var(--red); box-shadow: 0 0 10px var(--red); animation: blink 0.55s steps(2, end) infinite; }
        @keyframes blink { 50% { opacity: 0.25; } }

        .telemetry {
            display: flex;
            flex-wrap: wrap;
            flex: 1 1 auto;
        }

        .tele {
            padding: 13px 20px;
            border-right: 1px solid var(--rule);
            min-width: 150px;
            flex: 1 1 auto;
        }
        .tele:last-child { border-right: 0; }
        .tele .v { font-size: 13px; color: var(--ink); margin-top: 3px; }
        .tele .v.accent { color: var(--amber); }

        /* ---------- Banner de erro ---------- */
        .banner {
            display: none;
            border: 1px solid rgba(255, 87, 87, 0.4);
            border-left: 3px solid var(--red);
            background: rgba(255, 87, 87, 0.07);
            color: #ffb3b3;
            padding: 11px 16px;
            margin-bottom: var(--gap);
            font-size: 12px;
        }
        .banner.show { display: block; }
        .banner::before { content: '! '; color: var(--red); font-weight: 600; }

        /* ---------- Grade principal ---------- */
        .grid {
            display: grid;
            grid-template-columns: minmax(280px, 0.9fr) minmax(300px, 1.05fr) minmax(320px, 1.25fr);
            gap: var(--gap);
            margin-bottom: var(--gap);
        }

        .panel {
            border: 1px solid var(--rule);
            background: var(--panel);
            position: relative;
            display: flex;
            flex-direction: column;
        }

        /* Cantos de mira, como marcação de instrumento. */
        .panel::after {
            content: '';
            position: absolute;
            inset: 5px;
            pointer-events: none;
            background:
                linear-gradient(var(--rule-hi), var(--rule-hi)) left top / 8px 1px no-repeat,
                linear-gradient(var(--rule-hi), var(--rule-hi)) left top / 1px 8px no-repeat,
                linear-gradient(var(--rule-hi), var(--rule-hi)) right bottom / 8px 1px no-repeat,
                linear-gradient(var(--rule-hi), var(--rule-hi)) right bottom / 1px 8px no-repeat;
        }

        .panel > header {
            display: flex;
            align-items: baseline;
            justify-content: space-between;
            gap: 10px;
            padding: 11px 16px;
            border-bottom: 1px solid var(--rule);
            background: rgba(255, 255, 255, 0.012);
        }
        .panel > header .idx { color: var(--amber-dim); font-size: 10px; letter-spacing: 0.1em; }
        .panel > .body { padding: 16px; flex: 1 1 auto; }

        /* ---------- Métrica principal ---------- */
        .hero { display: flex; align-items: flex-end; gap: 16px; }

        .hero .figure {
            font-size: clamp(52px, 7vw, 82px);
            font-weight: 300;
            line-height: 0.85;
            color: var(--amber);
            letter-spacing: -0.03em;
            text-shadow: 0 0 32px rgba(255, 176, 0, 0.22);
        }
        .hero .of { color: var(--ink-faint); font-size: 12px; padding-bottom: 6px; }
        .hero .of b { color: var(--ink-dim); font-weight: 400; }

        .ratio-track {
            height: 6px;
            background: var(--rule);
            margin: 18px 0 8px;
            display: flex;
            overflow: hidden;
        }
        .ratio-track i { display: block; height: 100%; transition: width 0.5s ease; }

        .readouts { display: grid; grid-template-columns: repeat(3, 1fr); gap: 1px; background: var(--rule); margin-top: 18px; }
        .readouts div { background: var(--panel); padding: 11px 12px; }
        .readouts .v { font-size: 19px; margin-top: 2px; font-weight: 400; }
        .readouts .v small { font-size: 10px; color: var(--ink-faint); margin-left: 2px; }

        /* ---------- Distribuição por protocolo (CSS puro) ---------- */
        .proto-list { display: flex; flex-direction: column; gap: 10px; }

        .proto-row { display: grid; grid-template-columns: 62px 1fr 62px; align-items: center; gap: 10px; }
        .proto-row .name {
            font-family: 'IBM Plex Sans Condensed', sans-serif;
            text-transform: uppercase;
            letter-spacing: 0.1em;
            font-size: 11px;
            font-weight: 600;
        }
        .proto-row .track { height: 14px; background: var(--rule); position: relative; overflow: hidden; }
        .proto-row .track i {
            position: absolute; inset: 0 auto 0 0;
            background-image: repeating-linear-gradient(135deg, currentColor 0 6px, rgba(0, 0, 0, 0.25) 6px 8px);
            transition: width 0.6s cubic-bezier(0.2, 0.8, 0.2, 1);
        }
        .proto-row .qty { text-align: right; color: var(--ink-dim); font-size: 12px; }

        .stack {
            display: flex;
            height: 26px;
            margin-bottom: 18px;
            border: 1px solid var(--rule-hi);
        }
        .stack i { display: block; transition: width 0.6s cubic-bezier(0.2, 0.8, 0.2, 1); }

        /* ---------- Gráficos ---------- */
        .chart-box { position: relative; height: 210px; }
        .chart-box.tall { height: 268px; }

        /* ---------- Tabela ---------- */
        .table-panel > header { flex-wrap: wrap; }

        .tools { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }

        input[type="search"] {
            font-family: inherit;
            font-size: 12px;
            color: var(--ink);
            background: var(--void);
            border: 1px solid var(--rule-hi);
            padding: 7px 11px;
            min-width: 210px;
            outline: none;
        }
        input[type="search"]::placeholder { color: var(--ink-faint); }
        input[type="search"]:focus { border-color: var(--amber-dim); box-shadow: inset 0 0 0 1px rgba(255, 176, 0, 0.18); }

        .chip {
            font-family: 'IBM Plex Sans Condensed', sans-serif;
            text-transform: uppercase;
            letter-spacing: 0.1em;
            font-size: 10px;
            font-weight: 600;
            color: var(--ink-dim);
            background: transparent;
            border: 1px solid var(--rule-hi);
            padding: 7px 12px;
            cursor: pointer;
            transition: color 0.15s, border-color 0.15s, background 0.15s;
        }
        .chip:hover { color: var(--ink); border-color: var(--ink-faint); }
        .chip[aria-pressed="true"] { color: var(--void); background: var(--amber); border-color: var(--amber); }
        .chip:disabled { opacity: 0.35; cursor: not-allowed; }

        select.chip {
            appearance: none;
            padding-right: 22px;
            background-image: linear-gradient(45deg, transparent 50%, var(--ink-dim) 50%),
                              linear-gradient(135deg, var(--ink-dim) 50%, transparent 50%);
            background-position: calc(100% - 12px) 50%, calc(100% - 8px) 50%;
            background-size: 4px 4px, 4px 4px;
            background-repeat: no-repeat;
        }
        select.chip option { background: var(--panel); color: var(--ink); }
        .chip:disabled:hover { color: var(--ink-dim); border-color: var(--rule-hi); }

        /* Controles de escrita: só ficam ativos com a API key guardada. */
        .tele.acoes { min-width: 210px; }
        .botoes { display: flex; gap: 6px; margin-top: 4px; flex-wrap: wrap; }
        .botoes .chip { padding: 5px 10px; font-size: 9px; }
        .chip.chave { padding: 5px 8px; font-size: 12px; line-height: 1; }

        .dica { font-size: 10px; color: var(--ink-faint); margin-top: 5px; min-height: 12px; }
        .dica.erro { color: var(--red); }
        .dica.ok { color: var(--teal); }

        .kbox {
            display: none;
            gap: 6px;
            margin-top: 6px;
            align-items: center;
        }
        .kbox.show { display: flex; }
        .kbox input {
            font-family: inherit;
            font-size: 11px;
            color: var(--ink);
            background: var(--void);
            border: 1px solid var(--rule-hi);
            padding: 5px 8px;
            width: 168px;
            outline: none;
        }
        .kbox input:focus { border-color: var(--amber-dim); }

        /* ---------- Painel de ajustes ---------- */
        /* Precisa vir antes e ter especificidade maior que `.modal`: o atributo
           hidden depende de `[hidden]{display:none}` da folha do navegador, que
           tem a mesma especificidade de `.modal` e perde por vir antes. Sem esta
           regra o painel abre sozinho no carregamento da página. */
        .modal[hidden] { display: none; }

        .modal {
            position: fixed;
            inset: 0;
            z-index: 50;
            background: rgba(4, 6, 5, 0.82);
            display: flex;
            align-items: flex-start;
            justify-content: center;
            padding: 40px 20px;
            overflow-y: auto;
            animation: fade 0.18s ease;
        }
        @keyframes fade { from { opacity: 0; } }

        .modal-box {
            background: var(--panel);
            border: 1px solid var(--rule-hi);
            width: min(880px, 100%);
            display: flex;
            flex-direction: column;
            box-shadow: 0 24px 80px rgba(0, 0, 0, 0.6);
        }

        .modal-head, .modal-foot {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 14px;
            padding: 14px 18px;
            flex-wrap: wrap;
        }
        .modal-head { border-bottom: 1px solid var(--rule); background: rgba(255,255,255,0.012); }
        .modal-foot { border-top: 1px solid var(--rule); }

        .modal-body { padding: 4px 18px 18px; }

        .cfg-grupo { margin-top: 20px; }
        .cfg-grupo > .label {
            display: block;
            padding-bottom: 7px;
            border-bottom: 1px solid var(--rule);
            color: var(--amber-dim);
        }

        .cfg-item {
            display: grid;
            grid-template-columns: 1fr 190px;
            gap: 14px;
            align-items: start;
            padding: 14px 0;
            border-bottom: 1px solid rgba(30, 36, 34, 0.55);
        }
        .cfg-item:last-child { border-bottom: 0; }

        .cfg-nome { font-size: 12px; color: var(--ink); }
        .cfg-desc { font-size: 11px; color: var(--ink-dim); margin-top: 4px; line-height: 1.55; }
        .cfg-meta { font-size: 10px; color: var(--ink-faint); margin-top: 5px; }
        .cfg-meta b { color: var(--ink-dim); font-weight: 400; }

        .cfg-tag {
            display: inline-block;
            font-family: 'IBM Plex Sans Condensed', sans-serif;
            text-transform: uppercase;
            letter-spacing: 0.08em;
            font-size: 9px;
            font-weight: 600;
            padding: 1px 6px;
            border: 1px solid var(--rule-hi);
            color: var(--ink-faint);
            margin-left: 6px;
        }
        .cfg-tag.mudado { color: var(--void); background: var(--amber); border-color: var(--amber); }
        .cfg-tag.ciclo { color: var(--teal); border-color: var(--teal); }

        .cfg-controle { display: flex; flex-direction: column; gap: 6px; align-items: stretch; }
        .cfg-controle input[type="number"] {
            font-family: inherit;
            font-size: 12px;
            color: var(--ink);
            background: var(--void);
            border: 1px solid var(--rule-hi);
            padding: 7px 10px;
            outline: none;
            width: 100%;
        }
        .cfg-controle input:focus { border-color: var(--amber-dim); }
        .cfg-controle input.invalido { border-color: var(--red); }

        .cfg-bool { display: flex; gap: 6px; }

        /* Lista de URLs: ocupa a linha inteira, porque URL de fonte é longa e
           truncar no meio esconde justamente o parâmetro que muda o resultado. */
        .cfg-item.wide { grid-template-columns: 1fr; }
        .cfg-list { display: flex; flex-direction: column; gap: 6px; margin-top: 10px; }
        .cfg-list-row { display: flex; gap: 6px; align-items: center; }
        .cfg-list-row input[type="url"] {
            flex: 1;
            font-family: inherit;
            font-size: 11px;
            color: var(--ink);
            background: var(--void);
            border: 1px solid var(--rule-hi);
            padding: 7px 10px;
            outline: none;
            min-width: 0;
        }
        .cfg-list-row input:focus { border-color: var(--amber-dim); }
        .cfg-list-row input.invalido { border-color: var(--red); }
        .cfg-list-row .chip { flex: 0 0 auto; padding: 6px 10px; font-size: 9px; }
        .cfg-list-msg { font-size: 10px; color: var(--ink-faint); padding-left: 2px; min-height: 12px; }
        .cfg-list-msg.ok { color: var(--teal); }
        .cfg-list-msg.erro { color: var(--red); }
        .cfg-list-actions { display: flex; gap: 6px; margin-top: 4px; }
        .cfg-bool .chip { flex: 1; padding: 7px 4px; font-size: 9px; }

        .cfg-restaurar {
            background: none;
            border: 0;
            color: var(--ink-faint);
            font-family: inherit;
            font-size: 10px;
            cursor: pointer;
            text-align: right;
            padding: 0;
        }
        .cfg-restaurar:hover { color: var(--amber); }
        .cfg-restaurar[hidden] { display: none; }

        .senha-box { border-top: 1px solid var(--rule); padding-top: 0; }
        .senha-box .cfg-grupo { margin-top: 14px; }
        .cfg-controle input[type="password"] {
            font-family: inherit;
            font-size: 12px;
            color: var(--ink);
            background: var(--void);
            border: 1px solid var(--rule-hi);
            padding: 7px 10px;
            outline: none;
            width: 100%;
        }
        .cfg-controle input[type="password"]:focus { border-color: var(--amber-dim); }

        .chip.acao { color: var(--void); background: var(--amber); border-color: var(--amber); }
        .chip.acao:disabled { background: transparent; color: var(--ink-dim); border-color: var(--rule-hi); }

        @media (max-width: 620px) {
            .cfg-item { grid-template-columns: 1fr; }
            .modal { padding: 12px; }
        }

        .table-scroll { overflow: auto; max-height: 620px; }

        table { width: 100%; border-collapse: collapse; }

        thead th {
            position: sticky;
            top: 0;
            z-index: 2;
            background: var(--panel-hi);
            border-bottom: 1px solid var(--rule-hi);
            font-family: 'IBM Plex Sans Condensed', sans-serif;
            text-transform: uppercase;
            letter-spacing: 0.12em;
            font-size: 10px;
            font-weight: 600;
            color: var(--ink-dim);
            text-align: left;
            padding: 9px 12px;
            white-space: nowrap;
        }
        thead th.r { text-align: right; }

        tbody td {
            padding: 7px 12px;
            border-bottom: 1px solid rgba(30, 36, 34, 0.65);
            font-size: 12px;
            white-space: nowrap;
        }
        tbody td.r { text-align: right; }
        tbody tr { transition: background 0.12s; }
        tbody tr:hover { background: rgba(255, 176, 0, 0.05); }
        tbody tr:hover td:first-child { box-shadow: inset 2px 0 0 var(--amber); }

        .rank { color: var(--ink-faint); font-size: 11px; }
        .host { color: var(--ink); }
        .port { color: var(--ink-dim); }
        .geo { color: var(--ink-dim); }

        .proto {
            font-family: 'IBM Plex Sans Condensed', sans-serif;
            text-transform: uppercase;
            letter-spacing: 0.09em;
            font-size: 10px;
            font-weight: 700;
            padding: 2px 7px;
            border: 1px solid currentColor;
        }

        /* Barra de latência embutida na célula. */
        .lat { display: inline-flex; align-items: center; gap: 8px; justify-content: flex-end; width: 100%; }
        .lat .bar { width: 54px; height: 3px; background: var(--rule); position: relative; }
        .lat .bar i { position: absolute; inset: 0 auto 0 0; background: currentColor; }
        .lat .val { min-width: 50px; text-align: right; }

        .empty { text-align: center; padding: 46px 16px; color: var(--ink-faint); font-size: 12px; }
        .empty::after { content: '_'; animation: caret 1.1s steps(2, end) infinite; }
        @keyframes caret { 50% { opacity: 0; } }

        footer.foot {
            display: flex;
            flex-wrap: wrap;
            justify-content: space-between;
            gap: 10px;
            border: 1px solid var(--rule);
            border-top: 0;
            padding: 11px 16px;
            color: var(--ink-faint);
            font-size: 11px;
        }
        footer.foot code { color: var(--ink-dim); }

        /* Entrada escalonada dos painéis. */
        .rise { opacity: 0; transform: translateY(9px); animation: rise 0.5s cubic-bezier(0.2, 0.8, 0.2, 1) forwards; }
        @keyframes rise { to { opacity: 1; transform: none; } }
        .d1 { animation-delay: 0.04s; } .d2 { animation-delay: 0.10s; }
        .d3 { animation-delay: 0.16s; } .d4 { animation-delay: 0.22s; }

        @media (prefers-reduced-motion: reduce) {
            .rise { animation: none; opacity: 1; transform: none; }
            .led { animation: none !important; }
        }

        @media (max-width: 1180px) { .grid { grid-template-columns: 1fr 1fr; } .grid .panel:first-child { grid-column: 1 / -1; } }
        @media (max-width: 760px) {
            .shell { padding: 12px; }
            .grid { grid-template-columns: 1fr; }
            .grid .panel:first-child { grid-column: auto; }
            .brand { min-width: 0; border-right: 0; border-bottom: 1px solid var(--rule); width: 100%; }
            .readouts { grid-template-columns: 1fr; }
        }
    </style>
</head>
<body>
<div class="shell">

    <div class="topbar rise">
        <div class="brand">
            <span class="led" id="led" data-s="idle"></span>
            <div>
                <h1>PROXY<span>//</span>MONITOR</h1>
                <div class="tag num" id="brand-tag"></div>
            </div>
        </div>
        <div class="telemetry">
            <div class="tele">
                <div class="label" data-t="state"></div>
                <div class="v" id="t-status">&mdash;</div>
            </div>
            <div class="tele">
                <div class="label" data-t="last_scan"></div>
                <div class="v num" id="t-last">&mdash;</div>
            </div>
            <div class="tele">
                <div class="label" data-t="duration"></div>
                <div class="v num" id="t-duration">&mdash;</div>
            </div>
            <div class="tele">
                <div class="label" data-t="next_cycle"></div>
                <div class="v num accent" id="t-next">&mdash;</div>
            </div>
            <div class="tele acoes">
                <div class="label" data-t="controls"></div>
                <div class="botoes">
                    <button class="chip" id="btn-refresh" type="button" disabled></button>
                    <button class="chip" id="btn-config" type="button" disabled></button>
                    <button class="chip chave" id="btn-lock" type="button">&#128274;</button>
                </div>
                <div class="kbox" id="kbox">
                    <input type="password" id="k-input" autocomplete="current-password">
                    <button class="chip" id="k-submit" type="button"></button>
                </div>
                <div class="dica" id="action-msg"></div>
            </div>
        </div>
    </div>

    <div class="banner" id="banner"></div>

    <div class="grid">
        <section class="panel rise d1">
            <header>
                <span class="label" data-t="panel_operational"></span>
                <span class="idx">01</span>
            </header>
            <div class="body">
                <div class="hero">
                    <div class="figure num" id="m-total">&mdash;</div>
                    <div class="of" id="m-of"></div>
                </div>
                <div class="ratio-track"><i id="m-ratio" style="width:0;background:var(--amber)"></i></div>
                <div class="label num" id="m-rate"></div>
                <div class="readouts">
                    <div><div class="label" data-t="min"></div><div class="v num" id="m-min">0<small>s</small></div></div>
                    <div><div class="label" data-t="avg"></div><div class="v num" id="m-avg" style="color:var(--amber)">0<small>s</small></div></div>
                    <div><div class="label" data-t="max"></div><div class="v num" id="m-max">0<small>s</small></div></div>
                </div>
            </div>
        </section>

        <section class="panel rise d2">
            <header>
                <span class="label" data-t="panel_protocols"></span>
                <span class="idx">02</span>
            </header>
            <div class="body">
                <div class="stack" id="proto-stack"></div>
                <div class="proto-list" id="proto-list"></div>
            </div>
        </section>

        <section class="panel rise d3">
            <header>
                <span class="label" data-t="panel_latency"></span>
                <span class="idx">03</span>
            </header>
            <div class="body"><div class="chart-box"><canvas id="latencyChart"></canvas></div></div>
        </section>
    </div>

    <div class="grid" style="grid-template-columns: minmax(300px, 1fr) minmax(420px, 2.1fr);">
        <section class="panel rise d3">
            <header>
                <span class="label" data-t="panel_geo"></span>
                <span class="idx">04</span>
            </header>
            <div class="body"><div class="chart-box tall"><canvas id="countryChart"></canvas></div></div>
        </section>

        <section class="panel table-panel rise d4">
            <header>
                <span class="label"><span data-t="panel_nodes"></span>
                    <span class="num" id="tbl-count" style="color:var(--ink-faint)"></span></span>
                <div class="tools">
                    <input type="search" id="filter" autocomplete="off">
                    <button class="chip" id="chip-fast" type="button" aria-pressed="false"></button>
                    <button class="chip" id="chip-copy" type="button"></button>
                </div>
            </header>
            <div class="table-scroll">
                <table>
                    <thead>
                        <tr>
                            <th style="width:46px">#</th>
                            <th style="width:86px" data-t="col_proto"></th>
                            <th data-t="col_host"></th>
                            <th class="r" style="width:74px" data-t="col_port"></th>
                            <th class="r" style="width:132px" data-t="col_latency"></th>
                            <th style="width:160px" data-t="col_country"></th>
                        </tr>
                    </thead>
                    <tbody id="rows"></tbody>
                </table>
            </div>
        </section>
    </div>

    <div class="modal" id="cfg-modal" hidden>
        <div class="modal-box" role="dialog" aria-modal="true" aria-labelledby="cfg-title">
            <header class="modal-head">
                <div>
                    <span class="label" id="cfg-title"></span>
                    <div class="dica" id="cfg-subtitle"></div>
                </div>
                <div class="tools">
                    <select id="lang-select" class="chip" aria-label="language"></select>
                    <button class="chip" id="cfg-reset-all" type="button"></button>
                    <button class="chip" id="cfg-close" type="button"></button>
                </div>
            </header>
            <div class="modal-body" id="cfg-body"></div>
            <div class="modal-body senha-box">
                <section class="cfg-grupo">
                    <span class="label" id="pw-group"></span>
                    <div class="cfg-item">
                        <div>
                            <div class="cfg-nome"><span data-t="password_label"></span><span class="cfg-tag" id="pw-warn" hidden></span></div>
                            <div class="cfg-desc" data-t="password_description"></div>
                            <div class="cfg-meta" id="pw-msg"></div>
                        </div>
                        <div class="cfg-controle">
                            <input type="password" id="pw-current" autocomplete="current-password">
                            <input type="password" id="pw-new" autocomplete="new-password">
                            <button class="chip" id="pw-change" type="button"></button>
                        </div>
                    </div>
                </section>
            </div>
            <footer class="modal-foot">
                <span class="dica" id="cfg-msg"></span>
                <button class="chip acao" id="cfg-save" type="button" disabled></button>
            </footer>
        </div>
    </div>

    <footer class="foot">
        <p id="foot-routes"></p>
        <p class="num" id="foot-sync"></p>
    </footer>
</div>

<script>
    // Every string comes from the server catalog, so adding a language never
    // touches this file.
    const S = {{ strings|safe }};
    const LANGUAGES = {{ languages|safe }};
    const LOCALE = "{{ locale }}";
    const MAX_LATENCY = Number("{{ max_latency }}") || 5;
    const INTERVAL_MIN = Number("{{ interval_min }}") || 20;

    const REFRESH_MS = 30000;
    const ACTION_TIMEOUT_MS = 15000;
    const KNOWN_PROTOCOLS = ['http', 'https', 'socks4', 'socks5'];
    const $ = (id) => document.getElementById(id);

    /** Interpolate {name} placeholders in a catalog string. */
    function t(key, vars) {
        let out = S[key] || key;
        if (vars) for (const k in vars) out = out.split('{' + k + '}').join(vars[k]);
        return out;
    }

    function esc(value) {
        const div = document.createElement('div');
        div.textContent = value === null || value === undefined ? '' : String(value);
        return div.innerHTML;
    }

    /** Fill every element carrying data-t with its translation. */
    function applyStaticStrings() {
        document.querySelectorAll('[data-t]').forEach((el) => {
            el.textContent = t(el.getAttribute('data-t'));
        });
        $('brand-tag').textContent = t('tagline', { latency: MAX_LATENCY, interval: INTERVAL_MIN });
        $('filter').placeholder = t('filter_placeholder');
        $('k-input').placeholder = t('password_placeholder');
        $('k-submit').textContent = t('sign_in');
        $('chip-fast').textContent = t('under_1s');
        $('chip-copy').textContent = t('copy');
        $('btn-config').textContent = t('settings');
        $('btn-refresh').textContent = t('refresh');
        $('cfg-title').textContent = t('settings_title');
        $('cfg-subtitle').textContent = t('settings_subtitle');
        $('cfg-reset-all').textContent = t('reset_all');
        $('cfg-close').textContent = t('close');
        $('cfg-save').textContent = t('save');
        $('pw-group').textContent = t('security_group');
        $('pw-current').placeholder = t('current_password');
        $('pw-new').placeholder = t('new_password');
        $('pw-change').textContent = t('change_password');
        $('foot-routes').innerHTML = t('footer_full_list', {
            routes: '<code>/proxy/all</code>, <code>/proxy/all.txt</code>',
            header: '<code>X-API-Key</code>',
        });

        const sel = $('lang-select');
        sel.innerHTML = '';
        for (const code in LANGUAGES) {
            const opt = document.createElement('option');
            opt.value = code;
            opt.textContent = LANGUAGES[code];
            if (code === LOCALE) opt.selected = true;
            sel.appendChild(opt);
        }
    }

    $('lang-select').addEventListener('change', (e) => {
        // Reload with the choice; the server remembers it in a cookie.
        location.search = '?lang=' + encodeURIComponent(e.target.value);
    });

    // --- Session ----------------------------------------------------------
    // Reading is open; writing needs a login. The session is a signed, HttpOnly
    // cookie issued by the server — no credential kept where scripts can read it.
    let sessionActive = false;
    let initialPassword = false;

    function hint(text, cls) {
        const el = $('action-msg');
        el.textContent = text;
        el.className = 'dica' + (cls ? ' ' + cls : '');
    }

    function applyLockState() {
        $('btn-config').disabled = !sessionActive;
        $('btn-refresh').disabled = !sessionActive;
        $('btn-lock').textContent = sessionActive ? '\\u{1F513}' : '\\u{1F512}';
        $('btn-lock').title = sessionActive ? t('lock_open') : t('lock_closed');
        if (!sessionActive) hint(t('read_only'), '');
        else if (initialPassword) hint(t('default_password_warning'), 'erro');
        else hint('', '');
    }

    async function readSession() {
        try {
            const r = await fetch('/api/auth', { headers: { 'Accept': 'application/json' } });
            if (r.ok) {
                const d = await r.json();
                sessionActive = Boolean(d.logged_in);
                initialPassword = Boolean(d.initial_password);
            }
        } catch (e) { /* offline: keep whatever we had */ }
        applyLockState();
    }

    async function signIn(password) {
        try {
            const r = await fetch('/api/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ password: password }),
            });
            const d = await r.json().catch(() => ({}));
            if (r.ok) {
                sessionActive = true;
                initialPassword = Boolean(d.initial_password);
                $('kbox').classList.remove('show');
                $('k-input').value = '';
                applyLockState();
                return true;
            }
            hint(d.message || d.error || t('load_failed'), 'erro');
        } catch (err) {
            hint(t('network_failure', { error: err.message }), 'erro');
        }
        return false;
    }

    async function signOut() {
        try { await fetch('/api/logout', { method: 'POST' }); } catch (e) { /* ignore */ }
        sessionActive = false;
        applyLockState();
        if (!$('cfg-modal').hidden) closeCfg();
    }

    async function action(url, options) {
        if (!sessionActive) { hint(t('lock_closed'), 'erro'); return null; }
        // fetch has no timeout of its own: without this, a server that accepts
        // the connection and never answers leaves the UI waiting forever.
        const ctl = new AbortController();
        const timer = setTimeout(() => ctl.abort(), ACTION_TIMEOUT_MS);
        try {
            const res = await fetch(url, Object.assign({
                signal: ctl.signal,
                credentials: 'same-origin',
                headers: { 'Content-Type': 'application/json' },
            }, options || {}));

            // A non-JSON body is a failure, not an empty object: 200 with HTML
            // happens when a reverse proxy answers during a restart, and
            // treating it as success left the panel stuck on "loading".
            let body = null;
            try { body = await res.json(); } catch (err) { body = null; }

            if (res.status === 401) {
                sessionActive = false;
                applyLockState();
                hint(t('session_expired'), 'erro');
                return null;
            }
            if (!res.ok) {
                const detail = body ? (body.message || body.error) : null;
                hint(detail || ('HTTP ' + res.status), 'erro');
                return null;
            }
            if (body === null || typeof body !== 'object') {
                hint(t('unexpected_response'), 'erro');
                return null;
            }
            return body;
        } catch (err) {
            const msg = err.name === 'AbortError'
                ? t('timeout', { seconds: ACTION_TIMEOUT_MS / 1000 })
                : t('network_failure', { error: err.message });
            console.error('[proxy-monitor] ' + ((options && options.method) || 'GET') + ' ' + url, err);
            hint(msg, 'erro');
            return null;
        } finally {
            clearTimeout(timer);
        }
    }

    $('btn-lock').addEventListener('click', async () => {
        if (sessionActive) { await signOut(); hint(t('session_ended'), ''); return; }
        const box = $('kbox');
        box.classList.toggle('show');
        if (box.classList.contains('show')) $('k-input').focus();
    });
    $('k-submit').addEventListener('click', async () => {
        const v = $('k-input').value;
        if (!v) { hint(t('enter_password'), 'erro'); return; }
        await signIn(v);
    });
    $('k-input').addEventListener('keydown', (e) => { if (e.key === 'Enter') $('k-submit').click(); });

    $('btn-refresh').addEventListener('click', async () => {
        const r = await action('/api/refresh', { method: 'POST' });
        if (r) { hint(r.message || '', 'ok'); poll(); }
    });

    // --- Settings panel ---------------------------------------------------
    let cfgCurrent = [];
    let cfgPending = {};

    function cfgMsg(text, cls) {
        const el = $('cfg-msg');
        el.textContent = text;
        el.className = 'dica' + (cls ? ' ' + cls : '');
    }

    function markPending() {
        const n = Object.keys(cfgPending).length;
        $('cfg-save').disabled = n === 0;
        $('cfg-save').textContent = n ? t('save') + ' (' + n + ')' : t('save');
    }

    function stage(key, value) {
        const def = cfgCurrent.find((a) => a.key === key);
        if (!def) return;
        if (String(value) === String(def.value)) delete cfgPending[key];
        else cfgPending[key] = value;
        markPending();
    }

    function cfgFailed(text) {
        const body = $('cfg-body');
        body.innerHTML = '';
        const box = document.createElement('div');
        box.className = 'empty';
        box.textContent = text;
        body.appendChild(box);
        const wrap = document.createElement('div');
        wrap.style.textAlign = 'center';
        const b = document.createElement('button');
        b.className = 'chip';
        b.type = 'button';
        b.textContent = t('try_again');
        b.addEventListener('click', openCfg);
        wrap.appendChild(b);
        body.appendChild(wrap);
    }

    function renderCfg(list) {
        // Never trust the shape: anything but a list would blow up the forEach
        // below with the screen still on "loading", and no way out.
        if (!Array.isArray(list)) {
            cfgFailed(t('unexpected_response'));
            return;
        }
        cfgCurrent = list;
        cfgPending = {};
        markPending();

        const groups = [];
        list.forEach((a) => {
            let g = groups.find((x) => x.name === a.group);
            if (!g) { g = { name: a.group, items: [] }; groups.push(g); }
            g.items.push(a);
        });

        const body = $('cfg-body');
        body.innerHTML = '';

        groups.forEach((g) => {
            const sec = document.createElement('section');
            sec.className = 'cfg-grupo';
            const h = document.createElement('span');
            h.className = 'label';
            h.textContent = g.name;
            sec.appendChild(h);

            g.items.forEach((a) => {
                const row = document.createElement('div');
                row.className = 'cfg-item';

                const info = document.createElement('div');
                const name = document.createElement('div');
                name.className = 'cfg-nome';
                name.textContent = a.label;
                if (a.overridden) {
                    const tag = document.createElement('span');
                    tag.className = 'cfg-tag mudado';
                    tag.textContent = t('tag_changed');
                    name.appendChild(tag);
                }
                if (a.effect === 'next_cycle') {
                    const tag = document.createElement('span');
                    tag.className = 'cfg-tag ciclo';
                    tag.textContent = t('tag_next_cycle');
                    tag.title = t('tag_next_cycle_title');
                    name.appendChild(tag);
                }
                info.appendChild(name);

                const desc = document.createElement('div');
                desc.className = 'cfg-desc';
                desc.textContent = a.description;
                info.appendChild(desc);

                const meta = document.createElement('div');
                meta.className = 'cfg-meta';
                const parts = [];
                if (a.minimum !== null && a.minimum !== undefined) {
                    parts.push(t('range', { min: a.minimum, max: a.maximum }) + (a.unit ? ' ' + a.unit : ''));
                }
                parts.push(t('default_is', { value: a.default }));
                parts.push(t('env_is', { name: a.env }));
                meta.textContent = parts.join(' \\u00b7 ');
                info.appendChild(meta);
                row.appendChild(info);

                const ctrl = document.createElement('div');
                ctrl.className = 'cfg-controle';

                if (a.type === 'list') {
                    // Full width: source URLs are long, and truncating them hides
                    // the query parameter that decides what the source returns.
                    row.classList.add('wide');
                    ctrl.className = 'cfg-list';
                    const values = Array.isArray(a.value) ? a.value.slice() : [];

                    // Same contract as the numeric inputs: an invalid entry blocks
                    // saving instead of letting the server reject it after the click.
                    const commit = () => {
                        const inputs = [...ctrl.querySelectorAll('input[type=url]')];
                        const urls = inputs.map((i) => i.value.trim()).filter(Boolean);
                        const anyInvalid = inputs.some((i) => i.classList.contains('invalido'));
                        if (anyInvalid || urls.length === 0) {
                            delete cfgPending[a.key];
                            markPending();
                            return;
                        }
                        stage(a.key, urls);
                    };

                    const addRow = (url) => {
                        const line = document.createElement('div');
                        line.className = 'cfg-list-row';

                        const inp = document.createElement('input');
                        inp.type = 'url';
                        inp.value = url || '';
                        inp.placeholder = t('source_url_placeholder');
                        inp.addEventListener('input', () => {
                            const v = inp.value.trim();
                            inp.classList.toggle('invalido', Boolean(v) && !/^https?:[/][/].+/i.test(v));
                            commit();
                        });

                        const test = document.createElement('button');
                        test.className = 'chip';
                        test.type = 'button';
                        test.textContent = t('test_source');

                        const msg = document.createElement('div');
                        msg.className = 'cfg-list-msg';

                        test.addEventListener('click', async () => {
                            const v = inp.value.trim();
                            if (!v) return;
                            test.disabled = true;
                            msg.className = 'cfg-list-msg';
                            msg.textContent = t('testing');
                            const r = await action('/api/settings/test-source', {
                                method: 'POST', body: JSON.stringify({ url: v }),
                            });
                            test.disabled = false;
                            if (!r) { msg.className = 'cfg-list-msg erro'; msg.textContent = t('load_failed'); return; }
                            if (r.ok) {
                                const types = Object.entries(r.by_type)
                                    .map(([k, n]) => k + ' ' + n).join(', ');
                                msg.className = 'cfg-list-msg ok';
                                msg.textContent = t('source_ok', { found: r.found, types: types });
                            } else if (r.error) {
                                msg.className = 'cfg-list-msg erro';
                                msg.textContent = t('source_failed', { error: r.error });
                            } else {
                                msg.className = 'cfg-list-msg erro';
                                msg.textContent = t('source_empty', { lines: r.lines });
                            }
                        });

                        const del = document.createElement('button');
                        del.className = 'chip';
                        del.type = 'button';
                        del.textContent = t('remove_source');
                        del.addEventListener('click', () => {
                            wrap.remove();
                            commit();
                        });

                        line.appendChild(inp);
                        line.appendChild(test);
                        line.appendChild(del);

                        const wrap = document.createElement('div');
                        wrap.appendChild(line);
                        wrap.appendChild(msg);
                        ctrl.insertBefore(wrap, actions);
                    };

                    const actions = document.createElement('div');
                    actions.className = 'cfg-list-actions';
                    const add = document.createElement('button');
                    add.className = 'chip';
                    add.type = 'button';
                    add.textContent = t('add_source');
                    add.addEventListener('click', () => { addRow(''); commit(); });
                    actions.appendChild(add);
                    ctrl.appendChild(actions);

                    values.forEach(addRow);
                } else if (a.type === 'bool') {
                    const box = document.createElement('div');
                    box.className = 'cfg-bool';
                    [[t('on'), true], [t('off'), false]].forEach(([label, val]) => {
                        const b = document.createElement('button');
                        b.type = 'button';
                        b.className = 'chip';
                        b.textContent = label;
                        const mark = () => {
                            const now = (cfgPending[a.key] !== undefined) ? cfgPending[a.key] : a.value;
                            box.querySelectorAll('.chip').forEach((c, i) => {
                                c.setAttribute('aria-pressed', (i === 0) === Boolean(now) ? 'true' : 'false');
                            });
                        };
                        b.addEventListener('click', () => { stage(a.key, val); mark(); });
                        box.appendChild(b);
                        setTimeout(mark, 0);
                    });
                    ctrl.appendChild(box);
                } else {
                    const inp = document.createElement('input');
                    inp.type = 'number';
                    inp.value = a.value;
                    inp.step = a.type === 'float' ? '0.5' : '1';
                    if (a.minimum !== null) inp.min = a.minimum;
                    if (a.maximum !== null) inp.max = a.maximum;
                    inp.addEventListener('input', () => {
                        const n = Number(inp.value);
                        const bad = inp.value === '' || Number.isNaN(n) ||
                            (a.minimum !== null && n < a.minimum) || (a.maximum !== null && n > a.maximum);
                        inp.classList.toggle('invalido', bad);
                        if (bad) { delete cfgPending[a.key]; markPending(); return; }
                        stage(a.key, n);
                    });
                    ctrl.appendChild(inp);
                }

                const reset = document.createElement('button');
                reset.className = 'cfg-restaurar';
                reset.type = 'button';
                reset.textContent = t('back_to_default');
                reset.hidden = !a.overridden;
                reset.addEventListener('click', async () => {
                    const r = await action('/api/settings/reset', {
                        method: 'POST', body: JSON.stringify({ key: a.key }),
                    });
                    if (r) { renderCfg(r.settings); cfgMsg(t('reset_one', { label: a.label }), 'ok'); poll(); }
                });
                ctrl.appendChild(reset);
                row.appendChild(ctrl);
                sec.appendChild(row);
            });
            body.appendChild(sec);
        });
    }

    async function openCfg() {
        $('cfg-modal').hidden = false;
        cfgMsg('', '');
        pwMsg('', '');
        $('pw-current').value = '';
        $('pw-new').value = '';
        $('pw-warn').hidden = !initialPassword;
        $('pw-warn').textContent = t('tag_initial_password');
        $('pw-warn').classList.toggle('mudado', initialPassword);
        $('cfg-body').innerHTML = '<div class="empty">' + esc(t('loading')) + '</div>';
        try {
            const r = await action('/api/settings', { method: 'GET' });
            if (!r) { cfgFailed(t('load_failed')); return; }
            renderCfg(r.settings);
        } catch (err) {
            // Without this, an exception in the render left the panel stuck on
            // "loading" forever, with no message and no way out.
            console.error('[proxy-monitor] settings panel', err);
            cfgFailed(t('build_failed', { error: err.message }));
        }
    }

    function closeCfg() { $('cfg-modal').hidden = true; }

    $('btn-config').addEventListener('click', openCfg);
    $('cfg-close').addEventListener('click', closeCfg);
    $('cfg-modal').addEventListener('click', (e) => { if (e.target === $('cfg-modal')) closeCfg(); });
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape' && !$('cfg-modal').hidden) closeCfg();
    });

    $('cfg-save').addEventListener('click', async () => {
        const btn = $('cfg-save');
        btn.disabled = true;
        cfgMsg(t('saving'), '');
        const r = await action('/api/settings', {
            method: 'POST', body: JSON.stringify({ settings: cfgPending }),
        });
        if (r) {
            renderCfg(r.settings);
            cfgMsg(r.persisted ? t('saved') : (r.warning || t('saved_memory_only')),
                   r.persisted ? 'ok' : 'erro');
            poll();
        } else {
            markPending();
        }
    });

    $('cfg-reset-all').addEventListener('click', async () => {
        const r = await action('/api/settings/reset', { method: 'POST', body: JSON.stringify({}) });
        if (r) { renderCfg(r.settings); cfgMsg(t('reset_done'), 'ok'); poll(); }
    });

    function pwMsg(text, cls) {
        const el = $('pw-msg');
        el.textContent = text;
        el.className = 'cfg-meta';
        el.style.color = cls === 'erro' ? 'var(--red)' : cls === 'ok' ? 'var(--teal)' : '';
    }

    $('pw-change').addEventListener('click', async () => {
        const current = $('pw-current').value;
        const next = $('pw-new').value;
        if (!current || !next) { pwMsg(t('fill_both'), 'erro'); return; }

        const btn = $('pw-change');
        btn.disabled = true;
        pwMsg(t('changing'), '');
        try {
            const r = await fetch('/api/password', {
                method: 'POST',
                credentials: 'same-origin',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ current: current, new: next }),
            });
            const d = await r.json().catch(() => ({}));
            if (r.ok) {
                pwMsg(t('password_changed'), 'ok');
                $('pw-current').value = '';
                $('pw-new').value = '';
                initialPassword = Boolean(d.initial_password);
                $('pw-warn').hidden = !initialPassword;
                applyLockState();
            } else {
                pwMsg(d.error || ('HTTP ' + r.status), 'erro');
            }
        } catch (err) {
            pwMsg(t('network_failure', { error: err.message }), 'erro');
        }
        btn.disabled = false;
    });

    // --- Live data --------------------------------------------------------
    let latencyChart = null;
    let countryChart = null;
    let allProxies = [];

    function fmtClock(iso) {
        if (!iso) return null;
        const d = new Date(iso);
        if (isNaN(d.getTime())) return null;
        return d.toLocaleTimeString(LOCALE, { hour: '2-digit', minute: '2-digit' }) +
               ' ' + d.toLocaleDateString(LOCALE, { day: '2-digit', month: '2-digit' });
    }

    function showBanner(msg) {
        const b = $('banner');
        b.textContent = msg;
        b.classList.toggle('show', Boolean(msg));
    }

    async function poll() {
        try {
            const res = await fetch('/api/stats', { headers: { 'Accept': 'application/json' } });
            if (!res.ok) throw new Error('HTTP ' + res.status + ' on /api/stats');
            render(await res.json());
        } catch (err) {
            console.error('[proxy-monitor] /api/stats', err);
            showBanner(t('network_failure', { error: err.message }));
            $('led').dataset.s = 'error';
        }
    }

    function getVar(name) {
        return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
    }

    function colorFor(proto, i) {
        const palette = { http: getVar('--amber'), https: getVar('--teal'),
                          socks5: getVar('--violet'), socks4: getVar('--rose') };
        const fallback = ['#7f8c8a', '#c9a227', '#4d90c8'];
        return palette[proto] || fallback[i % fallback.length];
    }

    function render(data) {
        const st = data.stats || {};
        const labels = {
            ok: t('status_ok'), running: t('status_running'),
            error: t('status_error'), idle: t('status_idle'),
        };
        $('led').dataset.s = data.status || 'idle';
        $('t-status').textContent = labels[data.status] || String(data.status || '').toUpperCase();
        $('t-last').textContent = fmtClock(data.last_run) || t('never');
        $('t-duration').textContent = data.duration ? data.duration + 's' : '\\u2014';
        $('t-next').textContent = fmtClock(data.next_run) || '\\u2014';

        showBanner(data.status === 'error' && data.message ? data.message : '');

        const total = st.total || 0;
        const source = data.source_count || 0;
        $('m-total').textContent = total.toLocaleString(LOCALE);
        $('m-of').textContent = source ? t('of_tested', { count: source.toLocaleString(LOCALE) }) : '';

        const rate = source ? (total / source) * 100 : 0;
        $('m-ratio').style.width = Math.min(100, rate) + '%';
        $('m-rate').textContent = source
            ? t('pass_rate', { rate: rate.toFixed(1) })
            : (data.message || t('awaiting_scan'));

        $('m-min').innerHTML = (st.min_latency || 0) + '<small>s</small>';
        $('m-avg').innerHTML = (st.avg_latency || 0) + '<small>s</small>';
        $('m-max').innerHTML = (st.max_latency || 0) + '<small>s</small>';

        renderProtocols(st.by_protocol || {});
        renderLatency(st.latency_buckets || []);
        renderCountries(st.by_country || {});

        allProxies = data.proxies || [];
        renderTable();

        $('foot-sync').textContent = t('footer_sync', {
            time: new Date().toLocaleTimeString(LOCALE), seconds: REFRESH_MS / 1000,
        });
    }

    function renderProtocols(byProtocol) {
        const entries = Object.entries(byProtocol);
        const stack = $('proto-stack');
        const list = $('proto-list');
        if (!entries.length) {
            stack.innerHTML = '';
            list.innerHTML = '<div class="empty">' + esc(t('waiting_data')) + '</div>';
            return;
        }
        const sum = entries.reduce((acc, [, n]) => acc + n, 0) || 1;
        const biggest = Math.max(...entries.map(([, n]) => n));

        stack.innerHTML = entries.map(([proto, n], i) =>
            '<i style="width:' + (n / sum * 100) + '%;background:' + colorFor(proto, i) + '"></i>').join('');

        list.innerHTML = entries.map(([proto, n], i) => {
            const color = colorFor(proto, i);
            return '<div class="proto-row">' +
                '<span class="name" style="color:' + color + '">' + esc(proto) + '</span>' +
                '<span class="track"><i style="width:' + (n / biggest * 100) + '%;color:' + color + '"></i></span>' +
                '<span class="qty num">' + n + ' &middot; ' + (n / sum * 100).toFixed(1) + '%</span>' +
                '</div>';
        }).join('');
    }

    const CHART_GRID = 'rgba(120, 150, 140, 0.09)';
    const CHART_TICK = { color: '#6d7a76', font: { family: 'IBM Plex Mono', size: 10 } };
    const TOOLTIP = {
        backgroundColor: '#0d100f', borderColor: '#2c3532', borderWidth: 1,
        titleFont: { family: 'IBM Plex Mono', size: 11 },
        bodyFont: { family: 'IBM Plex Mono', size: 11 },
        padding: 9, displayColors: false,
    };

    function renderLatency(buckets) {
        if (latencyChart) latencyChart.destroy();
        latencyChart = new Chart($('latencyChart').getContext('2d'), {
            type: 'bar',
            data: {
                labels: buckets.map((b) => b.label),
                datasets: [{
                    data: buckets.map((b) => b.count),
                    backgroundColor: buckets.map((b, i) =>
                        'rgba(255, 176, 0, ' + (0.85 - (i / Math.max(1, buckets.length)) * 0.55).toFixed(2) + ')'),
                    borderWidth: 0, borderSkipped: false,
                }],
            },
            options: {
                responsive: true, maintainAspectRatio: false,
                plugins: {
                    legend: { display: false },
                    tooltip: Object.assign({}, TOOLTIP, {
                        callbacks: {
                            title: (items) => {
                                const b = buckets[items[0].dataIndex];
                                return b.label + 's \\u2013 ' + b.upper + 's';
                            },
                            label: (item) => item.parsed.y + ' proxies',
                        },
                    }),
                },
                scales: {
                    x: { grid: { display: false }, border: { color: '#1e2422' },
                         ticks: Object.assign({}, CHART_TICK, { maxRotation: 0, autoSkipPadding: 12 }) },
                    y: { beginAtZero: true, grid: { color: CHART_GRID }, border: { display: false },
                         ticks: Object.assign({}, CHART_TICK, { precision: 0 }) },
                },
            },
        });
    }

    function renderCountries(byCountry) {
        const sorted = Object.entries(byCountry).sort((a, b) => b[1] - a[1]).slice(0, 10);
        if (countryChart) countryChart.destroy();
        const teal = getVar('--teal');
        countryChart = new Chart($('countryChart').getContext('2d'), {
            type: 'bar',
            data: {
                labels: sorted.map(([c]) => c),
                datasets: [{
                    data: sorted.map(([, n]) => n),
                    backgroundColor: sorted.map(([c]) => c === 'Unknown' ? '#39423f' : 'rgba(63, 184, 160, 0.55)'),
                    borderColor: sorted.map(([c]) => c === 'Unknown' ? '#4b5551' : teal),
                    borderWidth: 1,
                }],
            },
            options: {
                responsive: true, maintainAspectRatio: false, indexAxis: 'y',
                plugins: {
                    legend: { display: false },
                    tooltip: Object.assign({}, TOOLTIP, {
                        callbacks: { label: (item) => item.parsed.x + ' proxies' },
                    }),
                },
                scales: {
                    x: { beginAtZero: true, grid: { color: CHART_GRID }, border: { display: false },
                         ticks: Object.assign({}, CHART_TICK, { precision: 0 }) },
                    y: { grid: { display: false }, border: { color: '#1e2422' }, ticks: CHART_TICK },
                },
            },
        });
    }

    function visibleProxies() {
        const term = $('filter').value.trim().toLowerCase();
        const onlyFast = $('chip-fast').getAttribute('aria-pressed') === 'true';
        return allProxies.filter((p) => {
            if (onlyFast && !(p.latency !== null && p.latency !== undefined && p.latency < 1)) return false;
            if (!term) return true;
            return [p.protocol, p.ip, p.port, p.country].some(
                (v) => v !== null && v !== undefined && String(v).toLowerCase().includes(term));
        });
    }

    function renderTable() {
        const tbody = $('rows');
        const rows = visibleProxies();
        $('tbl-count').textContent = '[' + rows.length + '/' + allProxies.length + ']';

        if (!rows.length) {
            tbody.innerHTML = '<tr><td colspan="6" class="empty">' +
                esc(allProxies.length ? t('no_match') : t('no_nodes')) + '</td></tr>';
            return;
        }

        tbody.innerHTML = rows.map((p, i) => {
            const proto = KNOWN_PROTOCOLS.includes(p.protocol) ? p.protocol : '';
            const color = colorFor(proto, i);
            const hasLat = p.latency !== null && p.latency !== undefined;
            const pct = hasLat ? Math.min(100, (p.latency / MAX_LATENCY) * 100) : 0;
            const latColor = !hasLat ? '#414c49'
                : p.latency < 1 ? getVar('--teal')
                : p.latency < MAX_LATENCY * 0.6 ? getVar('--amber') : getVar('--rose');
            return '<tr>' +
                '<td class="rank num">' + (i + 1) + '</td>' +
                '<td><span class="proto" style="color:' + color + '">' + esc(p.protocol) + '</span></td>' +
                '<td class="host num">' + esc(p.ip) + '</td>' +
                '<td class="port num r">' + esc(p.port) + '</td>' +
                '<td class="r"><span class="lat" style="color:' + latColor + '">' +
                    '<span class="bar"><i style="width:' + pct + '%"></i></span>' +
                    '<span class="val num">' + (hasLat ? p.latency.toFixed(2) + 's' : '\\u2014') + '</span>' +
                '</span></td>' +
                '<td class="geo">' + esc(p.country || '\\u2014') + '</td>' +
                '</tr>';
        }).join('');
    }

    $('filter').addEventListener('input', renderTable);
    $('chip-fast').addEventListener('click', (e) => {
        const btn = e.currentTarget;
        btn.setAttribute('aria-pressed', btn.getAttribute('aria-pressed') === 'true' ? 'false' : 'true');
        renderTable();
    });
    $('chip-copy').addEventListener('click', async (e) => {
        const btn = e.currentTarget;
        const text = visibleProxies().map((p) => p.full || (p.protocol + '://' + p.ip + ':' + p.port)).join('\\n');
        try {
            await navigator.clipboard.writeText(text);
            btn.textContent = t('copied');
        } catch (err) {
            btn.textContent = t('copy_failed');
        }
        setTimeout(() => { btn.textContent = t('copy'); }, 1600);
    });

    applyStaticStrings();
    readSession();
    poll();
    setInterval(poll, REFRESH_MS);
</script>
</body>
</html>
"""


@app.get("/")
def dashboard():
    """Dashboard, rendered in the requested language."""
    locale = current_locale()
    resp = app.make_response(render_template_string(
        DASHBOARD_HTML,
        locale=locale,
        strings=json.dumps(i18n.ui(locale), ensure_ascii=False),
        languages=json.dumps(i18n.LANGUAGES, ensure_ascii=False),
        max_latency=cfg("max_latency_seconds"),
        interval_min=round(cfg("interval_seconds") / 60),
    ))
    # Remember an explicit choice so it survives a plain reload.
    if request.args.get("lang"):
        resp.set_cookie("lang", locale, max_age=31536000, samesite="Lax", httponly=False)
    return resp


@app.get("/api/stats")
def api_stats():
    """Aggregate metrics plus the fastest proxies — what the dashboard polls."""
    with _lock:
        return jsonify({
            "status": _state["status"],
            "message": _state["message"],
            "last_run": _state["last_run"],
            "next_run": _state["next_run"],
            "duration": _state["duration"],
            "source_count": _state["source_count"],
            "max_latency": cfg("max_latency_seconds"),
            "interval_seconds": cfg("interval_seconds"),
            "stats": _state["stats"],
            "proxies": _state["proxy_data"][:cfg("dashboard_rows")],
        })


def _requested_types() -> list[str] | None:
    """`?types=http,socks5` — None means every protocol."""
    raw = request.args.get("types", "").strip()
    return [t for t in raw.split(",") if t.strip()] if raw else None


@app.get("/proxy/all")
def proxy_all():
    """Full list of valid proxies as JSON. `?types=` narrows the protocols."""
    types = _requested_types()
    with _lock:
        proxies = list(_state["proxies"])
        last_run, status, message = _state["last_run"], _state["status"], _state["message"]
    if types:
        proxies = proxy_validator.filter_by_type(proxies, types)
    return jsonify({
        "count": len(proxies),
        "last_run": last_run,
        "status": status,
        "message": message,
        "types": types,
        "proxies": proxies,
    })


@app.get("/proxy/all.txt")
def proxy_all_txt():
    """Same list in plain text, one per line.

    `?types=http,https,socks5` filters by protocol, which matters because plenty
    of tools reject SOCKS4.
    """
    types = _requested_types()
    with _lock:
        proxies = list(_state["proxies"])
    if types:
        proxies = proxy_validator.filter_by_type(proxies, types)
    body = "\n".join(proxies) + ("\n" if proxies else "")
    return body, 200, {"Content-Type": "text/plain; charset=utf-8"}


@app.post("/api/refresh")
def api_refresh():
    """Trigger a revalidation on demand, without blocking the response."""
    if _validation_lock.locked():
        return jsonify({"started": False, "message": "validation already running"}), 409
    threading.Thread(target=run_validation, daemon=True, name="manual-refresh").start()
    return jsonify({"started": True, "message": "validation started"}), 202


@app.get("/api/auth")
def api_auth_status():
    """Session state. Public: the UI needs to know whether to draw the padlock
    open or closed before any authentication happens."""
    return jsonify({
        "logged_in": logged_in(),
        "initial_password": auth_store.is_initial_password(),
        "locked_for": auth_store.locked_for(),
    })


@app.post("/api/login")
def api_login():
    wait = auth_store.locked_for()
    if wait:
        return jsonify({
            "error": "too many attempts",
            "message": f"wait {wait}s before trying again",
            "locked_for": wait,
        }), 429

    password = (request.get_json(silent=True) or {}).get("password", "")
    if not auth_store.check(password):
        auth_store.record_failure()
        _log(f"Login rejected (from {request.remote_addr})")
        return jsonify({"error": "wrong password"}), 401

    auth_store.clear_failures()
    session.clear()
    session["logged_in"] = True
    session.permanent = True
    _log(f"Dashboard login (from {request.remote_addr})")
    return jsonify({"logged_in": True, "initial_password": auth_store.is_initial_password()}), 200


@app.post("/api/logout")
def api_logout():
    session.clear()
    return jsonify({"logged_in": False}), 200


@app.post("/api/password")
def api_password():
    """Change the dashboard password. Requires the current one even while signed
    in — a forgotten open session must not become a password change."""
    body = request.get_json(silent=True) or {}
    current, new = body.get("current", ""), body.get("new", "")

    if not auth_store.check(current):
        auth_store.record_failure()
        return jsonify({"error": "current password is wrong"}), 401

    problem = auth_mod.AuthStore.validate_new(new)
    if problem:
        return jsonify({"error": problem}), 400
    if new == current:
        return jsonify({"error": "the new password matches the current one"}), 400

    auth_store.set_password(new)
    auth_store.clear_failures()
    session.clear()
    session["logged_in"] = True  # whoever changed it stays in
    session.permanent = True
    _log("Dashboard password changed")
    return jsonify({"changed": True, "initial_password": auth_store.is_initial_password()}), 200


@app.get("/api/settings")
def api_settings_get():
    """Schema plus current values, localized. The UI builds its form from this,
    so labels and descriptions live on the server, not duplicated in the HTML."""
    return jsonify({"settings": settings_store.describe(current_locale())})


@app.post("/api/settings")
def api_settings_post():
    """Apply a batch. All or nothing: one invalid value rejects the whole batch,
    so the configuration never lands in a half-state nobody asked for."""
    locale = current_locale()
    body = request.get_json(silent=True) or {}
    changes = body.get("settings", body)
    if not isinstance(changes, dict) or not changes:
        return jsonify({"error": "nothing to apply"}), 400

    # Checked here rather than inside the settings module: resolving a hostname
    # is network I/O, and `Store.load()` shares that validation path — the boot
    # would start doing DNS lookups for every persisted source.
    blocked = [
        reason
        for url in settings_mod.parse_list(changes.get("proxy_sources", []))
        for allowed, reason in [proxy_validator.source_is_allowed(url)]
        if not allowed
    ]
    if blocked:
        return jsonify({"error": "invalid values", "errors": blocked}), 400

    applied, errors = settings_store.apply(changes, locale)
    if errors:
        return jsonify({"error": "invalid values", "errors": errors}), 400

    disk_error = settings_store.save()
    _log("Settings changed from the dashboard: "
         + ", ".join(f"{k}={v}" for k, v in sorted(applied.items())))

    return jsonify({
        "applied": applied,
        "persisted": disk_error is None,
        "warning": f"could not write to disk: {disk_error}" if disk_error else None,
        "settings": settings_store.describe(locale),
    }), 200


@app.post("/api/settings/test-source")
def api_test_source():
    """Fetch one source URL and report what it yields, without saving anything.

    Adding a source blind means waiting a whole cycle to find out it returns
    nothing, or HTML, or a format we cannot parse. This answers in seconds.
    """
    url = (request.get_json(silent=True) or {}).get("url", "").strip()
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return jsonify({"ok": False, "error": "not an http(s) URL"}), 400

    # Without this the endpoint is a port scanner: the three possible answers
    # (responded / connection refused / timed out) map the network the server
    # can reach and the caller cannot.
    allowed, reason = proxy_validator.source_is_allowed(url)
    if not allowed:
        return jsonify({"ok": False, "error": reason}), 400

    started = time.perf_counter()
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=20) as resp:
            text = resp.read(2_000_000).decode("utf-8", errors="replace")
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)[:200]}), 200

    scheme = proxy_validator.scheme_for_source(url)
    lines = text.splitlines()
    found = [p for p in (proxy_validator.normalize_proxy(l, scheme) for l in lines) if p]
    by_type = {}
    for p in found:
        kind = proxy_validator.proxy_type(p) or "?"
        by_type[kind] = by_type.get(kind, 0) + 1

    return jsonify({
        "ok": bool(found),
        "found": len(found),
        "lines": len(lines),
        "by_type": by_type,
        "sample": found[:3],
        "elapsed": round(time.perf_counter() - started, 2),
    }), 200


@app.post("/api/settings/reset")
def api_settings_reset():
    """Drop overrides and fall back to the env vars. No body resets everything."""
    locale = current_locale()
    body = request.get_json(silent=True) or {}
    key = body.get("key")
    if key is not None and key not in settings_mod.BY_KEY:
        return jsonify({"error": f"unknown setting: {key}"}), 400

    settings_store.reset(key)
    disk_error = settings_store.save()
    _log(f"Setting reset to default: {key or 'all'}")
    return jsonify({
        "reset": key or "all",
        "persisted": disk_error is None,
        "settings": settings_store.describe(locale),
    }), 200


@app.get("/health")
def health():
    with _lock:
        return jsonify({
            "status": "ok",
            "validator_status": _state["status"],
            "proxies": len(_state["proxies"]),
            "last_run": _state["last_run"],
        })


# Outside the __main__ block so the scheduler also starts under gunicorn.
start_background_worker()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "8069")))
