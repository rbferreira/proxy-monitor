#!/usr/bin/env python3
"""
proxy_validator.py
==================
Downloads free proxy lists from public sources, tests every entry with a real
request through the proxy, and measures end-to-end latency (connection +
handshake + response).

Only proxies faster than `MAX_LATENCY_SECONDS` are considered valid — that
threshold is the health metric of the whole service.

Usage:
    python3 proxy_validator.py
    python3 proxy_validator.py --output proxies.txt --workers 150 --max-latency 3

Dependencies:
    pip install requests pysocks
"""

import argparse
import os
import sys
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

# Default sources. Override with the PROXY_SOURCES env var (see `sources_from_env`).
PROXY_SOURCES = [
    "https://api.proxyscrape.com/v4/free-proxy-list/get?request=display_proxies&proxy_format=protocolipport&format=text",
    "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=10000&ssl=all&anonymity=all",
    "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks5&timeout=10000",
    "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks4&timeout=10000",
]

# Test URLs: the first one answering with status < 400 marks the proxy as good.
#
# **HTTPS on purpose.** Testing an `http://` URL through a proxy does not
# exercise the CONNECT method — the request goes out in absolute-URI form and
# any transparent cache can answer it. Real traffic is overwhelmingly HTTPS,
# which requires the proxy to open a tunnel.
#
# Measured on a 652-proxy run: 174 passed over plain HTTP, only 70 over HTTPS.
# The 104 extra were false positives — proxies that look alive but cannot carry
# the traffic anyone actually wants to send.
DEFAULT_TEST_URLS = [
    "https://www.gstatic.com/generate_204",
    "https://example.com",
]

# Kept so `--test-http` can reproduce the weaker check for comparison.
HTTP_TEST_URLS = [
    "http://www.gstatic.com/generate_204",
    "http://example.com",
]

MAX_LATENCY_SECONDS = float(os.environ.get("MAX_LATENCY_SECONDS", "5.0"))
DEFAULT_WORKERS = int(os.environ.get("VALIDATOR_WORKERS", "100"))
DEFAULT_OUTPUT = "proxies.txt"

# Protocols this validator knows how to test.
KNOWN_SCHEMES = ("http", "https", "socks4", "socks5")


def sources_from_env() -> list[str] | None:
    """Sources overridden via the PROXY_SOURCES env var (comma or newline
    separated). Returns None when the variable is not set."""
    raw = os.environ.get("PROXY_SOURCES", "").strip()
    if not raw:
        return None
    parts = [p.strip() for p in raw.replace(",", "\n").splitlines()]
    return [p for p in parts if p]


def normalize_proxy(line: str, default_scheme: str = "http") -> str | None:
    """Normalize a source line into lowercase `scheme://host:port`.

    Returns None when the line is not a recognizable proxy. This matters more
    than it looks: sources sometimes answer with an HTML error page, and without
    this filter every junk line becomes a validation thread with a real timeout.
    """
    line = line.strip()
    if not line or line.startswith("#"):
        return None

    if "://" in line:
        scheme, _, hostport = line.partition("://")
        scheme = scheme.lower()
    else:
        scheme, hostport = default_scheme, line

    if scheme not in KNOWN_SCHEMES:
        return None

    host, sep, port = hostport.rpartition(":")
    if not sep or not host:
        return None
    if not port.isdigit() or not 0 < int(port) < 65536:
        return None

    return f"{scheme}://{host.lower()}:{int(port)}"


def scheme_for_source(url: str) -> str:
    """Protocol assumed for sources that return bare `ip:port` lines."""
    for scheme in ("socks5", "socks4", "https"):
        if f"protocol={scheme}" in url:
            return scheme
    return "http"


def fetch_proxies(source_urls: list[str] | None = None) -> list[str]:
    """Download every source and return unique, normalized proxies.

    A failing source only produces a warning — whatever the other sources
    returned is kept.
    """
    if source_urls is None:
        source_urls = sources_from_env() or PROXY_SOURCES

    all_proxies: set[str] = set()
    headers = {"User-Agent": "Mozilla/5.0"}

    for url in source_urls:
        default_scheme = scheme_for_source(url)
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=30) as resp:
                text = resp.read().decode("utf-8", errors="replace")
        except Exception as exc:
            print(f"WARNING: could not fetch {url}: {exc}", file=sys.stderr, flush=True)
            continue

        found = 0
        for line in text.splitlines():
            proxy = normalize_proxy(line, default_scheme)
            if proxy:
                all_proxies.add(proxy)
                found += 1
        print(f"      {found} proxies from {url.split('?')[0]}", file=sys.stderr, flush=True)

    return sorted(all_proxies)


def to_requests_scheme(proxy: str) -> str:
    """Convert the scheme into what `requests` + PySocks expect:
    socks5 -> socks5h (remote DNS), socks4 -> socks4a."""
    if proxy.startswith("socks5://"):
        return "socks5h://" + proxy[len("socks5://"):]
    if proxy.startswith("socks4://"):
        return "socks4a://" + proxy[len("socks4://"):]
    return proxy


def proxy_type(proxy: str) -> str | None:
    """Scheme of a `type://host:port` string, lowercased."""
    if "://" not in proxy:
        return None
    return proxy.split("://", 1)[0].lower()


def filter_by_type(proxies: list[str], types: list[str] | None = None) -> list[str]:
    """Keep only the given protocols, normalized and deduplicated.

    Many consumers accept just a subset — SOCKS4, in particular, is rejected by
    a lot of tooling. `types=None` means "everything we know how to validate".
    """
    # Intersected with what we know how to validate: a caller asking for a
    # protocol this validator never tests would be served entries nothing
    # vouched for.
    requested = {t.lower().strip() for t in (types or KNOWN_SCHEMES) if t and t.strip()}
    allowed = requested & set(KNOWN_SCHEMES)
    out = []
    for p in proxies:
        p = p.strip()
        kind = proxy_type(p)
        if not kind or kind not in allowed:
            continue
        out.append(f"{kind}://{p.split('://', 1)[1]}")
    return sorted(set(out))


def validate(
    proxy: str,
    test_urls: list[str] | None = None,
    max_latency: float = MAX_LATENCY_SECONDS,
) -> tuple[bool, float | None]:
    """Test a proxy with a real GET and measure end-to-end latency.

    Unlike `response.elapsed` — which excludes the TCP connection and the proxy
    handshake, precisely the expensive part — this times the whole request with
    `perf_counter`.

    Returns `(True, latency)` when some test URL answers with status < 400
    within `max_latency` seconds, otherwise `(False, None)`.
    """
    if test_urls is None:
        test_urls = DEFAULT_TEST_URLS

    url = to_requests_scheme(proxy)
    proxies = {"http": url, "https": url}
    headers = {"User-Agent": "Mozilla/5.0"}

    # Slightly above the latency budget: avoids cutting the handshake short,
    # while the real cutoff is the latency comparison below.
    req_timeout = max_latency + 1.0

    for test in test_urls:
        start = time.perf_counter()
        try:
            resp = requests.get(test, proxies=proxies, timeout=req_timeout, headers=headers)
        except Exception:
            continue  # try the next test URL
        latency = time.perf_counter() - start
        if resp.status_code < 400 and latency < max_latency:
            return (True, round(latency, 3))
    return (False, None)


def validate_all(
    proxies: list[str],
    test_urls: list[str] | None = None,
    max_latency: float = MAX_LATENCY_SECONDS,
    workers: int = DEFAULT_WORKERS,
    progress: bool = False,
) -> dict[str, float]:
    """Validate a whole list in parallel. Returns `{proxy: latency}` with only
    the ones that passed. Used by both the CLI and the server."""
    results: dict[str, float] = {}
    if not proxies:
        return results

    total = len(proxies)
    done = 0
    lock = threading.Lock()

    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        futures = {pool.submit(validate, p, test_urls, max_latency): p for p in proxies}
        for fut in as_completed(futures):
            proxy = futures[fut]
            try:
                ok, latency = fut.result()
            except Exception:
                ok, latency = False, None
            done += 1
            if ok:
                with lock:
                    results[proxy] = latency if latency is not None else 0.0
            if progress and (done % 100 == 0 or done == total):
                print(f"      ... {done}/{total} tested | {len(results)} valid", flush=True)

    return results


def main() -> int:
    parser = argparse.ArgumentParser(description="Download and validate free proxies.")
    parser.add_argument("--output", default=DEFAULT_OUTPUT, help=f"output file (default: {DEFAULT_OUTPUT})")
    parser.add_argument("--workers", type=int, default=DEFAULT_WORKERS, help=f"concurrency (default: {DEFAULT_WORKERS})")
    parser.add_argument("--max-latency", type=float, default=MAX_LATENCY_SECONDS,
                        help=f"maximum accepted latency, in seconds (default: {MAX_LATENCY_SECONDS})")
    parser.add_argument("--test-url", action="append", default=None, help="extra test URL (repeatable)")
    parser.add_argument("--source", action="append", default=None, help="extra proxy source (repeatable)")
    parser.add_argument("--types", default=None,
                        help="comma-separated protocols to keep, e.g. http,socks5 (default: all)")
    parser.add_argument("--test-http", action="store_true",
                        help="validate over plain HTTP instead of HTTPS (does not exercise CONNECT; "
                             "accepts proxies that cannot carry HTTPS traffic)")
    args = parser.parse_args()

    base_urls = HTTP_TEST_URLS if args.test_http else DEFAULT_TEST_URLS
    test_urls = base_urls + (args.test_url or [])
    sources = (sources_from_env() or PROXY_SOURCES) + (args.source or [])

    print(f"[1/3] Downloading proxies from {len(sources)} sources...")
    try:
        proxies = fetch_proxies(sources)
    except Exception as exc:
        print(f"ERROR: could not download the list: {exc}", file=sys.stderr)
        return 1

    total = len(proxies)
    print(f"      {total} unique proxies found")
    if not total:
        print("ERROR: no source returned any proxy.", file=sys.stderr)
        return 1

    mode = "plain HTTP" if args.test_http else "HTTPS (CONNECT)"
    print(f"[2/3] Validating {total} proxies ({args.workers} threads, max latency "
          f"{args.max_latency}s, {mode})...")
    results = validate_all(proxies, test_urls, args.max_latency, args.workers, progress=True)

    valid = sorted(results)
    if args.types:
        before = len(valid)
        valid = filter_by_type(valid, args.types.split(","))
        print(f"      {before - len(valid)} filtered out by --types={args.types}")

    print(f"[3/3] Writing {len(valid)} valid proxies to {args.output}")
    with open(args.output, "w", encoding="utf-8") as f:
        f.write("\n".join(valid) + ("\n" if valid else ""))

    if results:
        lat = sorted(results.values())
        avg = sum(lat) / len(lat)
        print(f"      latency: min {lat[0]:.2f}s | avg {avg:.2f}s | max {lat[-1]:.2f}s")
    print(f"Done: {len(valid)}/{total} working proxies -> {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
