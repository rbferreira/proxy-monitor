#!/usr/bin/env python3
"""
geoip.py
========
Country lookup from a local MaxMind-format database.

**Why local.** The obvious implementation asks a web API, and that is what this
service used to do: batches of 100 to ip-api.com with a 4 second sleep between
them, because the free tier allows roughly 15 batches per minute. That capped a
run at a few hundred addresses — every proxy past the cap showed as Unknown —
and the cache lived in memory, so every restart paid the whole bill again.

A local database answers in microseconds, has no cap, no rate limit, no third
party, and needs no TLS to protect the addresses being looked up. The file is
read through mmap, so the process does not carry it in resident memory.

**Country, not city.** DB-IP publishes both; the city database is about fifteen
times larger. Nothing here displays a city, so the country database is the one
that fits the job.

Licence: the DB-IP Lite databases are CC-BY 4.0 and require visible attribution
wherever results are shown. See ATTRIBUTION below — it is a condition of use,
not a courtesy, and it is rendered in the dashboard footer and the README.
"""

import gzip
import ipaddress
import os
import shutil
import tempfile
import threading
import time
from datetime import datetime, timezone

import maxminddb
import requests

# Rendered by anything that displays a lookup result. Required by CC-BY 4.0.
ATTRIBUTION_TEXT = "IP Geolocation by DB-IP"
ATTRIBUTION_URL = "https://db-ip.com"

DOWNLOAD_URL = "https://download.db-ip.com/free/dbip-country-lite-{version}.mmdb.gz"

# The compressed file is around 4 MB and the database around 8 MB. The ceilings
# are a guard against a redirect to something that is not a database at all,
# which would otherwise be written straight into the volume.
MAX_DOWNLOAD_BYTES = 64 * 1024 * 1024
MAX_UNPACKED_BYTES = 256 * 1024 * 1024

# DB-IP publishes monthly. Re-checking more often only wastes a request.
REFRESH_SECONDS = 7 * 24 * 3600

_lock = threading.Lock()
_reader = None
_reader_path = None


def db_path(data_dir: str) -> str:
    return os.path.join(data_dir, "dbip-country-lite.mmdb")


def _stamp_path(data_dir: str) -> str:
    return db_path(data_dir) + ".version"


def available_versions(now: datetime | None = None) -> list[str]:
    """Newest first. The current month appears a little into the month, so the
    previous one is the fallback rather than a failure."""
    now = now or datetime.now(timezone.utc)
    year, month = now.year, now.month
    previous = (year - 1, 12) if month == 1 else (year, month - 1)
    return [f"{year:04d}-{month:02d}", f"{previous[0]:04d}-{previous[1]:02d}"]


def read_stamp(data_dir: str) -> str:
    try:
        with open(_stamp_path(data_dir), encoding="utf-8") as f:
            return f.read().strip()
    except OSError:
        return ""


def _write_stamp(data_dir: str, version: str) -> None:
    try:
        with open(_stamp_path(data_dir), "w", encoding="utf-8") as f:
            f.write(version)
    except OSError:
        pass


def needs_refresh(data_dir: str, now: float | None = None) -> bool:
    path = db_path(data_dir)
    if not os.path.exists(path):
        return True
    try:
        age = (now or time.time()) - os.path.getmtime(path)
    except OSError:
        return True
    return age > REFRESH_SECONDS


def _download(url: str, timeout: int = 120) -> bytes:
    resp = requests.get(url, timeout=timeout, stream=True)
    resp.raise_for_status()
    chunks, total = [], 0
    for chunk in resp.iter_content(chunk_size=64 * 1024):
        total += len(chunk)
        if total > MAX_DOWNLOAD_BYTES:
            raise ValueError(f"download exceeded {MAX_DOWNLOAD_BYTES} bytes")
        chunks.append(chunk)
    return b"".join(chunks)


def install(data_dir: str, log=print) -> str:
    """Fetch the newest database and put it in place atomically.

    The replacement only happens after the decompressed file has been opened as
    a real database, so a truncated download or an HTML error page can never
    take the place of a working file. Returns the installed version, or "".
    """
    os.makedirs(data_dir, exist_ok=True)
    target = db_path(data_dir)
    last_error = None

    for version in available_versions():
        url = DOWNLOAD_URL.format(version=version)
        tmp_name = None
        try:
            payload = _download(url)
            with tempfile.NamedTemporaryFile(dir=data_dir, suffix=".tmp",
                                             delete=False) as tmp:
                tmp_name = tmp.name
                with gzip.GzipFile(fileobj=_BytesReader(payload)) as gz:
                    written = _copy_bounded(gz, tmp, MAX_UNPACKED_BYTES)
            # Prove it is a database before letting it replace the live one.
            with maxminddb.open_database(tmp_name) as probe:
                probe.get("8.8.8.8")
            os.replace(tmp_name, target)
            tmp_name = None
            _write_stamp(data_dir, version)
            log(f"GeoIP database {version} installed ({written / 1048576:.1f} MB)")
            return version
        except Exception as exc:  # noqa: BLE001 - any failure means try the next
            last_error = exc
            log(f"GeoIP database {version} unavailable: {exc}")
        finally:
            if tmp_name and os.path.exists(tmp_name):
                try:
                    os.unlink(tmp_name)
                except OSError:
                    pass

    log(f"WARNING: no GeoIP database could be installed ({last_error})")
    return ""


class _BytesReader:
    """Minimal file-like wrapper so GzipFile can read an in-memory payload."""

    def __init__(self, data: bytes):
        self._data = data
        self._pos = 0

    def read(self, size: int = -1) -> bytes:
        if size < 0:
            chunk = self._data[self._pos:]
            self._pos = len(self._data)
            return chunk
        chunk = self._data[self._pos:self._pos + size]
        self._pos += len(chunk)
        return chunk

    def seek(self, offset: int, whence: int = 0) -> int:
        base = {0: 0, 1: self._pos, 2: len(self._data)}[whence]
        self._pos = max(0, min(len(self._data), base + offset))
        return self._pos

    def tell(self) -> int:
        return self._pos


def _copy_bounded(src, dst, limit: int) -> int:
    written = 0
    while True:
        chunk = src.read(1024 * 1024)
        if not chunk:
            return written
        written += len(chunk)
        if written > limit:
            raise ValueError(f"unpacked file exceeded {limit} bytes")
        dst.write(chunk)


def open_reader(data_dir: str, log=print) -> bool:
    """Open the database for lookups. False when there is nothing to open."""
    global _reader, _reader_path
    path = db_path(data_dir)
    with _lock:
        if _reader is not None and _reader_path == path:
            return True
        try:
            reader = maxminddb.open_database(path)
        except (OSError, ValueError, maxminddb.InvalidDatabaseError) as exc:
            log(f"GeoIP database not usable: {exc}")
            return False
        if _reader is not None:
            try:
                _reader.close()
            except Exception:  # noqa: BLE001
                pass
        _reader, _reader_path = reader, path
        return True


def close() -> None:
    global _reader, _reader_path
    with _lock:
        if _reader is not None:
            try:
                _reader.close()
            except Exception:  # noqa: BLE001
                pass
        _reader, _reader_path = None, None


def is_ready() -> bool:
    return _reader is not None


def lookup(ip: str) -> str | None:
    """Country name in English, or None when it cannot be determined.

    Never raises: an address the database does not carry is an ordinary
    outcome, not an error, and callers render it as Unknown.
    """
    reader = _reader
    if reader is None or not ip:
        return None
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return None
    try:
        record = reader.get(ip)
    except (ValueError, maxminddb.InvalidDatabaseError):
        return None
    if not isinstance(record, dict):
        return None
    country = record.get("country") or {}
    names = country.get("names") or {}
    return names.get("en") or None


def lookup_many(ips) -> dict[str, str]:
    """Countries for every address that resolves to one.

    No batching, no sleeping, no cache: at roughly twenty thousand lookups per
    second against a memory-mapped file, a cache would cost more to maintain
    than the lookups it saves.
    """
    found = {}
    for ip in ips:
        country = lookup(ip)
        if country:
            found[ip] = country
    return found


def ensure(data_dir: str, log=print) -> bool:
    """Install the database when missing or stale, then open it.

    Called at boot and before each validation cycle. A failure here is not
    fatal: without a database every country reads Unknown and everything else
    works, which is better than refusing to validate proxies.
    """
    try:
        if needs_refresh(data_dir):
            if install(data_dir, log) and _reader is not None:
                close()  # reopen so the new file is the one being read
    except Exception as exc:  # noqa: BLE001
        log(f"WARNING: GeoIP refresh failed: {exc}")
    return open_reader(data_dir, log)
