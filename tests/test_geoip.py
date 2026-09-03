"""The local country database: install, refresh, look up, and fail quietly.

None of this path had coverage before: the old lookup went to a web API and the
suite disabled it globally, so the positive path was never exercised at all.
"""
import gzip
import io
import os
from datetime import datetime, timezone

import maxminddb
import pytest

import geoip


class FakeReader:
    """Stands in for a maxminddb reader, recording what it was asked."""

    def __init__(self, records=None, raises=None):
        self.records = records or {}
        self.raises = raises
        self.closed = False
        self.asked = []

    def get(self, ip):
        self.asked.append(ip)
        if self.raises:
            raise self.raises
        return self.records.get(ip)

    def close(self):
        self.closed = True

    # install() probes the downloaded file inside a `with`, so the reader is
    # closed before os.replace — on Windows you cannot replace an open file.
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False


def country(name):
    return {"country": {"names": {"en": name}, "iso_code": "XX"}}


@pytest.fixture(autouse=True)
def no_reader():
    geoip.close()
    yield
    geoip.close()


@pytest.fixture
def reader(monkeypatch):
    fake = FakeReader({
        "8.8.8.8": country("United States"),
        "5.253.59.150": country("The Netherlands"),
    })
    monkeypatch.setattr(geoip, "_reader", fake)
    return fake


class TestLookup:
    def test_returns_the_english_country_name(self, reader):
        assert geoip.lookup("8.8.8.8") == "United States"
        assert geoip.lookup("5.253.59.150") == "The Netherlands"

    def test_unknown_address_is_none_not_an_error(self, reader):
        """An address the database does not carry is an ordinary outcome."""
        assert geoip.lookup("192.0.2.1") is None

    def test_garbage_never_reaches_the_database(self, reader):
        for junk in ("", "not-an-ip", "999.999.999.999", "example.com"):
            assert geoip.lookup(junk) is None
        assert reader.asked == []

    def test_no_database_is_not_a_crash(self):
        assert geoip.lookup("8.8.8.8") is None

    def test_a_broken_database_is_swallowed(self, monkeypatch):
        monkeypatch.setattr(
            geoip, "_reader",
            FakeReader(raises=maxminddb.InvalidDatabaseError("corrupt")))
        assert geoip.lookup("8.8.8.8") is None

    def test_a_record_without_a_country_is_none(self, monkeypatch):
        monkeypatch.setattr(geoip, "_reader",
                            FakeReader({"8.8.8.8": {"continent": {}}}))
        assert geoip.lookup("8.8.8.8") is None

    def test_ipv6_works(self, monkeypatch):
        monkeypatch.setattr(geoip, "_reader",
                            FakeReader({"2001:4860:4860::8888": country("United States")}))
        assert geoip.lookup("2001:4860:4860::8888") == "United States"


class TestLookupMany:
    def test_only_resolvable_addresses_appear(self, reader):
        found = geoip.lookup_many(["8.8.8.8", "192.0.2.1", "5.253.59.150"])
        assert found == {"8.8.8.8": "United States",
                         "5.253.59.150": "The Netherlands"}

    def test_empty_input(self, reader):
        assert geoip.lookup_many([]) == {}

    def test_no_batching_and_no_sleeping(self, reader):
        """The old implementation slept 4s between batches of 100 to respect a
        rate limit. A local database has neither, so 250 addresses must cost
        exactly 250 lookups and no wall time."""
        ips = [f"10.0.{i // 256}.{i % 256}" for i in range(250)]
        geoip.lookup_many(ips)
        assert len(reader.asked) == 250


class TestVersions:
    def test_current_month_first_then_previous(self):
        at = datetime(2026, 9, 15, tzinfo=timezone.utc)
        assert geoip.available_versions(at) == ["2026-09", "2026-08"]

    def test_january_falls_back_across_the_year(self):
        at = datetime(2026, 1, 3, tzinfo=timezone.utc)
        assert geoip.available_versions(at) == ["2026-01", "2025-12"]


class TestRefreshPolicy:
    def test_missing_file_needs_a_refresh(self, tmp_path):
        assert geoip.needs_refresh(str(tmp_path)) is True

    def test_a_fresh_file_does_not(self, tmp_path):
        path = tmp_path / "dbip-country-lite.mmdb"
        path.write_bytes(b"x")
        assert geoip.needs_refresh(str(tmp_path)) is False

    def test_an_old_file_does(self, tmp_path):
        path = tmp_path / "dbip-country-lite.mmdb"
        path.write_bytes(b"x")
        old = os.path.getmtime(path) - geoip.REFRESH_SECONDS - 60
        os.utime(path, (old, old))
        assert geoip.needs_refresh(str(tmp_path)) is True


class TestInstall:
    """The live file must never be replaced by something unusable."""

    def _serve(self, monkeypatch, payload, fail_first=False):
        calls = []

        def fake_download(url, timeout=120):
            calls.append(url)
            if fail_first and len(calls) == 1:
                raise OSError("404")
            return payload

        monkeypatch.setattr(geoip, "_download", fake_download)
        return calls

    def test_a_good_database_is_installed(self, tmp_path, monkeypatch):
        self._serve(monkeypatch, gzip.compress(b"fake-mmdb-bytes"))
        monkeypatch.setattr(geoip.maxminddb, "open_database",
                            lambda p: FakeReader({"8.8.8.8": country("US")}))

        version = geoip.install(str(tmp_path), log=lambda m: None)

        assert version
        assert os.path.exists(geoip.db_path(str(tmp_path)))
        assert geoip.read_stamp(str(tmp_path)) == version

    def test_a_file_that_is_not_a_database_never_lands(self, tmp_path, monkeypatch):
        """An HTML error page compresses fine and would otherwise be written
        straight into the volume, replacing a working database."""
        self._serve(monkeypatch, gzip.compress(b"<html>404</html>"))
        monkeypatch.setattr(geoip.maxminddb, "open_database",
                            lambda p: (_ for _ in ()).throw(
                                maxminddb.InvalidDatabaseError("not a database")))

        assert geoip.install(str(tmp_path), log=lambda m: None) == ""
        assert not os.path.exists(geoip.db_path(str(tmp_path)))

    def test_an_existing_database_survives_a_failed_refresh(self, tmp_path, monkeypatch):
        target = geoip.db_path(str(tmp_path))
        os.makedirs(str(tmp_path), exist_ok=True)
        with open(target, "wb") as f:
            f.write(b"the-good-one")

        self._serve(monkeypatch, gzip.compress(b"<html>404</html>"))
        monkeypatch.setattr(geoip.maxminddb, "open_database",
                            lambda p: (_ for _ in ()).throw(
                                maxminddb.InvalidDatabaseError("nope")))
        geoip.install(str(tmp_path), log=lambda m: None)

        with open(target, "rb") as f:
            assert f.read() == b"the-good-one"

    def test_no_temporary_files_are_left_behind(self, tmp_path, monkeypatch):
        self._serve(monkeypatch, gzip.compress(b"<html>404</html>"))
        monkeypatch.setattr(geoip.maxminddb, "open_database",
                            lambda p: (_ for _ in ()).throw(ValueError("nope")))
        geoip.install(str(tmp_path), log=lambda m: None)

        assert [p for p in os.listdir(tmp_path) if p.endswith(".tmp")] == []

    def test_the_previous_month_is_tried_when_the_current_one_is_missing(
            self, tmp_path, monkeypatch):
        """DB-IP publishes a few days into the month, so a 404 on the current
        version is expected rather than exceptional."""
        calls = self._serve(monkeypatch, gzip.compress(b"ok"), fail_first=True)
        monkeypatch.setattr(geoip.maxminddb, "open_database",
                            lambda p: FakeReader({"8.8.8.8": country("US")}))

        assert geoip.install(str(tmp_path), log=lambda m: None)
        assert len(calls) == 2

    def test_an_oversized_download_is_refused(self, tmp_path, monkeypatch):
        """Guards against a redirect to something enormous filling the volume."""
        monkeypatch.setattr(geoip, "MAX_UNPACKED_BYTES", 32)
        self._serve(monkeypatch, gzip.compress(b"x" * 1000))
        monkeypatch.setattr(geoip.maxminddb, "open_database",
                            lambda p: FakeReader())

        assert geoip.install(str(tmp_path), log=lambda m: None) == ""
        assert not os.path.exists(geoip.db_path(str(tmp_path)))


class TestOpenReader:
    def test_missing_file_reports_failure_without_raising(self, tmp_path):
        assert geoip.open_reader(str(tmp_path), log=lambda m: None) is False
        assert geoip.is_ready() is False

    def test_opening_twice_reuses_the_reader(self, tmp_path, monkeypatch):
        opened = []
        monkeypatch.setattr(geoip.maxminddb, "open_database",
                            lambda p: opened.append(p) or FakeReader())
        assert geoip.open_reader(str(tmp_path), log=lambda m: None) is True
        assert geoip.open_reader(str(tmp_path), log=lambda m: None) is True
        assert len(opened) == 1


class TestEnsure:
    def test_a_failing_download_still_leaves_the_service_usable(self, tmp_path, monkeypatch):
        """Without a database every country reads Unknown — which beats
        refusing to validate proxies at all."""
        monkeypatch.setattr(geoip, "_download",
                            lambda url, timeout=120: (_ for _ in ()).throw(OSError("offline")))
        assert geoip.ensure(str(tmp_path), log=lambda m: None) is False
        assert geoip.lookup("8.8.8.8") is None


class TestAttribution:
    def test_the_licence_text_is_present(self):
        """CC-BY 4.0 requires it, so it is a constant and not a translated
        string that a locale could quietly drop."""
        assert geoip.ATTRIBUTION_TEXT == "IP Geolocation by DB-IP"
        assert geoip.ATTRIBUTION_URL == "https://db-ip.com"

    def test_the_dashboard_renders_it(self):
        import app as app_module
        assert "IP Geolocation by DB-IP" in app_module.DASHBOARD_HTML
        assert "https://db-ip.com" in app_module.DASHBOARD_HTML
