"""Flask routes, authentication, snapshot building and the settings API."""
import os

import pytest

os.environ.setdefault("API_KEY", "test-key")
os.environ.setdefault("DISABLE_SCHEDULER", "1")  # no scheduler during tests
os.environ.setdefault("GEOLOOKUP", "false")      # no GeoIP database in tests

import app as app_module  # noqa: E402

KEY = {"X-API-Key": os.environ["API_KEY"]}


@pytest.fixture
def client():
    app_module.app.config["TESTING"] = True
    with app_module.app.test_client() as c:
        yield c


@pytest.fixture(autouse=True)
def clean_state():
    """Every test starts from a blank global state."""
    with app_module._lock:
        app_module._state.update({
            "proxies": [],
            "latencies": {},
            "proxy_data": [],
            "last_run": None,
            "next_run": None,
            "duration": None,
            "source_count": 0,
            "status": "idle",
            "message": "",
        })
    # No country cache to clear: lookups read a local database directly.
    # The stability store is global, so samples recorded by one test would
    # otherwise decide the verdict seen by the next.
    app_module.stability_store.clear()
    yield


@pytest.fixture
def isolated_auth(tmp_path, monkeypatch):
    import auth as auth_mod
    a = auth_mod.AuthStore(str(tmp_path / "auth.json"))
    a.load()
    monkeypatch.setattr(app_module, "auth_store", a)
    app_module.app.secret_key = a.secret_key
    return a


@pytest.fixture
def isolated_settings(tmp_path, monkeypatch):
    import settings as settings_mod
    s = settings_mod.Store(str(tmp_path / "runtime.json"))
    monkeypatch.setattr(app_module, "settings_store", s)
    return s


def seed(proxies, latencies=None):
    latencies = latencies or {}
    proxy_data, stats = app_module.build_snapshot(proxies, latencies)
    with app_module._lock:
        app_module._state.update({
            "proxies": proxies,
            "latencies": latencies,
            "proxy_data": proxy_data,
            "stats": stats,
            "status": "ok",
            "source_count": len(proxies) * 2,
        })


class TestAuthorization:
    def test_dashboard_is_public(self, client):
        assert client.get("/").status_code == 200

    def test_stats_is_public_alongside_the_dashboard(self, client):
        """The dashboard fetches /api/stats with no credential — if that route
        needed one, the page would sit on 'loading' forever."""
        resp = client.get("/api/stats")
        assert resp.status_code == 200
        assert resp.is_json

    def test_health_is_public(self, client):
        assert client.get("/health").status_code == 200

    def test_proxy_all_needs_a_credential(self, client):
        assert client.get("/proxy/all").status_code == 401

    def test_proxy_all_with_api_key(self, client):
        assert client.get("/proxy/all", headers=KEY).status_code == 200

    def test_wrong_key(self, client):
        assert client.get("/proxy/all", headers={"X-API-Key": "nope"}).status_code == 401

    def test_401_answers_json(self, client):
        resp = client.get("/proxy/all")
        assert resp.is_json
        assert resp.get_json()["error"] == "unauthorized"


class TestDashboard:
    def test_html_points_at_stats(self, client):
        body = client.get("/").get_data(as_text=True)
        assert "/api/stats" in body
        # the Jinja placeholders must have been rendered, not left raw
        assert "{{" not in body

    def test_modal_starts_hidden(self, client):
        """Regression: `.modal { display: flex }` overrode the `hidden`
        attribute, so the settings panel opened by itself on page load."""
        body = client.get("/").get_data(as_text=True)
        assert '<div class="modal" id="cfg-modal" hidden>' in body
        assert ".modal[hidden] { display: none; }" in body

    def test_renders_in_english_by_default(self, client):
        body = client.get("/").get_data(as_text=True)
        assert 'lang="en"' in body
        assert '"state": "State"' in body or '"state":"State"' in body

    def test_renders_in_portuguese_on_request(self, client):
        body = client.get("/?lang=pt-BR").get_data(as_text=True)
        assert 'lang="pt-BR"' in body
        assert "Estado" in body

    def test_language_choice_is_remembered(self, client):
        resp = client.get("/?lang=pt-BR")
        cookies = "; ".join(resp.headers.getlist("Set-Cookie"))
        assert "lang=pt-BR" in cookies

    def test_language_is_not_pinned_without_an_explicit_choice(self, client):
        """Only an explicit pick sets the cookie; the header stays a hint."""
        resp = client.get("/", headers={"Accept-Language": "pt-BR"})
        assert "lang=" not in "; ".join(resp.headers.getlist("Set-Cookie"))

    def test_accept_language_is_a_hint(self, client):
        body = client.get("/", headers={"Accept-Language": "pt-BR,pt;q=0.9"}).get_data(as_text=True)
        assert 'lang="pt-BR"' in body

    def test_stats_contract(self, client):
        seed(["http://1.1.1.1:8080"], {"http://1.1.1.1:8080": 0.5})
        data = client.get("/api/stats").get_json()
        for field in ("status", "message", "last_run", "next_run", "duration",
                      "source_count", "max_latency", "interval_seconds", "stats", "proxies"):
            assert field in data
        for field in ("total", "healthy", "by_protocol", "by_country",
                      "latency_buckets", "avg_latency", "min_latency", "max_latency"):
            assert field in data["stats"]

    def test_table_rows_carry_what_the_ui_needs(self, client):
        seed(["socks5://9.9.9.9:1080"], {"socks5://9.9.9.9:1080": 1.25})
        row = client.get("/api/stats").get_json()["proxies"][0]
        assert row["protocol"] == "socks5"
        assert row["ip"] == "9.9.9.9"
        assert row["port"] == 1080
        assert row["latency"] == 1.25


class TestBuildSnapshot:
    def test_empty(self):
        proxy_data, stats = app_module.build_snapshot([], {})
        assert proxy_data == []
        assert stats["total"] == 0
        assert stats["avg_latency"] == 0

    def test_aggregates_by_protocol_and_country(self):
        proxies = ["http://1.1.1.1:80", "http://2.2.2.2:80", "socks5://3.3.3.3:1080"]
        _, stats = app_module.build_snapshot(proxies, {})
        assert stats["total"] == 3
        assert stats["by_protocol"] == {"http": 2, "socks5": 1}
        assert stats["by_country"] == {"Unknown": 3}  # geolookup disabled

    def test_latency_stats(self):
        proxies = ["http://1.1.1.1:80", "http://2.2.2.2:80", "http://3.3.3.3:80"]
        latencies = {"http://1.1.1.1:80": 1.0, "http://2.2.2.2:80": 2.0, "http://3.3.3.3:80": 3.0}
        _, stats = app_module.build_snapshot(proxies, latencies)
        assert stats["min_latency"] == 1.0
        assert stats["avg_latency"] == 2.0
        assert stats["max_latency"] == 3.0

    def test_sorted_fastest_first(self):
        proxies = ["http://1.1.1.1:80", "http://2.2.2.2:80", "http://3.3.3.3:80"]
        latencies = {"http://1.1.1.1:80": 3.0, "http://2.2.2.2:80": 0.5}
        proxy_data, _ = app_module.build_snapshot(proxies, latencies)
        assert [p["ip"] for p in proxy_data] == ["2.2.2.2", "1.1.1.1", "3.3.3.3"]
        assert proxy_data[-1]["latency"] is None  # unmeasured goes last

    def test_discards_invalid_entries(self):
        _, stats = app_module.build_snapshot(["not-a-proxy", "http://1.1.1.1:80"], {})
        assert stats["total"] == 1


class TestParseProxy:
    def test_ok(self):
        assert app_module.parse_proxy("socks5://1.2.3.4:1080") == {
            "protocol": "socks5", "ip": "1.2.3.4", "port": 1080,
            "full": "socks5://1.2.3.4:1080", "latency": None, "country": None,
        }

    def test_invalid(self):
        assert app_module.parse_proxy("junk") is None
        assert app_module.parse_proxy("http://1.2.3.4:port") is None


class TestProxyEndpoints:
    def test_all_json(self, client):
        seed(["http://1.1.1.1:80", "socks5://3.3.3.3:1080"])
        data = client.get("/proxy/all", headers=KEY).get_json()
        assert data["count"] == 2

    def test_all_txt_is_plain_text(self, client):
        seed(["http://1.1.1.1:80", "socks5://3.3.3.3:1080"])
        resp = client.get("/proxy/all.txt", headers=KEY)
        assert resp.mimetype == "text/plain"
        assert resp.get_data(as_text=True).splitlines() == [
            "http://1.1.1.1:80", "socks5://3.3.3.3:1080"]

    def test_types_filter_json(self, client):
        seed(["http://1.1.1.1:80", "socks4://2.2.2.2:1080", "socks5://3.3.3.3:1080"])
        data = client.get("/proxy/all?types=http,socks5", headers=KEY).get_json()
        assert data["count"] == 2
        assert "socks4://2.2.2.2:1080" not in data["proxies"]

    def test_types_filter_txt(self, client):
        seed(["http://1.1.1.1:80", "socks4://2.2.2.2:1080"])
        body = client.get("/proxy/all.txt?types=http", headers=KEY).get_data(as_text=True)
        assert body == "http://1.1.1.1:80\n"

    def test_empty_txt_does_not_emit_a_stray_line(self, client):
        assert client.get("/proxy/all.txt", headers=KEY).get_data(as_text=True) == ""

    def test_health_carries_diagnostics(self, client):
        seed(["http://1.1.1.1:80"])
        data = client.get("/health").get_json()
        assert data["status"] == "ok"
        assert data["proxies"] == 1


class TestRefresh:
    def test_refuses_while_already_running(self, client):
        app_module._validation_lock.acquire()
        try:
            assert client.post("/api/refresh", headers=KEY).status_code == 409
        finally:
            app_module._validation_lock.release()

    def test_needs_a_credential(self, client):
        assert client.post("/api/refresh").status_code == 401


class TestHealthDuringValidation:
    def test_health_answers_while_validating(self, client, monkeypatch):
        """Orchestrators probe right at boot, alongside the first validation. If
        /health waited on the lock, the container would come up unhealthy."""
        import threading
        import time as _t

        release = threading.Event()

        def slow_fetch(sources=None):
            release.wait(timeout=5)
            return ["http://1.1.1.1:80"]

        monkeypatch.setattr(app_module.proxy_validator, "fetch_proxies", slow_fetch)
        # Must patch what run_validation actually calls. Patching the wrong
        # function here does not fail the test — it quietly lets it open a real
        # connection to 1.1.1.1 and wait out the timeout.
        monkeypatch.setattr(
            app_module.proxy_validator, "validate_all_detailed",
            lambda *a, **kw: {"http://1.1.1.1:80": app_module.proxy_validator.Result(
                "http://1.1.1.1:80", True, 0.5)})

        t = threading.Thread(target=app_module.run_validation, daemon=True)
        t.start()
        try:
            for _ in range(50):
                if app_module._validation_lock.locked():
                    break
                _t.sleep(0.01)
            assert app_module._validation_lock.locked(), "validation never started"

            start = _t.perf_counter()
            resp = client.get("/health")
            elapsed = _t.perf_counter() - start

            assert resp.status_code == 200
            assert resp.get_json()["validator_status"] == "running"
            assert elapsed < 1.0, f"/health blocked for {elapsed:.2f}s"
        finally:
            release.set()
            t.join(timeout=5)


class TestOutputFile:
    def test_writes_and_reads_back(self, tmp_path, monkeypatch):
        target = tmp_path / "sub" / "proxies.txt"
        monkeypatch.setattr(app_module, "OUTPUT_FILE", str(target))
        monkeypatch.setattr(app_module, "DATA_DIR", str(target.parent))
        app_module.write_output_file(["http://1.1.1.1:80", "socks5://2.2.2.2:1080"])
        assert target.read_text(encoding="utf-8") == "http://1.1.1.1:80\nsocks5://2.2.2.2:1080\n"

        app_module.load_cached_proxies()
        with app_module._lock:
            assert app_module._state["proxies"] == ["http://1.1.1.1:80", "socks5://2.2.2.2:1080"]

    def test_empty_list_writes_no_stray_line(self, tmp_path, monkeypatch):
        target = tmp_path / "proxies.txt"
        monkeypatch.setattr(app_module, "OUTPUT_FILE", str(target))
        monkeypatch.setattr(app_module, "DATA_DIR", str(tmp_path))
        app_module.write_output_file([])
        assert target.read_text(encoding="utf-8") == ""

    def test_missing_file_does_not_break_boot(self, tmp_path, monkeypatch):
        monkeypatch.setattr(app_module, "OUTPUT_FILE", str(tmp_path / "absent.txt"))
        app_module.load_cached_proxies()  # must not raise

    def test_remembers_when_the_list_was_validated(self, tmp_path, monkeypatch):
        """A restart that serves a cache must not claim it never validated —
        the dashboard would contradict itself, and anything polling last_run
        would wait a whole interval for a timestamp it already had."""
        target = tmp_path / "proxies.txt"
        monkeypatch.setattr(app_module, "OUTPUT_FILE", str(target))
        monkeypatch.setattr(app_module, "DATA_DIR", str(tmp_path))
        monkeypatch.setattr(app_module, "CACHE_META_FILE", str(target) + ".meta.json")

        app_module.write_output_file(
            ["http://1.1.1.1:80"],
            {"last_run": "2026-01-01T00:00:00Z", "duration": 12.5, "source_count": 9},
        )
        app_module._set_state(last_run=None, duration=None, source_count=None)
        app_module.load_cached_proxies()

        with app_module._lock:
            assert app_module._state["last_run"] == "2026-01-01T00:00:00Z"
            assert app_module._state["duration"] == 12.5
            assert app_module._state["source_count"] == 9

    def test_a_corrupt_timestamp_file_is_ignored(self, tmp_path, monkeypatch):
        target = tmp_path / "proxies.txt"
        meta = tmp_path / "proxies.txt.meta.json"
        monkeypatch.setattr(app_module, "OUTPUT_FILE", str(target))
        monkeypatch.setattr(app_module, "DATA_DIR", str(tmp_path))
        monkeypatch.setattr(app_module, "CACHE_META_FILE", str(meta))
        app_module.write_output_file(['http://1.1.1.1:80'])
        meta.write_text("{not json", encoding="utf-8")

        app_module._set_state(last_run=None)
        app_module.load_cached_proxies()  # must not raise
        with app_module._lock:
            assert app_module._state["proxies"] == ["http://1.1.1.1:80"]
            assert app_module._state["last_run"] is None


class TestListToken:
    """Consumers that can only fetch a URL cannot send a header, so the
    plain-text list accepts a dedicated query-string token."""

    def test_no_token_configured_still_requires_a_header(self, client, monkeypatch):
        monkeypatch.setattr(app_module, "LIST_TOKEN", "")
        assert client.get("/proxy/all.txt").status_code == 401
        assert client.get("/proxy/all.txt?token=whatever").status_code == 401

    def test_correct_token_opens_the_list(self, client, monkeypatch):
        monkeypatch.setattr(app_module, "LIST_TOKEN", "secret-token")
        seed(["http://1.1.1.1:80"])
        resp = client.get("/proxy/all.txt?token=secret-token")
        assert resp.status_code == 200
        assert resp.get_data(as_text=True) == "http://1.1.1.1:80\n"

    def test_wrong_token_is_rejected(self, client, monkeypatch):
        monkeypatch.setattr(app_module, "LIST_TOKEN", "secret-token")
        assert client.get("/proxy/all.txt?token=wrong").status_code == 401

    def test_does_not_open_the_rest_of_the_api(self, client, monkeypatch):
        """The token is scoped to the plain-text list, nothing else."""
        monkeypatch.setattr(app_module, "LIST_TOKEN", "secret-token")
        assert client.get("/proxy/all?token=secret-token").status_code == 401
        assert client.post("/api/refresh?token=secret-token").status_code == 401
        assert client.get("/api/settings?token=secret-token").status_code == 401

    def test_empty_token_in_the_query_fails(self, client, monkeypatch):
        monkeypatch.setattr(app_module, "LIST_TOKEN", "secret-token")
        assert client.get("/proxy/all.txt?token=").status_code == 401


class TestSession:
    """Padlock login. Reading stays open; writing needs a session or the API key
    header (the latter for scripts only)."""

    def test_status_is_public(self, client, isolated_auth):
        d = client.get("/api/auth").get_json()
        assert d["logged_in"] is False
        assert d["initial_password"] is True

    def test_reading_stays_open_without_login(self, client, isolated_auth):
        assert client.get("/").status_code == 200
        assert client.get("/api/stats").status_code == 200

    def test_writing_without_a_session_is_401(self, client, isolated_auth):
        assert client.get("/api/settings").status_code == 401

    def test_login_with_the_initial_password(self, client, isolated_auth):
        r = client.post("/api/login", json={"password": "admin"})
        assert r.status_code == 200
        assert r.get_json()["logged_in"] is True
        assert client.get("/api/settings").status_code == 200

    def test_login_with_the_wrong_password(self, client, isolated_auth):
        assert client.post("/api/login", json={"password": "wrong"}).status_code == 401
        assert client.get("/api/settings").status_code == 401

    def test_logout_closes_access(self, client, isolated_auth):
        client.post("/api/login", json={"password": "admin"})
        assert client.get("/api/settings").status_code == 200
        client.post("/api/logout")
        assert client.get("/api/settings").status_code == 401

    def test_api_key_still_works_for_scripts(self, client, isolated_auth):
        assert client.get("/proxy/all", headers=KEY).status_code == 200

    def test_locks_after_too_many_attempts(self, client, isolated_auth):
        import auth as auth_mod
        for _ in range(auth_mod.MAX_ATTEMPTS):
            client.post("/api/login", json={"password": "wrong"})
        r = client.post("/api/login", json={"password": "admin"})
        assert r.status_code == 429
        assert r.get_json()["locked_for"] > 0


class TestPasswordAPI:
    def test_change_then_login_with_the_new_one(self, client, isolated_auth):
        client.post("/api/login", json={"password": "admin"})
        r = client.post("/api/password", json={"current": "admin", "new": "a-good-password"})
        assert r.status_code == 200
        assert r.get_json()["initial_password"] is False

        client.post("/api/logout")
        assert client.post("/api/login", json={"password": "admin"}).status_code == 401
        assert client.post("/api/login", json={"password": "a-good-password"}).status_code == 200

    def test_requires_the_current_password_even_when_signed_in(self, client, isolated_auth):
        """A forgotten open session must not become a password change."""
        client.post("/api/login", json={"password": "admin"})
        r = client.post("/api/password", json={"current": "guess", "new": "another-password"})
        assert r.status_code == 401
        assert isolated_auth.check("admin") is True

    def test_rejects_a_short_password(self, client, isolated_auth):
        client.post("/api/login", json={"password": "admin"})
        assert client.post("/api/password", json={"current": "admin", "new": "ab"}).status_code == 400

    def test_rejects_the_same_password(self, client, isolated_auth):
        client.post("/api/login", json={"password": "admin"})
        assert client.post("/api/password",
                           json={"current": "admin", "new": "admin"}).status_code == 400

    def test_whoever_changed_it_stays_signed_in(self, client, isolated_auth):
        client.post("/api/login", json={"password": "admin"})
        client.post("/api/password", json={"current": "admin", "new": "a-good-password"})
        assert client.get("/api/settings").status_code == 200


class TestSettingsAPI:
    def test_get_needs_a_credential(self, client):
        assert client.get("/api/settings").status_code == 401

    def test_post_needs_a_credential(self, client):
        assert client.post("/api/settings", json={"dashboard_rows": 20}).status_code == 401

    def test_get_returns_the_full_schema(self, client, isolated_settings):
        data = client.get("/api/settings", headers=KEY).get_json()
        assert len(data["settings"]) >= 7
        for item in data["settings"]:
            assert item["description"] and item["label"] and item["group"]

    def test_is_localized(self, client, isolated_settings):
        en = client.get("/api/settings", headers=KEY).get_json()["settings"]
        pt = client.get("/api/settings?lang=pt-BR", headers=KEY).get_json()["settings"]
        assert en[0]["label"] != pt[0]["label"]

    def test_apply_changes_behavior(self, client, isolated_settings):
        r = client.post("/api/settings", json={"dashboard_rows": 15}, headers=KEY)
        assert r.status_code == 200
        assert r.get_json()["applied"] == {"dashboard_rows": 15}

        seed([f"http://10.0.0.{i}:80" for i in range(1, 40)])
        assert len(client.get("/api/stats").get_json()["proxies"]) == 15

    def test_interval_reflects_in_stats(self, client, isolated_settings):
        client.post("/api/settings", json={"interval_seconds": 900}, headers=KEY)
        assert client.get("/api/stats").get_json()["interval_seconds"] == 900

    def test_invalid_value_rejects_the_whole_batch(self, client, isolated_settings):
        r = client.post("/api/settings",
                        json={"dashboard_rows": 20, "interval_seconds": 5}, headers=KEY)
        assert r.status_code == 400
        assert "errors" in r.get_json()
        assert isolated_settings.is_overridden("dashboard_rows") is False

    def test_empty_body_is_400(self, client, isolated_settings):
        assert client.post("/api/settings", json={}, headers=KEY).status_code == 400

    def test_accepts_the_settings_envelope(self, client, isolated_settings):
        r = client.post("/api/settings", json={"settings": {"dashboard_rows": 33}}, headers=KEY)
        assert r.status_code == 200
        assert app_module.cfg("dashboard_rows") == 33

    def test_reset_one(self, client, isolated_settings):
        client.post("/api/settings", json={"dashboard_rows": 33}, headers=KEY)
        r = client.post("/api/settings/reset", json={"key": "dashboard_rows"}, headers=KEY)
        assert r.status_code == 200
        assert isolated_settings.is_overridden("dashboard_rows") is False

    def test_reset_everything(self, client, isolated_settings):
        client.post("/api/settings",
                    json={"dashboard_rows": 33, "interval_seconds": 900}, headers=KEY)
        client.post("/api/settings/reset", json={}, headers=KEY)
        assert isolated_settings.is_overridden("dashboard_rows") is False
        assert isolated_settings.is_overridden("interval_seconds") is False

    def test_reset_unknown_key(self, client, isolated_settings):
        assert client.post("/api/settings/reset",
                           json={"key": "nope"}, headers=KEY).status_code == 400

    def test_persists_to_disk(self, client, isolated_settings):
        r = client.post("/api/settings", json={"dashboard_rows": 44}, headers=KEY)
        assert r.get_json()["persisted"] is True
        import settings as settings_mod
        other = settings_mod.Store(isolated_settings.path)
        other.load()
        assert other.get("dashboard_rows") == 44


class TestApiKeyGeneration:
    def test_env_wins(self, monkeypatch):
        monkeypatch.setenv("API_KEY", "from-env")
        assert app_module.load_api_key() == "from-env"

    def test_generates_and_persists(self, tmp_path, monkeypatch):
        monkeypatch.delenv("API_KEY", raising=False)
        target = tmp_path / "api_key"
        monkeypatch.setattr(app_module, "API_KEY_FILE", str(target))
        monkeypatch.setattr(app_module, "DATA_DIR", str(tmp_path))

        first = app_module.load_api_key()
        assert len(first) >= 20
        assert target.read_text(encoding="utf-8").strip() == first
        # a second boot reuses it instead of rotating
        assert app_module.load_api_key() == first

    def test_no_hardcoded_default(self):
        """Shipping a default credential in the source ships a working
        credential to everyone who reads it. An empty default is fine; a
        populated one is the bug this guards against."""
        import re
        source = open(app_module.__file__, encoding="utf-8").read()
        pattern = r"""environ\.get\(\s*["']API_KEY["']\s*,\s*["'][^"']+["']"""
        populated = re.search(pattern, source)
        assert populated is None, f"hardcoded API key default: {populated.group(0)}"


class TestSourceTesting:
    """Adding a source blind means waiting a whole cycle to learn it returns
    nothing. This endpoint answers in seconds."""

    def test_needs_a_credential(self, client):
        assert client.post("/api/settings/test-source",
                           json={"url": "https://example.com"}).status_code == 401

    def test_rejects_a_non_http_url(self, client):
        for bad in ["file:///etc/passwd", "ftp://host/x", "not-a-url", ""]:
            r = client.post("/api/settings/test-source", json={"url": bad}, headers=KEY)
            assert r.status_code == 400, bad
            assert r.get_json()["ok"] is False

    def test_reports_what_a_source_yields(self, client, monkeypatch):
        import io

        class FakeResponse(io.BytesIO):
            def __enter__(self): return self
            def __exit__(self, *a): return False

        body = b"1.1.1.1:8080\n2.2.2.2:3128\nnot a proxy\n"
        monkeypatch.setattr(app_module.urllib.request, "urlopen",
                            lambda *a, **kw: FakeResponse(body))

        r = client.post("/api/settings/test-source",
                        json={"url": "https://example.com/list"}, headers=KEY)
        d = r.get_json()
        assert d["ok"] is True
        assert d["found"] == 2
        assert d["by_type"] == {"http": 2}
        assert d["sample"][0].startswith("http://")

    def test_reports_a_source_that_yields_nothing(self, client, monkeypatch):
        import io

        class FakeResponse(io.BytesIO):
            def __enter__(self): return self
            def __exit__(self, *a): return False

        monkeypatch.setattr(app_module.urllib.request, "urlopen",
                            lambda *a, **kw: FakeResponse(b"<html>rate limited</html>"))
        d = client.post("/api/settings/test-source",
                        json={"url": "https://example.com/list"}, headers=KEY).get_json()
        assert d["ok"] is False
        assert d["found"] == 0

    def test_reports_a_fetch_failure_without_raising(self, client, monkeypatch):
        def boom(*a, **kw):
            raise OSError("connection refused")

        monkeypatch.setattr(app_module.urllib.request, "urlopen", boom)
        r = client.post("/api/settings/test-source",
                        json={"url": "https://example.com/list"}, headers=KEY)
        assert r.status_code == 200
        d = r.get_json()
        assert d["ok"] is False
        assert "refused" in d["error"]

    def test_infers_the_protocol_from_the_url(self, client, monkeypatch):
        import io

        class FakeResponse(io.BytesIO):
            def __enter__(self): return self
            def __exit__(self, *a): return False

        monkeypatch.setattr(app_module.urllib.request, "urlopen",
                            lambda *a, **kw: FakeResponse(b"1.1.1.1:1080\n"))
        d = client.post("/api/settings/test-source",
                        json={"url": "https://api/?protocol=socks5"}, headers=KEY).get_json()
        assert d["by_type"] == {"socks5": 1}


class TestConfigurableSources:
    def test_validation_uses_the_configured_sources(self, monkeypatch, isolated_settings):
        seen = {}

        def fake_fetch(sources=None):
            seen["sources"] = sources
            return []

        monkeypatch.setattr(app_module.proxy_validator, "fetch_proxies", fake_fetch)
        isolated_settings.apply({"proxy_sources": ["https://mine/list"]})
        app_module.run_validation()
        assert seen["sources"] == ["https://mine/list"]


class TestSourceGuardOverApi:
    def test_test_source_refuses_an_internal_target(self, client, monkeypatch):
        """Otherwise the endpoint is a port scanner: responded / refused /
        timed out maps the network the server reaches and the caller does not."""
        monkeypatch.setattr(app_module.proxy_validator, "source_is_allowed",
                            lambda u: (False, "resolves to a private address"))
        r = client.post("/api/settings/test-source",
                        json={"url": "http://192.168.1.1/list"}, headers=KEY)
        assert r.status_code == 400
        assert "private" in r.get_json()["error"]

    def test_saving_an_internal_source_is_refused(self, client, isolated_settings, monkeypatch):
        monkeypatch.setattr(app_module.proxy_validator, "source_is_allowed",
                            lambda u: ("192.168" not in u, "resolves to a private address"))
        r = client.post("/api/settings",
                        json={"proxy_sources": ["http://192.168.1.1/list"]}, headers=KEY)
        assert r.status_code == 400
        assert isolated_settings.is_overridden("proxy_sources") is False

    def test_public_sources_still_save(self, client, isolated_settings, monkeypatch):
        monkeypatch.setattr(app_module.proxy_validator, "source_is_allowed",
                            lambda u: (True, ""))
        r = client.post("/api/settings",
                        json={"proxy_sources": ["https://public.example/list"]}, headers=KEY)
        assert r.status_code == 200
        assert isolated_settings.get("proxy_sources") == ["https://public.example/list"]

    def test_other_settings_do_not_pay_for_the_check(self, client, isolated_settings, monkeypatch):
        """Saving an unrelated setting must not trigger DNS resolution."""
        called = []
        monkeypatch.setattr(app_module.proxy_validator, "source_is_allowed",
                            lambda u: (called.append(u), (True, ""))[1])
        client.post("/api/settings", json={"dashboard_rows": 40}, headers=KEY)
        assert called == []


class TestImageContents:
    """The Dockerfile copies an explicit file list rather than the whole tree,
    which keeps the image small but means a new module is easy to forget. That
    mistake does not show up until the container refuses to boot, so it is
    worth catching here instead."""

    def _dockerfile_modules(self):
        root = os.path.dirname(os.path.dirname(os.path.abspath(app_module.__file__)))
        path = os.path.join(root, "proxy-monitor", "Dockerfile")
        if not os.path.exists(path):
            path = os.path.join(os.path.dirname(os.path.abspath(app_module.__file__)),
                                "Dockerfile")
        with open(path, encoding="utf-8") as f:
            for line in f:
                if line.startswith("COPY ") and ".py" in line:
                    return {p for p in line.split() if p.endswith(".py")}
        raise AssertionError("no COPY line for python modules in the Dockerfile")

    def test_every_local_module_app_imports_is_copied(self):
        import ast

        source_path = os.path.abspath(app_module.__file__)
        with open(source_path, encoding="utf-8") as f:
            tree = ast.parse(f.read())

        local = set()
        source_dir = os.path.dirname(source_path)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    name = alias.name.split(".")[0]
                    if os.path.exists(os.path.join(source_dir, name + ".py")):
                        local.add(name + ".py")

        copied = self._dockerfile_modules()
        missing = local - copied
        assert not missing, f"imported but never copied into the image: {sorted(missing)}"


class TestStabilityWiring:
    """The store reaching the API and the dashboard."""

    def test_rows_carry_a_verdict(self, client):
        seed(["http://1.1.1.1:80"], {"http://1.1.1.1:80": 0.5})
        row = client.get("/api/stats").get_json()["proxies"][0]
        assert "stability" in row
        assert row["stability"]["state"] in ("unknown", "unstable", "stable")

    def test_an_unmeasured_proxy_reports_unknown_not_unstable(self, client):
        seed(["http://1.1.1.1:80"], {"http://1.1.1.1:80": 0.5})
        row = client.get("/api/stats").get_json()["proxies"][0]
        assert row["stability"]["state"] == "unknown"

    def test_stats_count_the_states(self, client):
        seed(["http://1.1.1.1:80"], {"http://1.1.1.1:80": 0.5})
        stats = client.get("/api/stats").get_json()["stats"]
        for field in ("stable", "unstable", "unknown"):
            assert field in stats

    def test_stats_expose_the_recheck_cadence(self, client):
        data = client.get("/api/stats").get_json()
        for field in ("last_check", "next_check", "recheck_seconds", "stability_enabled"):
            assert field in data


class TestStableFilter:
    def _seed_mixed(self):
        good, bad = "http://1.1.1.1:80", "http://2.2.2.2:80"
        seed([good, bad], {good: 0.4, bad: 0.4})
        for _ in range(6):
            app_module.stability_store.record(good, 0.4)
            app_module.stability_store.record(bad, None)
        return good, bad

    def test_unfiltered_by_default(self, client):
        """The upgrade must not change what an existing consumer receives."""
        good, bad = self._seed_mixed()
        body = client.get("/proxy/all", headers=KEY).get_json()
        assert set(body["proxies"]) == {good, bad}
        assert body["stable_only"] is False

    def test_stable_true_narrows_the_list(self, client):
        good, _ = self._seed_mixed()
        body = client.get("/proxy/all?stable=true", headers=KEY).get_json()
        assert body["proxies"] == [good]
        assert body["stable_only"] is True

    def test_the_text_endpoint_filters_too(self, client):
        good, _ = self._seed_mixed()
        resp = client.get("/proxy/all.txt?stable=true", headers=KEY)
        assert resp.get_data(as_text=True).strip() == good

    def test_warming_up_does_not_empty_the_list(self, client):
        """Answering 200 with zero proxies for ten minutes after every deploy
        gets the service blamed for an outage it did not cause."""
        seed(["http://1.1.1.1:80"], {"http://1.1.1.1:80": 0.4})
        app_module.stability_store.record("http://1.1.1.1:80", 0.4)

        body = client.get("/proxy/all?stable=true", headers=KEY).get_json()
        assert body["proxies"] == ["http://1.1.1.1:80"]
        assert body["stable_only"] is False
        assert body["stability"]["warming_up"] is True

    def test_once_judged_an_empty_stable_list_is_reported_as_such(self, client):
        """The other half of the rule: the warm-up escape must not mask a real
        'everything died'."""
        seed(["http://1.1.1.1:80"], {"http://1.1.1.1:80": 0.4})
        for _ in range(6):
            app_module.stability_store.record("http://1.1.1.1:80", None)

        body = client.get("/proxy/all?stable=true", headers=KEY).get_json()
        assert body["proxies"] == []
        assert body["stable_only"] is True
        assert body["stability"]["warming_up"] is False

    def test_the_query_parameter_overrides_the_setting_both_ways(self, client, isolated_settings):
        good, _ = self._seed_mixed()
        isolated_settings.apply({"publish_stable_only": True})

        narrowed = client.get("/proxy/all", headers=KEY).get_json()
        assert narrowed["proxies"] == [good]

        widened = client.get("/proxy/all?stable=false", headers=KEY).get_json()
        assert len(widened["proxies"]) == 2


class TestRecheckLoop:
    def test_it_skips_while_a_full_cycle_holds_the_lock(self):
        """Queuing would re-test proxies checked seconds earlier, and bias every
        window toward the moment just after discovery."""
        app_module._validation_lock.acquire()
        try:
            assert app_module.recheck_once() is False
        finally:
            app_module._validation_lock.release()

    def test_nothing_to_recheck_is_not_an_error(self):
        assert app_module.recheck_once() is False

    def test_it_records_samples_and_republishes(self, monkeypatch):
        seed(["http://1.1.1.1:80"], {"http://1.1.1.1:80": 0.9})
        monkeypatch.setattr(
            app_module.proxy_validator, "validate_all_detailed",
            lambda *a, **kw: {"http://1.1.1.1:80": app_module.proxy_validator.Result(
                "http://1.1.1.1:80", True, 0.3)})

        assert app_module.recheck_once() is True
        with app_module._lock:
            assert app_module._state["proxy_data"][0]["latency"] == 0.3
            assert app_module._state["last_check"] is not None

    def test_it_leaves_the_discovery_fields_alone(self, monkeypatch):
        """The published list is a discovery artifact; a re-check annotates it
        and must not claim a new scan happened."""
        seed(["http://1.1.1.1:80"], {"http://1.1.1.1:80": 0.9})
        app_module._set_state(last_run="2026-01-01T00:00:00Z", duration=42.0,
                              source_count=3000)
        monkeypatch.setattr(
            app_module.proxy_validator, "validate_all_detailed",
            lambda *a, **kw: {"http://1.1.1.1:80": app_module.proxy_validator.Result(
                "http://1.1.1.1:80", False)})

        app_module.recheck_once()
        with app_module._lock:
            assert app_module._state["last_run"] == "2026-01-01T00:00:00Z"
            assert app_module._state["duration"] == 42.0
            assert app_module._state["source_count"] == 3000
            assert app_module._state["proxies"] == ["http://1.1.1.1:80"]

    def test_a_failed_recheck_counts_against_the_proxy(self, monkeypatch):
        seed(["http://1.1.1.1:80"], {"http://1.1.1.1:80": 0.9})
        monkeypatch.setattr(
            app_module.proxy_validator, "validate_all_detailed",
            lambda *a, **kw: {"http://1.1.1.1:80": app_module.proxy_validator.Result(
                "http://1.1.1.1:80", False)})

        app_module.recheck_once()
        view = app_module.stability_store.view("http://1.1.1.1:80")
        assert view["checks"] == 1
        assert view["success_rate"] == 0.0


class TestStabilityDisabled:
    def test_everything_reports_unknown(self, client, isolated_settings):
        """Off must look like 'nothing was measured', never like 'nothing is
        stable' — the second is a claim, and a false one."""
        isolated_settings.apply({"stability_enabled": False})
        seed(["http://1.1.1.1:80"], {"http://1.1.1.1:80": 0.4})
        for _ in range(6):
            app_module.stability_store.record("http://1.1.1.1:80", 0.4)

        row = client.get("/api/stats").get_json()["proxies"][0]
        assert row["stability"]["state"] == "unknown"

    def test_the_filter_becomes_a_no_op(self, client, isolated_settings):
        isolated_settings.apply({"stability_enabled": False})
        seed(["http://1.1.1.1:80"], {"http://1.1.1.1:80": 0.4})
        body = client.get("/proxy/all?stable=true", headers=KEY).get_json()
        assert body["proxies"] == ["http://1.1.1.1:80"]


class TestSchedulerGating:
    def test_disable_scheduler_stops_both_loops(self):
        """The suite sets DISABLE_SCHEDULER=1. If the re-check loop ignored it,
        every pytest run would open real connections to the internet."""
        import threading
        running = {t.name for t in threading.enumerate()}
        assert "proxy-recheck" not in running
        assert "proxy-validator" not in running


class TestScheduledCycleWaits:
    """Regression: the scheduled cycle used the same non-blocking acquire as a
    manual trigger, so whenever a re-check pass held the lock the cycle was
    dropped and the next one was twenty minutes away. Observed in production —
    the published list aged 40 minutes instead of 20, and the stable count
    decayed because nothing replaced the dead proxies."""

    def test_a_scheduled_cycle_waits_for_a_recheck_to_finish(self, monkeypatch):
        import threading

        monkeypatch.setattr(app_module, "_LOCK_WAIT_SECONDS", 5)
        monkeypatch.setattr(app_module.proxy_validator, "fetch_proxies",
                            lambda sources=None: ["http://1.1.1.1:80"])
        monkeypatch.setattr(
            app_module.proxy_validator, "validate_all_detailed",
            lambda *a, **kw: {"http://1.1.1.1:80": app_module.proxy_validator.Result(
                "http://1.1.1.1:80", True, 0.5)})

        app_module._validation_lock.acquire()
        released = threading.Event()

        def hold_briefly():
            released.wait(timeout=2)
            app_module._validation_lock.release()

        holder = threading.Thread(target=hold_briefly, daemon=True)
        holder.start()
        released.set()

        app_module.run_validation(wait=True)
        holder.join(timeout=5)

        with app_module._lock:
            assert app_module._state["last_run"] is not None

    def test_a_manual_trigger_still_refuses_to_wait(self, monkeypatch):
        """/api/refresh must answer at once rather than block the request."""
        calls = []
        monkeypatch.setattr(app_module.proxy_validator, "fetch_proxies",
                            lambda sources=None: calls.append(1) or [])

        app_module._validation_lock.acquire()
        try:
            app_module.run_validation()
        finally:
            app_module._validation_lock.release()
        assert calls == []

    def test_the_scheduler_asks_to_wait(self):
        """The wiring, not just the capability: a scheduler calling the default
        would reintroduce the bug silently."""
        import inspect
        source = inspect.getsource(app_module.scheduler_loop)
        assert "run_validation(wait=True)" in source
        assert "\n        run_validation()" not in source


class TestQualityOrdering:
    """Latency alone puts a fast proxy that fails half the time above a
    dependable one — backwards for a consumer taking the first N."""

    def _seed_three(self):
        fast_flaky = "http://1.1.1.1:80"
        slow_solid = "http://2.2.2.2:80"
        unmeasured = "http://3.3.3.3:80"
        seed([fast_flaky, slow_solid, unmeasured],
             {fast_flaky: 0.2, slow_solid: 2.0})
        for _ in range(6):
            app_module.stability_store.record(slow_solid, 2.0)
        for i in range(6):
            app_module.stability_store.record(fast_flaky, 0.2 if i % 2 else None)
        return fast_flaky, slow_solid, unmeasured

    def test_stable_beats_fast(self, client):
        fast_flaky, slow_solid, _ = self._seed_three()
        order = client.get("/proxy/all", headers=KEY).get_json()["proxies"]
        assert order.index(slow_solid) < order.index(fast_flaky)

    def test_latency_sort_is_still_available(self, client):
        fast_flaky, slow_solid, _ = self._seed_three()
        order = client.get("/proxy/all?sort=latency", headers=KEY).get_json()["proxies"]
        assert order.index(fast_flaky) < order.index(slow_solid)

    def test_stable_sort_is_diff_friendly(self, client):
        """A list that reshuffles every request makes a consumer filter out
        reordering noise to see real changes."""
        self._seed_three()
        first = client.get("/proxy/all?sort=stable", headers=KEY).get_json()["proxies"]
        second = client.get("/proxy/all?sort=stable", headers=KEY).get_json()["proxies"]
        assert first == second == sorted(first)

    def test_unmeasured_lands_between_stable_and_unstable(self, client):
        """Unknown is not a failure, so it must not sort below one."""
        fast_flaky, slow_solid, unmeasured = self._seed_three()
        order = client.get("/proxy/all", headers=KEY).get_json()["proxies"]
        assert order.index(slow_solid) < order.index(unmeasured) < order.index(fast_flaky)


class TestCountryFilter:
    def _seed_with_countries(self, monkeypatch):
        monkeypatch.setattr(app_module, "fetch_countries",
                            lambda ips: {"1.1.1.1": "Brazil", "2.2.2.2": "Germany"})
        seed(["http://1.1.1.1:80", "http://2.2.2.2:80"],
             {"http://1.1.1.1:80": 0.5, "http://2.2.2.2:80": 0.5})

    def test_narrows_to_one_country(self, client, monkeypatch):
        self._seed_with_countries(monkeypatch)
        got = client.get("/proxy/all?country=Brazil", headers=KEY).get_json()["proxies"]
        assert got == ["http://1.1.1.1:80"]

    def test_case_insensitive_and_multiple(self, client, monkeypatch):
        self._seed_with_countries(monkeypatch)
        got = client.get("/proxy/all?country=brazil,GERMANY", headers=KEY).get_json()["proxies"]
        assert len(got) == 2

    def test_no_parameter_keeps_everything(self, client, monkeypatch):
        self._seed_with_countries(monkeypatch)
        assert len(client.get("/proxy/all", headers=KEY).get_json()["proxies"]) == 2

    def test_an_unknown_country_returns_nothing_rather_than_everything(self, client, monkeypatch):
        """Silently ignoring a filter nobody matched would hand back the full
        list as if it were the answer."""
        self._seed_with_countries(monkeypatch)
        assert client.get("/proxy/all?country=Narnia", headers=KEY).get_json()["proxies"] == []


class TestTextTemplate:
    def test_plain_output_is_unchanged(self, client):
        seed(["http://1.1.1.1:80"], {"http://1.1.1.1:80": 0.5})
        body = client.get("/proxy/all.txt", headers=KEY).get_data(as_text=True)
        assert body.strip() == "http://1.1.1.1:80"

    def test_fields_are_substituted(self, client, monkeypatch):
        monkeypatch.setattr(app_module, "fetch_countries", lambda ips: {"1.1.1.1": "Brazil"})
        seed(["http://1.1.1.1:80"], {"http://1.1.1.1:80": 0.5})
        body = client.get("/proxy/all.txt?format={{ip}}:{{port}}|{{country}}|{{protocol}}",
                          headers=KEY).get_data(as_text=True)
        assert body.strip() == "1.1.1.1:80|Brazil|http"

    def test_a_missing_value_renders_empty_not_none(self, client):
        """`None` in a text line is a Python leak, not a value."""
        seed(["http://1.1.1.1:80"], {})
        body = client.get("/proxy/all.txt?format={{full}}|{{latency}}|{{country}}",
                          headers=KEY).get_data(as_text=True)
        assert body.strip() == "http://1.1.1.1:80||"

    def test_an_unknown_placeholder_is_left_alone(self, client):
        seed(["http://1.1.1.1:80"], {"http://1.1.1.1:80": 0.5})
        body = client.get("/proxy/all.txt?format={{full}} {{nope}}",
                          headers=KEY).get_data(as_text=True)
        assert "{{nope}}" in body

    def test_the_template_carries_the_stability_verdict(self, client):
        seed(["http://1.1.1.1:80"], {"http://1.1.1.1:80": 0.5})
        for _ in range(6):
            app_module.stability_store.record("http://1.1.1.1:80", 0.4)
        body = client.get("/proxy/all.txt?format={{full}}|{{stability}}",
                          headers=KEY).get_data(as_text=True)
        assert body.strip().endswith("|stable")


class TestCacheKeepsWhatWeMeasured:
    """The list survived a restart; what we knew about it did not. The
    dashboard showed a full table above 0s/0s/0s, and ?sort=latency degraded
    to alphabetical, for the eight minutes until the first cycle landed."""

    def _write_cache(self, tmp_path, monkeypatch, meta):
        import json as _json
        target = tmp_path / "proxies.txt"
        monkeypatch.setattr(app_module, "OUTPUT_FILE", str(target))
        monkeypatch.setattr(app_module, "DATA_DIR", str(tmp_path))
        monkeypatch.setattr(app_module, "CACHE_META_FILE", str(target) + ".meta.json")
        app_module.write_output_file(["http://1.1.1.1:80", "http://2.2.2.2:80"], meta)
        return target

    def test_latencies_come_back(self, tmp_path, monkeypatch):
        self._write_cache(tmp_path, monkeypatch, {
            "last_run": "2026-01-01T00:00:00Z",
            "latencies": {"http://1.1.1.1:80": 0.4, "http://2.2.2.2:80": 2.1},
        })
        app_module.load_cached_proxies()
        with app_module._lock:
            rows = {p["full"]: p for p in app_module._state["proxy_data"]}
            assert rows["http://1.1.1.1:80"]["latency"] == 0.4
            assert app_module._state["stats"]["min_latency"] == 0.4

    def test_exit_addresses_come_back(self, tmp_path, monkeypatch):
        self._write_cache(tmp_path, monkeypatch, {
            "last_run": "2026-01-01T00:00:00Z",
            "exit_ips": {"http://1.1.1.1:80": "9.9.9.9"},
        })
        app_module.load_cached_proxies()
        with app_module._lock:
            rows = {p["full"]: p for p in app_module._state["proxy_data"]}
            assert rows["http://1.1.1.1:80"]["exit_ip"] == "9.9.9.9"

    def test_a_cache_without_measurements_still_loads(self, tmp_path, monkeypatch):
        """Files written by the previous version carry only the three scalars."""
        self._write_cache(tmp_path, monkeypatch, {"last_run": "2026-01-01T00:00:00Z"})
        app_module.load_cached_proxies()
        with app_module._lock:
            assert len(app_module._state["proxies"]) == 2
            assert app_module._state["stats"]["min_latency"] == 0

    def test_garbage_measurements_are_ignored_not_trusted(self, tmp_path, monkeypatch):
        self._write_cache(tmp_path, monkeypatch, {
            "latencies": {"http://1.1.1.1:80": "fast", "http://2.2.2.2:80": 1.5},
            "exit_ips": {"http://1.1.1.1:80": 42},
        })
        app_module.load_cached_proxies()
        with app_module._lock:
            rows = {p["full"]: p for p in app_module._state["proxy_data"]}
            assert rows["http://1.1.1.1:80"]["latency"] is None
            assert rows["http://1.1.1.1:80"]["exit_ip"] is None
            assert rows["http://2.2.2.2:80"]["latency"] == 1.5


class TestBadgeStaysHonest:
    """The README claims a test count, and a number in a document drifts on the
    very next commit. It drifted twice before this test existed."""

    def test_the_readme_badge_matches_the_suite(self):
        import ast
        import glob
        import re

        root = os.path.dirname(os.path.dirname(os.path.abspath(app_module.__file__)))
        readme = os.path.join(root, "proxy-monitor", "README.md")
        if not os.path.exists(readme):
            readme = os.path.join(os.path.dirname(os.path.abspath(app_module.__file__)),
                                  "README.md")
        with open(readme, encoding="utf-8") as f:
            claimed = re.search(r"tests-(\d+)%20passing", f.read())
        assert claimed, "no test badge in the README"

        tests_dir = os.path.dirname(os.path.abspath(__file__))
        actual = 0
        for path in glob.glob(os.path.join(tests_dir, "test_*.py")):
            with open(path, encoding="utf-8") as f:
                tree = ast.parse(f.read())
            actual += sum(
                1 for node in ast.walk(tree)
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                and node.name.startswith("test_"))

        assert int(claimed.group(1)) == actual, (
            f"README says {claimed.group(1)} tests, the suite has {actual}")
