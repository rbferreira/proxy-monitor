"""Flask routes, authentication, snapshot building and the settings API."""
import os

import pytest

os.environ.setdefault("API_KEY", "test-key")
os.environ.setdefault("DISABLE_SCHEDULER", "1")  # no scheduler during tests
os.environ.setdefault("GEOLOOKUP", "false")      # no calls to ip-api.com

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
    app_module._country_cache.clear()
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
        monkeypatch.setattr(app_module.proxy_validator, "validate_all",
                            lambda *a, **kw: {"http://1.1.1.1:80": 0.5})

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
