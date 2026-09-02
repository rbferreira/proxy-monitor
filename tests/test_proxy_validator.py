"""Parsing, normalization and protocol filtering."""
import proxy_validator as pv


class TestNormalizeProxy:
    def test_with_scheme(self):
        assert pv.normalize_proxy("http://1.2.3.4:8080") == "http://1.2.3.4:8080"
        assert pv.normalize_proxy("socks5://5.6.7.8:1080") == "socks5://5.6.7.8:1080"

    def test_without_scheme_uses_default(self):
        assert pv.normalize_proxy("1.2.3.4:8080") == "http://1.2.3.4:8080"
        assert pv.normalize_proxy("1.2.3.4:1080", "socks5") == "socks5://1.2.3.4:1080"

    def test_lowercases(self):
        assert pv.normalize_proxy("HTTP://1.2.3.4:8080") == "http://1.2.3.4:8080"

    def test_rejects_junk(self):
        # Sources sometimes answer with an HTML error page; without this filter
        # every junk line becomes a validation thread with a real timeout.
        assert pv.normalize_proxy("") is None
        assert pv.normalize_proxy("   ") is None
        assert pv.normalize_proxy("# a comment") is None
        assert pv.normalize_proxy("<html><body>Rate limited</body></html>") is None
        assert pv.normalize_proxy("ftp://1.2.3.4:21") is None
        assert pv.normalize_proxy("http://1.2.3.4") is None          # no port
        assert pv.normalize_proxy("http://1.2.3.4:abc") is None      # non-numeric port
        assert pv.normalize_proxy("http://1.2.3.4:0") is None        # out of range
        assert pv.normalize_proxy("http://1.2.3.4:70000") is None
        assert pv.normalize_proxy("http://:8080") is None            # no host

    def test_trims_whitespace(self):
        assert pv.normalize_proxy("  http://1.2.3.4:8080  ") == "http://1.2.3.4:8080"


class TestSchemeForSource:
    def test_infers_from_protocol_param(self):
        assert pv.scheme_for_source("https://api/?protocol=socks5&x=1") == "socks5"
        assert pv.scheme_for_source("https://api/?protocol=socks4") == "socks4"
        assert pv.scheme_for_source("https://api/?protocol=http") == "http"

    def test_defaults_to_http(self):
        assert pv.scheme_for_source("https://api/?request=display_proxies") == "http"


class TestToRequestsScheme:
    def test_socks_gets_remote_dns(self):
        assert pv.to_requests_scheme("socks5://1.2.3.4:1080") == "socks5h://1.2.3.4:1080"
        assert pv.to_requests_scheme("socks4://1.2.3.4:1080") == "socks4a://1.2.3.4:1080"

    def test_http_unchanged(self):
        assert pv.to_requests_scheme("http://1.2.3.4:8080") == "http://1.2.3.4:8080"


class TestFilterByType:
    def test_keeps_only_requested(self):
        entries = [
            "socks4://9.9.9.9:1080",
            "http://2.2.2.2:8080",
            "http://1.1.1.1:8080",
            "socks5://3.3.3.3:1080",
        ]
        assert pv.filter_by_type(entries, ["http", "socks5"]) == [
            "http://1.1.1.1:8080",
            "http://2.2.2.2:8080",
            "socks5://3.3.3.3:1080",
        ]

    def test_none_keeps_everything(self):
        entries = ["socks4://9.9.9.9:1080", "http://1.1.1.1:80"]
        assert len(pv.filter_by_type(entries, None)) == 2

    def test_deduplicates_and_lowercases(self):
        assert pv.filter_by_type(["http://1.1.1.1:80", "HTTP://1.1.1.1:80"]) == ["http://1.1.1.1:80"]

    def test_ignores_unknown_scheme(self):
        assert pv.filter_by_type(["ftp://1.1.1.1:21", "http://1.1.1.1:80"], ["http", "ftp"]) == [
            "http://1.1.1.1:80"
        ]

    def test_tolerates_blank_entries_in_types(self):
        assert pv.filter_by_type(["http://1.1.1.1:80"], ["http", "", "  "]) == ["http://1.1.1.1:80"]


class TestProxyType:
    def test_extracts_scheme(self):
        assert pv.proxy_type("socks5://1.1.1.1:1080") == "socks5"
        assert pv.proxy_type("HTTP://1.1.1.1:80") == "http"

    def test_none_without_scheme(self):
        assert pv.proxy_type("1.1.1.1:80") is None


class TestValidateAll:
    def test_filters_out_failures(self, monkeypatch):
        """Regression: an early version tested `if fut.result():` against a tuple,
        which is always truthy — every proxy passed, including the failing ones."""
        def fake_validate(proxy, test_urls, max_latency):
            return (True, 0.5) if proxy.endswith(":80") else (False, None)

        monkeypatch.setattr(pv, "validate", fake_validate)
        result = pv.validate_all(
            ["http://1.1.1.1:80", "http://2.2.2.2:9999", "http://3.3.3.3:80"],
            workers=2,
        )
        assert result == {"http://1.1.1.1:80": 0.5, "http://3.3.3.3:80": 0.5}

    def test_empty_list(self):
        assert pv.validate_all([]) == {}

    def test_worker_exception_does_not_abort_the_run(self, monkeypatch):
        def fake_validate(proxy, test_urls, max_latency):
            if proxy.endswith(":80"):
                raise RuntimeError("boom")
            return (True, 1.0)

        monkeypatch.setattr(pv, "validate", fake_validate)
        assert pv.validate_all(["http://1.1.1.1:80", "http://2.2.2.2:8080"], workers=2) == {
            "http://2.2.2.2:8080": 1.0
        }


class TestValidate:
    def test_measures_end_to_end_latency(self, monkeypatch):
        """Latency must include connection and handshake, not just `resp.elapsed`."""
        import time

        class FakeResp:
            status_code = 200

        def slow_get(url, **kwargs):
            time.sleep(0.05)
            return FakeResp()

        monkeypatch.setattr(pv.requests, "get", slow_get)
        ok, latency = pv.validate("http://1.1.1.1:80", ["https://test"], max_latency=5.0)
        assert ok
        assert latency >= 0.05

    def test_rejects_above_the_cutoff(self, monkeypatch):
        import time

        class FakeResp:
            status_code = 200

        def slow_get(url, **kwargs):
            time.sleep(0.2)
            return FakeResp()

        monkeypatch.setattr(pv.requests, "get", slow_get)
        assert pv.validate("http://1.1.1.1:80", ["https://test"], max_latency=0.1) == (False, None)

    def test_rejects_error_status(self, monkeypatch):
        class FakeResp:
            status_code = 502

        monkeypatch.setattr(pv.requests, "get", lambda url, **kw: FakeResp())
        assert pv.validate("http://1.1.1.1:80", ["https://test"], max_latency=5.0) == (False, None)

    def test_falls_through_to_the_next_url(self, monkeypatch):
        class FakeResp:
            status_code = 200

        calls = []

        def get(url, **kwargs):
            calls.append(url)
            if url == "https://first":
                raise OSError("connection refused")
            return FakeResp()

        monkeypatch.setattr(pv.requests, "get", get)
        ok, _ = pv.validate("http://1.1.1.1:80", ["https://first", "https://second"], 5.0)
        assert ok
        assert calls == ["https://first", "https://second"]


class TestSourcesFromEnv:
    def test_unset(self, monkeypatch):
        monkeypatch.delenv("PROXY_SOURCES", raising=False)
        assert pv.sources_from_env() is None

    def test_comma_or_newline_separated(self, monkeypatch):
        monkeypatch.setenv("PROXY_SOURCES", "https://a/list, https://b/list")
        assert pv.sources_from_env() == ["https://a/list", "https://b/list"]
        monkeypatch.setenv("PROXY_SOURCES", "https://a/list\nhttps://b/list\n")
        assert pv.sources_from_env() == ["https://a/list", "https://b/list"]


class TestTestProtocol:
    """Real traffic is HTTPS. Validating over plain HTTP does not exercise
    CONNECT and accepts proxies that fail in practice — measured at 75% of the
    list in one run."""

    def test_default_urls_are_https(self):
        assert all(u.startswith("https://") for u in pv.DEFAULT_TEST_URLS)

    def test_http_alternative_exists_for_comparison(self):
        assert all(u.startswith("http://") for u in pv.HTTP_TEST_URLS)

    def test_validate_uses_https_by_default(self, monkeypatch):
        seen = []

        class FakeResp:
            status_code = 200

        def get(url, **kw):
            seen.append(url)
            return FakeResp()

        monkeypatch.setattr(pv.requests, "get", get)
        ok, _ = pv.validate("http://1.1.1.1:80")
        assert ok
        assert seen[0].startswith("https://")
