"""Parsing, normalization and protocol filtering."""
import pytest

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
        def fake_validate(proxy, test_urls, max_latency, samples=1):
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
        def fake_validate(proxy, test_urls, max_latency, samples=1):
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
        ok, _ = pv.validate("http://1.1.1.1:80", ["https://first", "https://second"], 5.0,
                            samples=1)
        assert ok
        assert calls == ["https://first", "https://second"]

    def test_extra_samples_stay_on_the_url_that_answered(self, monkeypatch):
        """Re-sampling must not walk back through the list: measuring two
        different servers would report the distance between them, not the
        proxy."""
        class FakeResp:
            status_code = 200

        calls = []

        def get(url, **kwargs):
            calls.append(url)
            if url == "https://first":
                raise OSError("connection refused")
            return FakeResp()

        monkeypatch.setattr(pv.requests, "get", get)
        ok, _ = pv.validate("http://1.1.1.1:80", ["https://first", "https://second"], 5.0,
                            samples=3)
        assert ok
        assert calls == ["https://first"] + ["https://second"] * 3


class TestLatencySamples:
    """The median of a few samples, so one hiccup does not become a property of
    the proxy."""

    def _timed(self, monkeypatch, durations):
        """A fake clock, so the test asserts on arithmetic rather than sleeping."""
        class FakeResp:
            status_code = 200

        ticks = iter(range(10_000))
        pending = list(durations)
        now = [0.0]

        def perf_counter():
            return now[0]

        def get(url, **kwargs):
            next(ticks)
            step = pending.pop(0)
            if step is None:
                raise OSError("refused")
            now[0] += step
            return FakeResp()

        monkeypatch.setattr(pv.time, "perf_counter", perf_counter)
        monkeypatch.setattr(pv.requests, "get", get)

    def test_reports_the_median_not_the_first(self, monkeypatch):
        self._timed(monkeypatch, [0.5, 3.0, 0.6])
        ok, latency = pv.validate("http://1.1.1.1:80", ["https://x"], 5.0, samples=3)
        assert ok
        assert latency == 0.6

    def test_one_outlier_does_not_drag_the_result(self, monkeypatch):
        """A mean would report 1.37s here; the median reports what the proxy
        actually does most of the time."""
        self._timed(monkeypatch, [0.4, 0.4, 3.3])
        _, latency = pv.validate("http://1.1.1.1:80", ["https://x"], 5.0, samples=3)
        assert latency == 0.4

    def test_a_single_sample_is_the_old_behaviour(self, monkeypatch):
        self._timed(monkeypatch, [0.9])
        ok, latency = pv.validate("http://1.1.1.1:80", ["https://x"], 5.0, samples=1)
        assert ok and latency == 0.9

    def test_a_failed_repeat_counts_against_the_proxy(self, monkeypatch):
        """An intermittent proxy must not report the latency of its good runs
        only. The failed sample lands at the cutoff, so the median suffers."""
        self._timed(monkeypatch, [0.4, None, None])
        ok, latency = pv.validate("http://1.1.1.1:80", ["https://x"], 5.0, samples=3)
        assert ok is False and latency is None

    def test_a_slow_first_look_skips_the_extra_samples(self, monkeypatch):
        """Already over budget: more samples cannot rescue it, so do not pay."""
        calls = []

        class FakeResp:
            status_code = 200

        now = [0.0]

        def get(url, **kwargs):
            calls.append(url)
            now[0] += 9.0
            return FakeResp()

        monkeypatch.setattr(pv.time, "perf_counter", lambda: now[0])
        monkeypatch.setattr(pv.requests, "get", get)

        ok, _ = pv.validate("http://1.1.1.1:80", ["https://x"], 5.0, samples=5)
        assert ok is False
        assert len(calls) == 1

    def test_zero_or_negative_is_treated_as_one(self, monkeypatch):
        self._timed(monkeypatch, [0.7])
        ok, latency = pv.validate("http://1.1.1.1:80", ["https://x"], 5.0, samples=0)
        assert ok and latency == 0.7


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


class TestInternalSourceGuard:
    """The service fetches whatever URL it is handed, so an operator could
    otherwise point it at hosts only the server can reach — a router, an
    unauthenticated panel, or a cloud metadata endpoint handing out credentials."""

    def test_detects_loopback(self, monkeypatch):
        monkeypatch.setattr(pv.socket, "getaddrinfo",
                            lambda *a, **kw: [(2, 1, 6, "", ("127.0.0.1", 0))])
        assert pv.resolves_to_internal("localhost") is True

    def test_detects_rfc1918(self, monkeypatch):
        for addr in ("10.0.0.1", "172.16.5.5", "192.168.1.1"):
            monkeypatch.setattr(pv.socket, "getaddrinfo",
                                lambda *a, **kw: [(2, 1, 6, "", (addr, 0))])
            assert pv.resolves_to_internal("host.internal") is True, addr

    def test_detects_link_local_metadata(self, monkeypatch):
        """169.254.169.254 is the cloud metadata endpoint — the classic escalation."""
        monkeypatch.setattr(pv.socket, "getaddrinfo",
                            lambda *a, **kw: [(2, 1, 6, "", ("169.254.169.254", 0))])
        assert pv.resolves_to_internal("metadata") is True

    def test_allows_a_public_address(self, monkeypatch):
        monkeypatch.setattr(pv.socket, "getaddrinfo",
                            lambda *a, **kw: [(2, 1, 6, "", ("93.184.216.34", 0))])
        assert pv.resolves_to_internal("example.com") is False

    def test_blocks_when_any_answer_is_internal(self, monkeypatch):
        """A name resolving to both a public and a private address is still a
        way in — the connection could land on either."""
        monkeypatch.setattr(pv.socket, "getaddrinfo", lambda *a, **kw: [
            (2, 1, 6, "", ("93.184.216.34", 0)),
            (2, 1, 6, "", ("192.168.0.5", 0)),
        ])
        assert pv.resolves_to_internal("mixed.example") is True

    def test_empty_hostname_is_refused(self):
        assert pv.resolves_to_internal("") is True
        assert pv.resolves_to_internal(None) is True

    def test_unresolvable_name_is_allowed_through(self, monkeypatch):
        """The fetch will fail on its own; guessing here would block a legitimate
        host that happens to be down."""
        def boom(*a, **kw):
            raise pv.socket.gaierror("nope")
        monkeypatch.setattr(pv.socket, "getaddrinfo", boom)
        assert pv.resolves_to_internal("down.example.com") is False

    def test_source_is_allowed_reports_a_reason(self, monkeypatch):
        monkeypatch.setattr(pv, "ALLOW_INTERNAL_SOURCES", False)
        monkeypatch.setattr(pv, "resolves_to_internal", lambda h: True)
        allowed, reason = pv.source_is_allowed("http://192.168.1.1/list")
        assert allowed is False
        assert "ALLOW_INTERNAL_SOURCES" in reason

    def test_opt_in_lets_internal_through(self, monkeypatch):
        """Someone genuinely hosting their list on a private box must be able to."""
        monkeypatch.setattr(pv, "ALLOW_INTERNAL_SOURCES", True)
        monkeypatch.setattr(pv, "resolves_to_internal", lambda h: True)
        allowed, _ = pv.source_is_allowed("http://192.168.1.1/list")
        assert allowed is True

    def test_fetch_skips_a_blocked_source(self, monkeypatch):
        monkeypatch.setattr(pv, "source_is_allowed", lambda u: (False, "blocked"))
        assert pv.fetch_proxies(["http://192.168.1.1/list"]) == []

    def test_fetch_keeps_going_past_a_blocked_source(self, monkeypatch):
        import io

        class FakeResponse(io.BytesIO):
            def __enter__(self): return self
            def __exit__(self, *a): return False

        monkeypatch.setattr(pv, "source_is_allowed",
                            lambda u: (("192.168" not in u), "blocked"))
        monkeypatch.setattr(pv.urllib.request, "urlopen",
                            lambda *a, **kw: FakeResponse(b"1.1.1.1:8080\n"))
        out = pv.fetch_proxies(["http://192.168.1.1/list", "https://public.example/list"])
        assert out == ["http://1.1.1.1:8080"]


class TestParseIdentity:
    """Identity services answer in two shapes, and neither is negotiable."""

    def test_a_bare_address(self):
        assert pv.parse_identity("203.0.113.7\n") == "203.0.113.7"

    def test_a_json_object(self):
        assert pv.parse_identity('{"ip":"203.0.113.7"}') == "203.0.113.7"

    def test_ipv6(self):
        assert pv.parse_identity("2001:db8::1") == "2001:db8::1"

    def test_an_html_error_page_is_not_an_address(self):
        """A captive portal or an error page answers 200 with a body. Without
        this check its text would be recorded as the exit address."""
        assert pv.parse_identity("<html><body>Access denied</body></html>") is None

    def test_json_carrying_something_that_is_not_an_address(self):
        assert pv.parse_identity('{"ip":"not-an-ip"}') is None

    def test_empty_and_whitespace(self):
        assert pv.parse_identity("") is None
        assert pv.parse_identity("   \n ") is None


class TestDetectExitIp:
    def test_returns_the_address_the_service_reports(self, monkeypatch):
        class FakeResp:
            status_code = 200
            text = "203.0.113.7"

        monkeypatch.setattr(pv.requests, "get", lambda url, **kw: FakeResp())
        assert pv.detect_exit_ip("http://1.1.1.1:80") == "203.0.113.7"

    def test_falls_through_when_the_first_service_is_down(self, monkeypatch):
        """The reason the endpoint is a list: one hardcoded service that
        rate-limits would make every proxy look like it has no exit address."""
        seen = []

        class FakeResp:
            status_code = 200
            text = "203.0.113.7"

        def get(url, **kw):
            seen.append(url)
            if len(seen) == 1:
                raise OSError("rate limited")
            return FakeResp()

        monkeypatch.setattr(pv.requests, "get", get)
        assert pv.detect_exit_ip("http://1.1.1.1:80") == "203.0.113.7"
        assert len(seen) == 2

    def test_skips_an_error_status(self, monkeypatch):
        class Resp:
            def __init__(self, code, text):
                self.status_code, self.text = code, text

        answers = iter([Resp(429, "slow down"), Resp(200, "203.0.113.9")])
        monkeypatch.setattr(pv.requests, "get", lambda url, **kw: next(answers))
        assert pv.detect_exit_ip("http://1.1.1.1:80") == "203.0.113.9"

    def test_every_service_failing_is_unknown_not_an_error(self, monkeypatch):
        monkeypatch.setattr(pv.requests, "get",
                            lambda url, **kw: (_ for _ in ()).throw(OSError("no route")))
        assert pv.detect_exit_ip("http://1.1.1.1:80") is None


class TestValidateAllDetailed:
    """Unlike validate_all, this reports failures — which is the difference
    between 'this proxy failed' and 'this proxy was never tried'."""

    def test_failures_are_present_as_values(self, monkeypatch):
        monkeypatch.setattr(pv, "validate",
                            lambda p, u, m, s: (True, 0.5) if p.endswith(":80") else (False, None))
        monkeypatch.setattr(pv, "detect_exit_ip", lambda p, **kw: "203.0.113.7")

        out = pv.validate_all_detailed(["http://1.1.1.1:80", "http://2.2.2.2:9999"], workers=2)

        assert out["http://1.1.1.1:80"].ok is True
        assert out["http://2.2.2.2:9999"].ok is False
        assert out["http://2.2.2.2:9999"].latency is None

    def test_only_passing_proxies_are_asked_for_an_exit_address(self, monkeypatch):
        """The extra request must fall on the ~12% that work, not on everything."""
        asked = []
        monkeypatch.setattr(pv, "validate",
                            lambda p, u, m, s: (True, 0.5) if p.endswith(":80") else (False, None))
        monkeypatch.setattr(pv, "detect_exit_ip", lambda p, **kw: asked.append(p) or "203.0.113.7")

        pv.validate_all_detailed(
            ["http://1.1.1.1:80", "http://2.2.2.2:9999", "http://3.3.3.3:9999"], workers=2)
        assert asked == ["http://1.1.1.1:80"]

    def test_exit_detection_can_be_switched_off(self, monkeypatch):
        monkeypatch.setattr(pv, "validate", lambda p, u, m, s: (True, 0.5))
        monkeypatch.setattr(pv, "detect_exit_ip",
                            lambda p, **kw: pytest.fail("should not be called"))

        out = pv.validate_all_detailed(["http://1.1.1.1:80"], with_exit_ip=False)
        assert out["http://1.1.1.1:80"].exit_ip is None

    def test_a_worker_exception_is_a_failure_not_a_gap(self, monkeypatch):
        def boom(p, u, m, s):
            raise RuntimeError("boom")

        monkeypatch.setattr(pv, "validate", boom)
        out = pv.validate_all_detailed(["http://1.1.1.1:80"])
        assert out["http://1.1.1.1:80"].ok is False

    def test_validate_all_still_returns_only_passing_latencies(self, monkeypatch):
        """The CLI's view must not change shape underneath it."""
        monkeypatch.setattr(pv, "validate",
                            lambda p, u, m, s: (True, 0.5) if p.endswith(":80") else (False, None))
        assert pv.validate_all(["http://1.1.1.1:80", "http://2.2.2.2:9999"]) == {
            "http://1.1.1.1:80": 0.5}


class TestSchemeFromFilename:
    """File-based lists name their protocol in the filename, not a query
    parameter. Reading only the parameter meant every entry of a socks5.txt was
    tested as HTTP and failed, which reads as a dead source rather than a wrong
    guess about it."""

    def test_a_socks_filename_is_honoured(self):
        base = "https://raw.githubusercontent.com/x/PROXY-List/master/"
        assert pv.scheme_for_source(base + "socks5.txt") == "socks5"
        assert pv.scheme_for_source(base + "socks4.txt") == "socks4"
        assert pv.scheme_for_source(base + "http.txt") == "http"

    def test_a_compound_filename_still_works(self):
        assert pv.scheme_for_source(
            "https://x/online-proxies/txt/proxies-socks5.txt") == "socks5"

    def test_the_filename_beats_the_directory(self):
        """The name is the more specific claim about what is inside."""
        assert pv.scheme_for_source("https://x/socks5-archive/http.txt") == "http"

    def test_the_query_parameter_still_wins(self):
        assert pv.scheme_for_source("https://x/list.txt?protocol=socks4") == "socks4"

    def test_an_extensionless_path_works(self):
        assert pv.scheme_for_source("https://x/socks5") == "socks5"

    def test_an_unrelated_name_stays_http(self):
        assert pv.scheme_for_source("https://x/proxies/all/data.txt") == "http"


class TestDefaultSources:
    def test_more_than_one_provider(self):
        """Four endpoints of one API is a single point of failure wearing four
        hats: one interface change and there is no input at all."""
        from urllib.parse import urlparse
        hosts = {urlparse(u).netloc for u in pv.PROXY_SOURCES}
        assert len(hosts) > 1

    def test_every_default_is_an_https_url(self):
        assert all(u.startswith("https://") for u in pv.PROXY_SOURCES)
