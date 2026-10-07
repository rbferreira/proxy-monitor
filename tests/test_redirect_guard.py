"""The internal-address guard has to hold across redirects, not just for the
URL that was configured. Real sockets here: the bug lived in urllib's own
redirect handling, which a mocked urlopen would never exercise."""
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

import app as app_module
import proxy_validator as pv

KEY = {"X-API-Key": "test-key"}
INTERNAL_BODY = b"10.9.8.7:3128\n"
PUBLIC_BODY = b"1.2.3.4:8080\n"


PUBLIC, INTERNAL = "127.0.0.1", "127.0.0.2"


def _serve(handler, host):
    server = HTTPServer((host, 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def _body(payload, hits=None):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if hits is not None:
                hits.append(self.path)
            self.send_response(200)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *a):
            pass
    return Handler


def _redirect_to(location, hits):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            hits.append(self.path)
            self.send_response(302)
            self.send_header("Location", location)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *a):
            pass
    return Handler


@pytest.fixture
def servers(monkeypatch):
    """Two loopback addresses stand in for the two sides: 127.0.0.1 is treated
    as a public host, 127.0.0.2 stays internal. Only that one exception is
    faked; every check — by name and by connected address — is the real one."""
    real = pv._ip_is_internal
    monkeypatch.setattr(pv, "_ip_is_internal",
                        lambda ip: False if str(ip) == PUBLIC else real(ip))
    monkeypatch.setattr(pv, "ALLOW_INTERNAL_SOURCES", False)
    monkeypatch.setattr(pv.time, "sleep", lambda s: None)

    started = []

    def start(handler, host=PUBLIC):
        s = _serve(handler, host)
        started.append(s)
        return f"http://{host}:{s.server_port}"

    yield start
    for s in started:
        s.shutdown()
        s.server_close()


class TestRedirectGuard:
    def test_redirect_to_an_internal_address_is_refused(self, servers):
        internal_hits = []
        internal = servers(_body(INTERNAL_BODY, internal_hits), INTERNAL)
        public = servers(_redirect_to(f"{internal}/", []))

        assert pv.fetch_source(f"{public}/list") is None
        assert internal_hits == []

    def test_a_refused_redirect_is_not_retried(self, servers):
        internal = servers(_body(INTERNAL_BODY), INTERNAL)
        hits = []
        public = servers(_redirect_to(f"{internal}/", hits))

        pv.fetch_source(f"{public}/list", attempts=3)
        assert len(hits) == 1

    def test_redirect_between_public_hosts_still_works(self, servers):
        target = servers(_body(PUBLIC_BODY))
        public = servers(_redirect_to(f"{target}/list", []))

        assert pv.fetch_source(f"{public}/list") == PUBLIC_BODY.decode()

    def test_allow_internal_sources_lets_it_through(self, servers, monkeypatch):
        monkeypatch.setattr(pv, "ALLOW_INTERNAL_SOURCES", True)
        internal = servers(_body(INTERNAL_BODY), INTERNAL)
        public = servers(_redirect_to(f"{internal}/", []))

        assert pv.fetch_source(f"{public}/list") == INTERNAL_BODY.decode()

    def test_the_source_probe_does_not_follow_it_either(self, servers):
        internal = servers(_body(INTERNAL_BODY), INTERNAL)
        public = servers(_redirect_to(f"{internal}/", []))

        client = app_module.app.test_client()
        d = client.post("/api/settings/test-source",
                        json={"url": f"{public}/list"}, headers=KEY).get_json()
        assert d["ok"] is False
        assert "refused" in d["error"]
        assert "10.9.8.7" not in str(d)


class TestCheckedAtConnectTime:
    """DNS rebinding: the name looks public when it is checked and resolves
    internally when the fetch connects. Simulated by fooling the name check;
    the socket check must still refuse."""

    def test_a_name_check_that_was_fooled_does_not_matter(self, servers, monkeypatch):
        internal_hits = []
        internal = servers(_body(INTERNAL_BODY, internal_hits), INTERNAL)
        monkeypatch.setattr(pv, "resolves_to_internal", lambda host: False)

        assert pv.source_is_allowed(f"{internal}/") == (True, "")
        assert pv.fetch_source(f"{internal}/") is None
        assert internal_hits == [], "a request reached the internal host"

    def test_through_a_redirect_too(self, servers, monkeypatch):
        internal_hits = []
        internal = servers(_body(INTERNAL_BODY, internal_hits), INTERNAL)
        public = servers(_redirect_to(f"{internal}/", []))
        monkeypatch.setattr(pv, "resolves_to_internal", lambda host: False)

        assert pv.fetch_source(f"{public}/list") is None
        assert internal_hits == []

    def test_a_refusal_at_connect_time_is_not_retried(self, servers, monkeypatch):
        internal = servers(_body(INTERNAL_BODY), INTERNAL)
        monkeypatch.setattr(pv, "resolves_to_internal", lambda host: False)
        slept = []
        monkeypatch.setattr(pv.time, "sleep", slept.append)

        assert pv.fetch_source(f"{internal}/", attempts=3) is None
        assert slept == [], "a refused address was retried"

    def test_the_refusal_reads_once(self, servers, monkeypatch):
        internal = servers(_body(INTERNAL_BODY), INTERNAL)
        monkeypatch.setattr(pv, "resolves_to_internal", lambda host: False)

        with pytest.raises(pv.BlockedRedirect) as caught:
            pv.open_url(pv.urllib.request.Request(f"{internal}/"), timeout=5)
        assert str(caught.value).count("urlopen error") == 1

    def test_ipv4_mapped_ipv6_is_judged_by_its_ipv4(self):
        import ipaddress
        assert pv._ip_is_internal(ipaddress.ip_address("::ffff:10.0.0.1"))
        assert pv._ip_is_internal(ipaddress.ip_address("::ffff:169.254.169.254"))
        assert not pv._ip_is_internal(ipaddress.ip_address("::ffff:8.8.8.8"))


class TestEgressProxy:
    """With HTTP(S)_PROXY set, the socket reaches the operator's proxy — often
    on a private address by design. That must not block every source."""

    def test_a_private_egress_proxy_is_not_mistaken_for_the_target(self, servers, monkeypatch):
        seen = []

        class FakeProxy(BaseHTTPRequestHandler):
            def do_GET(self):
                seen.append(self.path)  # absolute URI: proxied request
                self.send_response(200)
                self.send_header("Content-Length", str(len(PUBLIC_BODY)))
                self.end_headers()
                self.wfile.write(PUBLIC_BODY)

            def log_message(self, *a):
                pass

        proxy = servers(FakeProxy, INTERNAL)
        monkeypatch.setenv("HTTP_PROXY", proxy)
        monkeypatch.setenv("NO_PROXY", "")
        monkeypatch.setattr(pv, "_opener", pv.urllib.request.build_opener(
            pv._GuardedRedirects, pv._GuardedHTTPHandler, pv._GuardedHTTPSHandler))

        assert pv.fetch_source("http://public.example/list") == PUBLIC_BODY.decode()
        assert seen == ["http://public.example/list"]
