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


def _serve(handler):
    server = HTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def _body(payload):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
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
    """`localhost` plays a public host, `127.0.0.1` the internal one. Only the
    name lookup is faked; the rest of the guard is the real one."""
    real = pv.resolves_to_internal
    monkeypatch.setattr(pv, "resolves_to_internal",
                        lambda host: False if host == "localhost" else real(host))
    monkeypatch.setattr(pv, "ALLOW_INTERNAL_SOURCES", False)
    monkeypatch.setattr(pv.time, "sleep", lambda s: None)

    started = []

    def start(handler):
        s = _serve(handler)
        started.append(s)
        return s.server_port

    yield start
    for s in started:
        s.shutdown()
        s.server_close()


class TestRedirectGuard:
    def test_redirect_to_an_internal_address_is_refused(self, servers):
        internal = servers(_body(INTERNAL_BODY))
        hits = []
        public = servers(_redirect_to(f"http://127.0.0.1:{internal}/", hits))

        assert pv.fetch_source(f"http://localhost:{public}/list") is None

    def test_a_refused_redirect_is_not_retried(self, servers):
        internal = servers(_body(INTERNAL_BODY))
        hits = []
        public = servers(_redirect_to(f"http://127.0.0.1:{internal}/", hits))

        pv.fetch_source(f"http://localhost:{public}/list", attempts=3)
        assert len(hits) == 1

    def test_redirect_between_public_hosts_still_works(self, servers):
        target = servers(_body(PUBLIC_BODY))
        hits = []
        public = servers(_redirect_to(f"http://localhost:{target}/list", hits))

        assert pv.fetch_source(f"http://localhost:{public}/list") == PUBLIC_BODY.decode()

    def test_allow_internal_sources_lets_it_through(self, servers, monkeypatch):
        monkeypatch.setattr(pv, "ALLOW_INTERNAL_SOURCES", True)
        internal = servers(_body(INTERNAL_BODY))
        hits = []
        public = servers(_redirect_to(f"http://127.0.0.1:{internal}/", hits))

        assert pv.fetch_source(f"http://localhost:{public}/list") == INTERNAL_BODY.decode()

    def test_the_source_probe_does_not_follow_it_either(self, servers):
        internal = servers(_body(INTERNAL_BODY))
        hits = []
        public = servers(_redirect_to(f"http://127.0.0.1:{internal}/", hits))

        client = app_module.app.test_client()
        d = client.post("/api/settings/test-source",
                        json={"url": f"http://localhost:{public}/list"},
                        headers=KEY).get_json()
        assert d["ok"] is False
        assert "refused" in d["error"]
        assert "10.9.8.7" not in str(d)
