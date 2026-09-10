"""Session-wide setup, imported by pytest before any test module.

Everything the service persists hangs off `OUTPUT_FILE`: the proxy cache and its
metadata, the API key, the dashboard password, the settings overrides and the
stability history. `app.py` resolves all of those at import and **writes some of
them right there**, inside `start_background_worker()` — the auth file is created
with the initial password, the API key is generated if absent.

So pointing them somewhere disposable is not something a fixture can do; by the
time the first fixture runs, the files exist. It has to happen here, before any
test module imports the app.

Without this the suite writes into the real data directory — `/data` in the
container, `C:\\data` on Windows — mixing test state into a running service's,
and leaving files behind after a run that was supposed to be read-only.
"""
import os
import shutil
import tempfile

import pytest

STATE_DIR = tempfile.mkdtemp(prefix="proxy-monitor-tests-")

# Assigned rather than defaulted: an OUTPUT_FILE already in the environment is
# most likely a real one, and inheriting it is the exact accident this prevents.
os.environ["OUTPUT_FILE"] = os.path.join(STATE_DIR, "proxies.txt")

os.environ.setdefault("API_KEY", "test-key")
os.environ.setdefault("DISABLE_SCHEDULER", "1")  # no scheduler during tests
os.environ.setdefault("GEOLOOKUP", "false")      # no GeoIP database in tests


def pytest_sessionfinish(session, exitstatus):
    shutil.rmtree(STATE_DIR, ignore_errors=True)


@pytest.fixture
def state_dir():
    """The only directory the suite is allowed to write to."""
    return STATE_DIR
