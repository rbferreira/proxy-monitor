"""Dashboard password and brute-force protection."""
import json

import pytest

import auth as auth_mod


@pytest.fixture
def store(tmp_path):
    s = auth_mod.AuthStore(str(tmp_path / "auth.json"))
    s.load()
    return s


class TestInitialPassword:
    def test_starts_as_admin(self, store):
        assert store.check("admin") is True
        assert store.is_initial_password() is True

    def test_rejects_anything_else(self, store):
        assert store.check("whatever") is False
        assert store.check("") is False

    def test_generates_a_secret_key_on_first_run(self, store):
        assert len(store.secret_key) >= 32

    def test_file_holds_hash_and_secret(self, store):
        d = json.loads(open(store.path, encoding="utf-8").read())
        assert d["password_hash"] and d["secret_key"]
        # the cleartext password never reaches disk
        assert "admin" not in d["password_hash"]


class TestPasswordChange:
    def test_change_invalidates_the_previous(self, store):
        store.set_password("another-password")
        assert store.check("another-password") is True
        assert store.check("admin") is False
        assert store.is_initial_password() is False

    def test_change_persists(self, store):
        store.set_password("a-decent-password")
        other = auth_mod.AuthStore(store.path)
        other.load()
        assert other.check("a-decent-password") is True

    def test_secret_key_survives_restart(self, store):
        """If the key rotated on every boot, each deploy would sign users out
        with no visible reason."""
        before = store.secret_key
        other = auth_mod.AuthStore(store.path)
        other.load()
        assert other.secret_key == before

    def test_new_password_validation(self):
        v = auth_mod.AuthStore.validate_new
        assert v("") is not None
        assert v("   ") is not None
        assert v("abc") is not None          # too short
        assert v(None) is not None
        assert v("admin") is None            # 5 chars, accepted
        assert v("a-decent-password") is None


class TestCorruptFile:
    def test_invalid_json_falls_back_to_default(self, tmp_path):
        p = tmp_path / "auth.json"
        p.write_text("{not json", encoding="utf-8")
        s = auth_mod.AuthStore(str(p))
        s.load()
        assert s.check("admin") is True

    def test_missing_hash_falls_back_to_default(self, tmp_path):
        p = tmp_path / "auth.json"
        p.write_text(json.dumps({"secret_key": "x" * 40}), encoding="utf-8")
        s = auth_mod.AuthStore(str(p))
        s.load()
        assert s.check("admin") is True
        assert s.secret_key == "x" * 40  # an existing key is preserved

    def test_short_secret_is_replaced(self, tmp_path):
        p = tmp_path / "auth.json"
        p.write_text(json.dumps({"password_hash": "irrelevant", "secret_key": "short"}),
                     encoding="utf-8")
        s = auth_mod.AuthStore(str(p))
        s.load()
        assert len(s.secret_key) >= 32


class TestBruteForce:
    def test_open_at_first(self, store):
        assert store.locked_for() == 0

    def test_locks_after_the_limit(self, store):
        for _ in range(auth_mod.MAX_ATTEMPTS):
            store.record_failure()
        assert store.locked_for() > 0

    def test_below_the_limit_stays_open(self, store):
        for _ in range(auth_mod.MAX_ATTEMPTS - 1):
            store.record_failure()
        assert store.locked_for() == 0

    def test_success_clears_the_counter(self, store):
        for _ in range(auth_mod.MAX_ATTEMPTS):
            store.record_failure()
        store.clear_failures()
        assert store.locked_for() == 0

    def test_old_failures_leave_the_window(self, store):
        import time as _t
        now = _t.time()
        store._failures = [now - auth_mod.WINDOW_SECONDS - 1] * auth_mod.MAX_ATTEMPTS
        assert store.locked_for() == 0
