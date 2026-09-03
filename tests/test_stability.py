"""Per-proxy history and the verdict drawn from it.

The point of the module is refusing to call a proxy reliable on one lucky
check, so most of these tests are about what it declines to assert.
"""
import json

import pytest

import stability as st


@pytest.fixture
def store(tmp_path):
    return st.Store(str(tmp_path / "stability.json"))


def feed(store, proxy, samples, start=1000.0, step=120.0):
    """Record a sequence at a fixed cadence, returning the final clock."""
    now = start
    for sample in samples:
        store.record(proxy, sample, now)
        now += step
    return now - step


class TestRecord:
    def test_counts_and_rate(self, store):
        feed(store, "p", [0.5, None, 0.4, 0.6])
        view = store.view("p", 1000.0 + 3 * 120)
        assert view["checks"] == 4
        assert view["success_rate"] == 0.75

    def test_streak_counts_back_from_the_latest(self, store):
        """A great historical rate means nothing if it is failing right now."""
        now = feed(store, "p", [0.4, 0.4, 0.4, None, 0.5])
        assert store.view("p", now)["streak"] == 1

    def test_a_failure_breaks_the_streak(self, store):
        now = feed(store, "p", [0.4, 0.4, None])
        assert store.view("p", now)["streak"] == 0

    def test_median_ignores_the_failures(self, store):
        now = feed(store, "p", [0.2, None, 0.4, None, 0.6])
        assert store.view("p", now)["median_latency"] == 0.4

    def test_the_window_forgets_the_distant_past(self, store):
        store.policy.window = 5
        now = feed(store, "p", [None] * 5 + [0.3] * 5)
        view = store.view("p", now)
        assert view["checks"] == 5
        assert view["success_rate"] == 1.0

    def test_spread_needs_two_measurements(self, store):
        now = feed(store, "p", [0.5])
        assert store.view("p", now)["spread"] is None


class TestVerdict:
    """unknown, unstable and stable are three different claims."""

    def test_a_proxy_nobody_measured_is_unknown(self, store):
        assert store.state_of("never-seen") == st.UNKNOWN

    def test_too_few_checks_is_unknown_not_unstable(self, store):
        """Reporting an unmeasured proxy as unstable is a claim we cannot
        support, and on a dashboard it is indistinguishable from one that
        genuinely fails."""
        now = feed(store, "p", [0.4, 0.4])
        assert store.state_of("p", now) == st.UNKNOWN
        assert store.view("p", now)["blockers"] == ["checks"]

    def test_a_good_run_qualifies(self, store):
        now = feed(store, "p", [0.4] * 5)
        assert store.state_of("p", now) == st.STABLE
        assert store.view("p", now)["blockers"] == []

    def test_a_poor_success_rate_is_unstable(self, store):
        now = feed(store, "p", [0.4, None, None, 0.4, 0.4, 0.4, 0.4])
        view = store.view("p", now)
        assert view["state"] == st.UNSTABLE
        assert "rate" in view["blockers"]

    def test_good_history_but_failing_now_is_unstable(self, store):
        """The rule that matters most: a proxy with an excellent record that is
        down right now must not be advertised as stable."""
        now = feed(store, "p", [0.4] * 8 + [None, None])
        view = store.view("p", now)
        assert view["state"] == st.UNSTABLE
        assert "streak" in view["blockers"]

    def test_stale_history_is_unknown_again(self, store):
        """Evidence expires. A service that was down must not come back
        asserting a verdict from measurements taken an hour ago."""
        now = feed(store, "p", [0.4] * 6)
        assert store.state_of("p", now) == st.STABLE

        much_later = now + st.STALE_SECONDS + 60
        assert store.state_of("p", much_later) == st.UNKNOWN
        assert "stale" in store.view("p", much_later)["blockers"]

    def test_stable_since_is_forgotten_when_it_stops_being_stable(self, store):
        now = feed(store, "p", [0.4] * 6)
        assert store.view("p", now)["stable_for"] is not None
        store.record("p", None, now + 120)
        assert store.view("p", now + 120)["stable_for"] is None


class TestPolicyClamping:
    def test_a_threshold_above_the_window_cannot_lock_everything_out(self, store):
        """Settings are validated one key at a time, so nothing stops someone
        asking for more checks than the window can ever hold."""
        store.policy.window = 5
        store.policy.min_checks = 50
        now = feed(store, "p", [0.4] * 5)
        assert store.state_of("p", now) == st.STABLE

    def test_streak_is_clamped_too(self, store):
        store.policy.window = 4
        store.policy.min_streak = 40
        now = feed(store, "p", [0.4] * 4)
        assert store.state_of("p", now) == st.STABLE


class TestAggregates:
    def test_counts_by_state(self, store):
        now = feed(store, "good", [0.4] * 6)
        feed(store, "bad", [None, None, 0.4, None, None, 0.4], start=1000.0)
        feed(store, "new", [0.4], start=1000.0 + 5 * 120)
        counts = store.counts(["good", "bad", "new"], now)
        assert counts == {st.STABLE: 1, st.UNSTABLE: 1, st.UNKNOWN: 1}

    def test_stable_only_filters(self, store):
        now = feed(store, "good", [0.4] * 6)
        feed(store, "new", [0.4], start=1000.0 + 5 * 120)
        assert store.stable_only(["good", "new"], now) == ["good"]

    def test_warming_up_distinguishes_not_ready_from_nothing_qualifies(self, store):
        now = feed(store, "new", [0.4])
        assert store.warming_up(["new"], now) is True

        now = feed(store, "bad", [None] * 6)
        assert store.warming_up(["bad"], now) is False


class TestPruning:
    def test_forgets_records_nothing_touched(self, store):
        feed(store, "old", [0.4] * 3, start=1000.0)
        feed(store, "fresh", [0.4] * 3, start=50_000.0)
        removed = store.prune(now=50_500.0)
        assert removed == 1
        assert store.state_of("fresh", 50_500.0) != st.UNKNOWN or len(store) == 1

    def test_a_failing_proxy_keeps_its_history(self, store):
        """Its failures are exactly the evidence that it is unreliable —
        dropping them would let it look unknown and start over."""
        now = feed(store, "failing", [None] * 6)
        store.prune(now=now)
        assert len(store) == 1
        assert store.state_of("failing", now) == st.UNSTABLE

    def test_a_hard_ceiling_backstops_a_bad_retention(self, store, monkeypatch):
        monkeypatch.setattr(st, "MAX_TRACKED", 10)
        for i in range(25):
            store.record(f"p{i}", 0.4, 1000.0 + i)
        store.prune(now=1000.0 + 30, retention=10_000)
        assert len(store) == 10


class TestPersistence:
    def test_history_survives_a_restart(self, store, tmp_path):
        now = feed(store, "p", [0.4] * 6)
        assert store.save() is None

        again = st.Store(str(tmp_path / "stability.json"))
        again.load()
        assert again.state_of("p", now) == st.STABLE
        assert again.view("p", now)["checks"] == 6

    def test_the_file_is_written_atomically(self, store, tmp_path):
        feed(store, "p", [0.4] * 3)
        store.save()
        assert not (tmp_path / "stability.json.tmp").exists()

    def test_a_missing_file_is_harmless(self, tmp_path):
        s = st.Store(str(tmp_path / "absent.json"))
        s.load()
        assert len(s) == 0

    def test_a_corrupt_file_is_harmless(self, store):
        with open(store.path, "w", encoding="utf-8") as f:
            f.write("{not json")
        store.load()
        assert len(store) == 0

    def test_a_future_schema_is_refused_rather_than_guessed(self, store):
        with open(store.path, "w", encoding="utf-8") as f:
            json.dump({"version": 99, "proxies": {"p": {"samples": [0.4]}}}, f)
        store.load()
        assert len(store) == 0

    def test_a_shrunken_window_truncates_the_restored_history(self, store, tmp_path):
        feed(store, "p", [0.4] * 15)
        store.save()

        smaller = st.Store(str(tmp_path / "stability.json"), st.Policy(window=4))
        smaller.load()
        assert smaller.view("p", 3000.0)["checks"] == 4

    def test_a_long_outage_comes_back_unknown(self, store, tmp_path):
        """The restart hazard: a full window of successes restored from disk
        would otherwise assert 'stable' from evidence that has expired."""
        now = feed(store, "p", [0.4] * 6)
        store.save()

        again = st.Store(str(tmp_path / "stability.json"))
        again.load()
        assert again.state_of("p", now + st.STALE_SECONDS + 1) == st.UNKNOWN

    def test_garbage_samples_are_dropped_not_trusted(self, store):
        with open(store.path, "w", encoding="utf-8") as f:
            json.dump({"version": st.SCHEMA_VERSION,
                       "proxies": {"p": {"samples": [0.4, "fast", None, {}],
                                         "first_seen": 1, "last_seen": 2}}}, f)
        store.load()
        assert store.view("p", 2.0)["checks"] == 2

    def test_the_file_stays_compact(self, store):
        """Written every couple of minutes: pretty-printing it quadruples the
        size for a file no person reads."""
        for i in range(100):
            feed(store, f"p{i}", [0.4] * st.WINDOW)
        store.save()
        import os
        size = os.path.getsize(store.path)
        assert size < 60_000, f"{size} bytes for 100 proxies"


class TestClear:
    def test_clear_empties_it(self, store):
        feed(store, "p", [0.4] * 3)
        store.clear()
        assert len(store) == 0
