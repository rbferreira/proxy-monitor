"""Schema, validation and persistence of the runtime settings."""
import json

import pytest

import i18n
import settings as st


@pytest.fixture
def store(tmp_path):
    return st.Store(str(tmp_path / "runtime.json"))


class TestSchema:
    def test_keys_are_unique(self):
        keys = [s.key for s in st.SETTINGS]
        assert len(keys) == len(set(keys))

    def test_every_setting_is_translated_in_every_language(self):
        """A setting with no text would render as a bare key in the panel."""
        for lang in i18n.CATALOG:
            for s in st.SETTINGS:
                text = i18n.setting_text(lang, s.key)
                assert text["label"], f"{s.key} has no label in {lang}"
                assert len(text["description"]) > 60, f"{s.key} description too short in {lang}"

    def test_every_group_is_translated(self):
        for lang in i18n.CATALOG:
            for s in st.SETTINGS:
                assert i18n.group_name(lang, s.group) != s.group or s.group in i18n.CATALOG[lang]["groups"]

    def test_numeric_settings_have_bounds(self):
        for s in st.SETTINGS:
            if s.type in ("int", "float"):
                assert s.minimum is not None and s.maximum is not None, s.key
                assert s.minimum < s.maximum

    def test_default_within_bounds(self):
        for s in st.SETTINGS:
            if s.type in ("int", "float"):
                assert s.minimum <= s.default <= s.maximum, s.key

    def test_effect_is_declared_and_valid(self):
        for s in st.SETTINGS:
            assert s.effect in ("immediate", "next_cycle")


class TestCoerce:
    def test_int_accepts_string(self):
        s = st.BY_KEY["interval_seconds"]
        assert st.coerce(s, "1800") == 1800
        assert st.coerce(s, 1800) == 1800

    def test_float_accepts_int(self):
        assert st.coerce(st.BY_KEY["max_latency_seconds"], 8) == 8.0

    def test_bool_from_many_shapes(self):
        s = st.BY_KEY["geolookup"]
        for v in (True, "true", "1", "yes", "on"):
            assert st.coerce(s, v) is True
        for v in (False, "false", "0", "no", "off", "anything"):
            assert st.coerce(s, v) is False

    def test_rejects_below_minimum(self):
        with pytest.raises(ValueError, match="minimum"):
            st.coerce(st.BY_KEY["interval_seconds"], 30)

    def test_rejects_above_maximum(self):
        with pytest.raises(ValueError, match="maximum"):
            st.coerce(st.BY_KEY["validator_workers"], 5000)

    def test_rejects_text_for_numbers(self):
        with pytest.raises(ValueError, match="integer"):
            st.coerce(st.BY_KEY["interval_seconds"], "twenty minutes")

    def test_error_mentions_the_label(self):
        with pytest.raises(ValueError, match="Interval between cycles"):
            st.coerce(st.BY_KEY["interval_seconds"], 1)

    def test_error_is_localized(self):
        with pytest.raises(ValueError, match="Intervalo entre ciclos"):
            st.coerce(st.BY_KEY["interval_seconds"], 1, "pt-BR")


class TestStore:
    def test_env_used_without_override(self, store, monkeypatch):
        monkeypatch.setenv("INTERVAL_SECONDS", "900")
        assert store.get("interval_seconds") == 900
        assert store.is_overridden("interval_seconds") is False

    def test_invalid_env_falls_back_to_default(self, store, monkeypatch):
        monkeypatch.setenv("INTERVAL_SECONDS", "pineapple")
        assert store.get("interval_seconds") == st.BY_KEY["interval_seconds"].default

    def test_blank_env_falls_back_to_default(self, store, monkeypatch):
        monkeypatch.setenv("INTERVAL_SECONDS", "   ")
        assert store.get("interval_seconds") == st.BY_KEY["interval_seconds"].default

    def test_override_beats_env(self, store, monkeypatch):
        monkeypatch.setenv("INTERVAL_SECONDS", "900")
        store.apply({"interval_seconds": 1800})
        assert store.get("interval_seconds") == 1800
        assert store.is_overridden("interval_seconds") is True

    def test_reset_returns_to_env(self, store, monkeypatch):
        monkeypatch.setenv("INTERVAL_SECONDS", "900")
        store.apply({"interval_seconds": 1800})
        store.reset("interval_seconds")
        assert store.get("interval_seconds") == 900

    def test_reset_everything(self, store):
        store.apply({"interval_seconds": 1800, "dashboard_rows": 50})
        store.reset()
        assert not store.is_overridden("interval_seconds")
        assert not store.is_overridden("dashboard_rows")


class TestApplyBatch:
    def test_valid_batch(self, store):
        applied, errors = store.apply({"interval_seconds": 1800, "geolookup": False})
        assert errors == []
        assert applied == {"interval_seconds": 1800, "geolookup": False}

    def test_all_or_nothing(self, store):
        """One bad value must not leave the config half-applied."""
        _, errors = store.apply({"interval_seconds": 1800, "validator_workers": 99999})
        assert len(errors) == 1
        assert store.is_overridden("interval_seconds") is False

    def test_unknown_key_is_an_error(self, store):
        _, errors = store.apply({"does_not_exist": 1})
        assert "unknown" in errors[0]

    def test_empty_batch_is_harmless(self, store):
        assert store.apply({}) == ({}, [])
        assert store.apply(None) == ({}, [])


class TestPersistence:
    def test_save_and_reload(self, store):
        store.apply({"interval_seconds": 1800, "geolookup": False})
        assert store.save() is None

        other = st.Store(store.path)
        other.load()
        assert other.get("interval_seconds") == 1800
        assert other.get("geolookup") is False

    def test_missing_file_is_harmless(self, tmp_path):
        s = st.Store(str(tmp_path / "does-not-exist.json"))
        s.load()
        assert s.get("interval_seconds") == st.BY_KEY["interval_seconds"].default

    def test_corrupt_file_is_harmless(self, tmp_path):
        p = tmp_path / "runtime.json"
        p.write_text("{not json at all", encoding="utf-8")
        s = st.Store(str(p))
        s.load()
        assert s.get("interval_seconds") == st.BY_KEY["interval_seconds"].default

    def test_unknown_setting_in_file_is_skipped(self, tmp_path):
        """A setting removed in a future version must not block the boot."""
        p = tmp_path / "runtime.json"
        p.write_text(json.dumps({"interval_seconds": 1800, "retired_setting": 7}), encoding="utf-8")
        s = st.Store(str(p))
        s.load()
        assert s.get("interval_seconds") == 1800

    def test_out_of_range_value_in_file_is_skipped(self, tmp_path):
        p = tmp_path / "runtime.json"
        p.write_text(json.dumps({"interval_seconds": 5, "dashboard_rows": 50}), encoding="utf-8")
        s = st.Store(str(p))
        s.load()
        assert s.get("interval_seconds") == st.BY_KEY["interval_seconds"].default
        assert s.get("dashboard_rows") == 50

    def test_write_is_atomic(self, store, tmp_path):
        store.apply({"dashboard_rows": 42})
        store.save()
        assert not (tmp_path / "runtime.json.tmp").exists()
        assert json.loads((tmp_path / "runtime.json").read_text(encoding="utf-8")) == {
            "dashboard_rows": 42
        }


class TestDescribe:
    def test_carries_everything_the_ui_needs(self, store):
        for item in store.describe():
            for field in ("key", "label", "description", "group", "type",
                          "value", "default", "overridden", "effect", "env"):
                assert field in item, f"{item['key']} missing {field}"

    def test_marks_overrides(self, store):
        store.apply({"dashboard_rows": 25})
        by_key = {i["key"]: i for i in store.describe()}
        assert by_key["dashboard_rows"]["overridden"] is True
        assert by_key["interval_seconds"]["overridden"] is False

    def test_groups_are_localized(self, store):
        en = {i["group"] for i in store.describe("en")}
        pt = {i["group"] for i in store.describe("pt-BR")}
        assert "Validation" in en
        assert "Validação" in pt

    def test_labels_are_localized(self, store):
        en = {i["key"]: i["label"] for i in store.describe("en")}
        pt = {i["key"]: i["label"] for i in store.describe("pt-BR")}
        assert en["interval_seconds"] != pt["interval_seconds"]

    def test_unknown_locale_falls_back_to_english(self, store):
        fallback = {i["key"]: i["label"] for i in store.describe("de")}
        english = {i["key"]: i["label"] for i in store.describe("en")}
        assert fallback == english
