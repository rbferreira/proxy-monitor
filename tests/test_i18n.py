"""Translation catalog: coverage, locale resolution and fallbacks."""
import i18n


class TestCoverage:
    def test_every_language_has_the_same_ui_keys(self):
        """A missing key would silently render as the raw key name on screen."""
        base = set(i18n.CATALOG[i18n.DEFAULT_LOCALE]["ui"])
        for lang, block in i18n.CATALOG.items():
            assert set(block["ui"]) == base, f"{lang} differs: {base ^ set(block['ui'])}"

    def test_every_language_has_the_same_groups(self):
        base = set(i18n.CATALOG[i18n.DEFAULT_LOCALE]["groups"])
        for lang, block in i18n.CATALOG.items():
            assert set(block["groups"]) == base, lang

    def test_every_language_has_the_same_settings(self):
        base = set(i18n.CATALOG[i18n.DEFAULT_LOCALE]["settings"])
        for lang, block in i18n.CATALOG.items():
            assert set(block["settings"]) == base, lang

    def test_no_blank_strings(self):
        for lang, block in i18n.CATALOG.items():
            for key, value in block["ui"].items():
                assert value.strip(), f"{lang}.{key} is empty"

    def test_every_language_is_registered(self):
        assert set(i18n.LANGUAGES) == set(i18n.CATALOG)

    def test_placeholders_match_across_languages(self):
        """`{count}` in one language and `{total}` in another would render a
        literal brace to the user."""
        import re
        holders = lambda s: set(re.findall(r"\{(\w+)\}", s))
        base = i18n.CATALOG[i18n.DEFAULT_LOCALE]["ui"]
        for lang, block in i18n.CATALOG.items():
            for key, value in block["ui"].items():
                assert holders(value) == holders(base[key]), f"{lang}.{key}"


class TestNormalizeLocale:
    def test_exact_match(self):
        assert i18n.normalize_locale("pt-BR") == "pt-BR"
        assert i18n.normalize_locale("en") == "en"

    def test_case_and_separator_insensitive(self):
        assert i18n.normalize_locale("PT_br") == "pt-BR"
        assert i18n.normalize_locale("pt-br") == "pt-BR"

    def test_base_language_matches_regional(self):
        assert i18n.normalize_locale("pt") == "pt-BR"

    def test_unknown_falls_back(self):
        assert i18n.normalize_locale("de") == i18n.DEFAULT_LOCALE
        assert i18n.normalize_locale("") == i18n.DEFAULT_LOCALE
        assert i18n.normalize_locale(None) == i18n.DEFAULT_LOCALE


class TestAcceptLanguage:
    def test_reads_the_first_supported(self):
        assert i18n.from_accept_language("pt-BR,pt;q=0.9,en;q=0.8") == "pt-BR"

    def test_english_header(self):
        assert i18n.from_accept_language("en-US,en;q=0.9") == "en"

    def test_unsupported_falls_back(self):
        assert i18n.from_accept_language("de-DE,de;q=0.9") == i18n.DEFAULT_LOCALE

    def test_missing_header(self):
        assert i18n.from_accept_language(None) == i18n.DEFAULT_LOCALE
        assert i18n.from_accept_language("") == i18n.DEFAULT_LOCALE


class TestLookups:
    def test_ui_returns_a_full_catalog(self):
        strings = i18n.ui("pt-BR")
        assert strings["state"] == "Estado"
        assert len(strings) == len(i18n.CATALOG["en"]["ui"])

    def test_ui_of_unknown_locale_is_english(self):
        assert i18n.ui("de") == i18n.ui("en")

    def test_group_name(self):
        assert i18n.group_name("en", "validation") == "Validation"
        assert i18n.group_name("pt-BR", "validation") == "Validação"
        assert i18n.group_name("en", "nonexistent") == "nonexistent"

    def test_setting_text(self):
        en = i18n.setting_text("en", "interval_seconds")
        pt = i18n.setting_text("pt-BR", "interval_seconds")
        assert en["label"] != pt["label"]
        assert en["description"] and pt["description"]

    def test_unknown_setting_returns_the_key(self):
        assert i18n.setting_text("en", "nope")["label"] == "nope"
