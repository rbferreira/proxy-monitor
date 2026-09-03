#!/usr/bin/env python3
"""
i18n.py
=======
Translation catalog for every human-facing string: settings labels and
descriptions, dashboard copy, and status words.

Structure lives in `settings.py` (keys, types, bounds); text lives here. That
split is what lets a new setting appear in the UI without touching the HTML,
and a new language ship without touching the schema.

Adding a language: copy the `en` block, translate the values, register it in
`LANGUAGES`. Missing keys fall back to English rather than showing a blank.
"""

DEFAULT_LOCALE = "en"

# Display names are intentionally written in their own language.
LANGUAGES = {
    "en": "English",
    "pt-BR": "Português",
}

CATALOG: dict[str, dict] = {
    "en": {
        "groups": {
            "sources": "Proxy sources",
            "validation": "Validation",
            "geo": "Geolocation",
            "dashboard": "Dashboard",
            "security": "Security",
        },
        "settings": {
            "proxy_sources": {
                "label": "Source URLs",
                "description": "One URL per line. Each must return a plain-text list of "
                               "proxies, as `ip:port` or `protocol://ip:port`. When the URL "
                               "carries a `protocol=` parameter it is used for lines without "
                               "a scheme. Test a URL before saving to see what it yields.",
            },
            "interval_seconds": {
                "label": "Interval between cycles",
                "description": "How often the whole list is revalidated. Shorter keeps the "
                               "list fresher — free proxies die fast, around 38% per hour — "
                               "at the cost of running validation more often.",
            },
            "max_latency_seconds": {
                "label": "Latency cutoff",
                "description": "Proxies slower than this are discarded. Each test times out at "
                               "this value plus one second. Raising it yields more proxies, but "
                               "slower ones; the TLS handshake alone eats a good part of the budget.",
            },
            "validator_workers": {
                "label": "Validation threads",
                "description": "How many proxies are tested in parallel. More threads shorten the "
                               "run but open more simultaneous connections from the host.",
            },
            "latency_samples": {
                "label": "Latency samples",
                "description": "How many times a passing proxy is measured, reporting the median. "
                               "One sample turns a passing network hiccup into a property of the "
                               "proxy. Only proxies that already passed pay for the extra requests.",
            },
            "detect_exit_ip": {
                "label": "Detect exit address",
                "description": "Asks each working proxy which address its traffic leaves from. A "
                               "transparent proxy exits under your own address, which a pass/fail "
                               "check cannot see. Costs one extra request per working proxy.",
            },
            "geolookup": {
                "label": "Look up IP country",
                "description": "Resolves each IP's country from a local database to feed the origin "
                               "chart. The database is downloaded once and refreshed monthly. "
                               "Turned off, everything shows as Unknown.",
            },
            "dashboard_rows": {
                "label": "Table rows",
                "description": "How many proxies, fastest first, the table receives. Does not "
                               "affect the lists served by the endpoints, which are always complete.",
            },
            "latency_buckets": {
                "label": "Histogram buckets",
                "description": "How many columns the latency distribution is split into, from zero "
                               "up to the latency cutoff. More buckets mean finer detail and "
                               "thinner bars.",
            },
        },
        "ui": {
            "tagline": "latency cutoff {latency}s · cycle {interval}min",
            "state": "State",
            "last_scan": "Last scan",
            "duration": "Duration",
            "next_cycle": "Next cycle",
            "controls": "Controls",
            "status_ok": "OPERATIONAL",
            "status_running": "SCANNING",
            "status_error": "FAILED",
            "status_idle": "STANDBY",
            "never": "never",
            "panel_operational": "Operational proxies",
            "panel_protocols": "Protocols",
            "panel_latency": "Latency distribution",
            "panel_geo": "Geographic origin · top 10",
            "panel_nodes": "Active nodes",
            "of_tested": "of {count}\ntested",
            "pass_rate": "pass rate {rate}%",
            "awaiting_scan": "awaiting first scan",
            "waiting_data": "awaiting data",
            "min": "min",
            "avg": "avg",
            "max": "max",
            "col_proto": "Proto",
            "col_host": "Host",
            "col_port": "Port",
            "col_latency": "Latency",
            "col_exit": "Exit",
            "col_country": "Country",
            "filter_placeholder": "filter host / protocol / country",
            "under_1s": "< 1s",
            "copy": "copy",
            "copied": "copied ✓",
            "copy_failed": "failed",
            "settings": "settings",
            "no_match": "no node matches the filter",
            "no_nodes": "no nodes available",
            "loading": "loading",
            "footer_full_list": "Full list: {routes} · header {header}",
            "footer_sync": "SYNC {time} · auto {seconds}s",
            "read_only": "read only — click the padlock",
            "password_placeholder": "dashboard password",
            "sign_in": "sign in",
            "enter_password": "enter the password",
            "session_ended": "session ended",
            "session_expired": "session expired — sign in again",
            "lock_open": "Session open — click to sign out",
            "lock_closed": "Sign in to change settings",
            "default_password_warning": "password is still the initial one — change it in settings",
            "settings_title": "Settings",
            "settings_subtitle": "Applied immediately and kept across restarts. Each one shows where its default comes from.",
            "reset_all": "reset all",
            "close": "close",
            "save": "save",
            "saving": "saving...",
            "saved": "settings saved",
            "saved_memory_only": "saved in memory only",
            "reset_done": "everything back to the environment defaults",
            "reset_one": "{label} back to default",
            "try_again": "try again",
            "load_failed": "could not load",
            "build_failed": "could not build the panel: {error}",
            "unexpected_response": "unexpected response from the server",
            "timeout": "server did not answer in {seconds}s",
            "network_failure": "network failure: {error}",
            "tag_changed": "changed",
            "tag_next_cycle": "next cycle",
            "tag_next_cycle_title": "Only takes effect on the next validation",
            "tag_initial_password": "still the initial one",
            "range": "range {min}–{max}",
            "default_is": "default {value}",
            "env_is": "env {name}",
            "back_to_default": "↺ back to default",
            "password_label": "Dashboard password",
            "password_description": "Protects write actions; viewing stays open. Stored as a hash "
                                    "in the data volume, so it survives deploys and does not depend "
                                    "on an environment variable.",
            "current_password": "current password",
            "new_password": "new password",
            "change_password": "change password",
            "password_changed": "password changed",
            "fill_both": "fill in both fields",
            "changing": "changing...",
            "language": "Language",
            "refresh": "revalidate",
            "security_group": "Security",
            "on": "on",
            "off": "off",
            "test_source": "test",
            "testing": "testing...",
            "source_ok": "{found} proxies ({types})",
            "source_empty": "responded, but no proxy recognized in {lines} lines",
            "source_failed": "failed: {error}",
            "source_url_placeholder": "https://example.com/proxies.txt",
            "add_source": "add",
            "remove_source": "remove",
            "one_per_line": "one URL per line",
        },
    },

    "pt-BR": {
        "groups": {
            "sources": "Fontes de proxy",
            "validation": "Validação",
            "geo": "Geolocalização",
            "dashboard": "Dashboard",
            "security": "Segurança",
        },
        "settings": {
            "proxy_sources": {
                "label": "URLs das fontes",
                "description": "Uma URL por linha. Cada uma precisa devolver uma lista de "
                               "proxies em texto puro, no formato `ip:porta` ou "
                               "`protocolo://ip:porta`. Se a URL tiver um parâmetro "
                               "`protocol=`, ele vale para as linhas sem esquema. Teste uma "
                               "URL antes de salvar para ver o que ela devolve.",
            },
            "interval_seconds": {
                "label": "Intervalo entre ciclos",
                "description": "De quanto em quanto tempo a lista inteira é revalidada. Menor deixa "
                               "a lista mais fresca — proxy público morre rápido, cerca de 38% por "
                               "hora — ao custo de rodar a validação mais vezes.",
            },
            "max_latency_seconds": {
                "label": "Corte de latência",
                "description": "Proxy mais lento que isso é descartado. O timeout de cada teste é "
                               "este valor + 1s. Subir traz mais proxies, porém mais lentos; o "
                               "handshake TLS sozinho já consome boa parte do orçamento.",
            },
            "validator_workers": {
                "label": "Threads de validação",
                "description": "Quantos proxies são testados em paralelo. Mais threads encurtam a "
                               "rodada, mas abrem mais conexões simultâneas na mesma máquina.",
            },
            "latency_samples": {
                "label": "Amostras de latência",
                "description": "Quantas vezes um proxy aprovado é medido, reportando a mediana. "
                               "Uma amostra só transforma qualquer engasgo de rede em característica "
                               "do proxy. Só quem já passou paga pelas requisições extras.",
            },
            "detect_exit_ip": {
                "label": "Detectar endereço de saída",
                "description": "Pergunta a cada proxy funcional por qual endereço o tráfego sai. "
                               "Proxy transparente sai com o seu próprio endereço, e uma checagem "
                               "de passa/não-passa não enxerga isso. Custa uma requisição extra.",
            },
            "geolookup": {
                "label": "Consultar país dos IPs",
                "description": "Busca o país de cada IP num banco local para alimentar o gráfico de "
                               "origem. O banco é baixado uma vez e atualizado mensalmente. "
                               "Desligado, todos aparecem como Unknown.",
            },
            "dashboard_rows": {
                "label": "Linhas na tabela",
                "description": "Quantos proxies, do mais rápido para o mais lento, a tabela recebe. "
                               "Não afeta a lista servida pelos endpoints, que é sempre completa.",
            },
            "latency_buckets": {
                "label": "Faixas do histograma",
                "description": "Em quantas colunas a distribuição de latência é dividida, de zero até "
                               "o corte de latência. Mais faixas dão mais detalhe e barras mais finas.",
            },
        },
        "ui": {
            "tagline": "corte de latência {latency}s · ciclo {interval}min",
            "state": "Estado",
            "last_scan": "Última varredura",
            "duration": "Duração",
            "next_cycle": "Próximo ciclo",
            "controls": "Controle",
            "status_ok": "OPERACIONAL",
            "status_running": "VARRENDO",
            "status_error": "FALHA",
            "status_idle": "EM ESPERA",
            "never": "nunca",
            "panel_operational": "Proxies operacionais",
            "panel_protocols": "Protocolos",
            "panel_latency": "Distribuição de latência",
            "panel_geo": "Origem geográfica · top 10",
            "panel_nodes": "Nós ativos",
            "of_tested": "de {count}\ntestados",
            "pass_rate": "taxa de aprovação {rate}%",
            "awaiting_scan": "aguardando varredura",
            "waiting_data": "aguardando dados",
            "min": "mín",
            "avg": "média",
            "max": "máx",
            "col_proto": "Proto",
            "col_host": "Host",
            "col_port": "Porta",
            "col_latency": "Latência",
            "col_exit": "Saída",
            "col_country": "País",
            "filter_placeholder": "filtrar host / protocolo / país",
            "under_1s": "< 1s",
            "copy": "copiar",
            "copied": "copiado ✓",
            "copy_failed": "falhou",
            "settings": "ajustes",
            "no_match": "nenhum nó bate com o filtro",
            "no_nodes": "nenhum nó disponível",
            "loading": "carregando",
            "footer_full_list": "Lista completa: {routes} · header {header}",
            "footer_sync": "SYNC {time} · auto {seconds}s",
            "read_only": "somente leitura — clique no cadeado",
            "password_placeholder": "senha do painel",
            "sign_in": "entrar",
            "enter_password": "informe a senha",
            "session_ended": "sessão encerrada",
            "session_expired": "sessão expirada — entre de novo",
            "lock_open": "Sessão aberta — clique para sair",
            "lock_closed": "Entrar para alterar ajustes",
            "default_password_warning": "senha ainda é a inicial — troque em ajustes",
            "settings_title": "Ajustes",
            "settings_subtitle": "Valem na hora e sobrevivem a restart. Cada um mostra de onde vem o padrão.",
            "reset_all": "restaurar tudo",
            "close": "fechar",
            "save": "salvar",
            "saving": "salvando...",
            "saved": "ajustes salvos",
            "saved_memory_only": "salvo só em memória",
            "reset_done": "tudo voltou ao padrão das variáveis de ambiente",
            "reset_one": "{label} voltou ao padrão",
            "try_again": "tentar de novo",
            "load_failed": "não foi possível carregar",
            "build_failed": "erro ao montar o painel: {error}",
            "unexpected_response": "resposta inesperada do servidor",
            "timeout": "servidor não respondeu em {seconds}s",
            "network_failure": "falha de rede: {error}",
            "tag_changed": "alterado",
            "tag_next_cycle": "próximo ciclo",
            "tag_next_cycle_title": "Só passa a valer na próxima validação",
            "tag_initial_password": "ainda é a inicial",
            "range": "faixa {min}–{max}",
            "default_is": "padrão {value}",
            "env_is": "env {name}",
            "back_to_default": "↺ voltar ao padrão",
            "password_label": "Senha do painel",
            "password_description": "Protege as ações de escrita; a visualização segue aberta. "
                                    "Guardada como hash no volume, então sobrevive a deploy e não "
                                    "depende de variável de ambiente.",
            "current_password": "senha atual",
            "new_password": "nova senha",
            "change_password": "trocar senha",
            "password_changed": "senha alterada",
            "fill_both": "preencha os dois campos",
            "changing": "trocando...",
            "language": "Idioma",
            "refresh": "revalidar",
            "security_group": "Segurança",
            "on": "ligado",
            "off": "desligado",
            "test_source": "testar",
            "testing": "testando...",
            "source_ok": "{found} proxies ({types})",
            "source_empty": "respondeu, mas nenhum proxy reconhecido em {lines} linhas",
            "source_failed": "falhou: {error}",
            "source_url_placeholder": "https://exemplo.com/proxies.txt",
            "add_source": "adicionar",
            "remove_source": "remover",
            "one_per_line": "uma URL por linha",
        },
    },
}


def normalize_locale(requested: str | None) -> str:
    """Resolve whatever arrived (query string, cookie, Accept-Language) into a
    supported locale. Falls back to the default instead of failing."""
    if not requested:
        return DEFAULT_LOCALE
    wanted = requested.strip()
    if wanted in CATALOG:
        return wanted
    # `pt`, `pt_BR`, `PT-br` and `pt-BR;q=0.9` all mean the same thing here.
    base = wanted.replace("_", "-").split(";")[0].split(",")[0].lower()
    for code in CATALOG:
        if code.lower() == base or code.lower().split("-")[0] == base.split("-")[0]:
            return code
    return DEFAULT_LOCALE


def from_accept_language(header: str | None) -> str:
    """Best guess from the browser's Accept-Language header, used only as the
    initial suggestion — an explicit choice always wins."""
    if not header:
        return DEFAULT_LOCALE
    for chunk in header.split(","):
        code = normalize_locale(chunk)
        if code != DEFAULT_LOCALE or chunk.strip().lower().startswith("en"):
            return code
    return DEFAULT_LOCALE


def ui(locale: str) -> dict:
    """UI strings for a locale, with English filling any gap."""
    base = dict(CATALOG[DEFAULT_LOCALE]["ui"])
    base.update(CATALOG.get(locale, {}).get("ui", {}))
    return base


def group_name(locale: str, key: str) -> str:
    groups = CATALOG.get(locale, {}).get("groups", {})
    return groups.get(key) or CATALOG[DEFAULT_LOCALE]["groups"].get(key, key)


def setting_text(locale: str, key: str) -> dict:
    """Label and description of a setting, falling back to English per field so
    a partially translated language still shows something useful."""
    fallback = CATALOG[DEFAULT_LOCALE]["settings"].get(key, {})
    text = CATALOG.get(locale, {}).get("settings", {}).get(key, {})
    return {
        "label": text.get("label") or fallback.get("label") or key,
        "description": text.get("description") or fallback.get("description") or "",
    }
