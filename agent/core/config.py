"""
Настройки агента: одно типизированное место вместо чтения os.environ по всему
модулю.

Почему не pydantic-settings: это отдельный пакет, а контур закрытый — каждая
новая зависимость должна попасть во внутренний индекс pip. Значения читаются
из окружения фабрикой ниже, а проверяет и приводит типы обычная pydantic-модель.
"""
from __future__ import annotations

import os
from typing import Optional

from pydantic import BaseModel, Field, field_validator


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default)


def _flag(name: str, default: str = "false") -> bool:
    return _env(name, default).strip().lower() in ("1", "true", "yes", "on")


def _list(name: str, sep: str = ";") -> list[str]:
    return [p.strip() for p in _env(name).split(sep) if p.strip()]


class LLMSettings(BaseModel):
    base_url:    str   = "https://your-llm-server.com/v1"
    api_key:     str   = "your-token-here"
    model:       str   = "gpt-4o-mini"
    max_tokens:  int   = 2048
    temperature: float = 0.3
    # auto — проверить поддержку инструментов пробным запросом
    tools:       str   = "auto"
    tool_rounds: int   = 4


class PrometheusSettings(BaseModel):
    url:               str = "http://localhost:9090"
    max_metrics_hours: int = 24
    baseline_offset_days: int = 7
    # Сколько недель усреднять медианой. Одна точка ненадёжна:
    # сбой или праздник ровно неделю назад искажает базу
    baseline_weeks:       int = 4
    series_max_rows:   int = 500


class DatabaseSettings(BaseModel):
    """Хранилище агента: алерты, чаты, доступы, оценки ответов.

    По умолчанию SQLite рядом с агентом — ставить нечего, переживает рестарт.
    Для нескольких экземпляров агента или общей истории переключается на MySQL
    одной переменной DB_URL.
    """
    url:   str  = "sqlite+aiosqlite:////opt/ai-alert-agent/alerts.db"
    echo:  bool = False
    pool_size:     int = 5
    pool_recycle:  int = 1800     # MySQL рвёт простаивающие соединения
    alerts_retention_days: int = 30
    chats_retention_days:  int = 30

    @property
    def is_sqlite(self) -> bool:
        return self.url.startswith("sqlite")

    @field_validator("url")
    @classmethod
    def _known_driver(cls, v: str) -> str:
        ok = ("sqlite+aiosqlite:", "mysql+asyncmy:", "mysql+aiomysql:")
        if not v.startswith(ok):
            raise ValueError(
                "DB_URL должен начинаться с одного из: " + ", ".join(ok)
                + ". Синхронные драйверы не годятся: приложение асинхронное")
        return v


class AuthSettings(BaseModel):
    enabled:            bool = True
    admin_user:         str  = "admin"
    admin_password_hash: str = ""
    secret:             str  = ""
    session_ttl_hours:  float = 12.0


class LDAPSettings(BaseModel):
    enabled:        bool = False
    url:            str  = ""
    bind_template:  str  = "{username}"
    base_dn:        str  = ""
    user_base:      str  = ""
    user_filter:    str  = "(sAMAccountName={username})"
    search_user:     str = ""
    search_password: str = ""
    search_filter:   str = ""
    search_mode:     str = "prefix"
    allowed_groups:    list[str] = Field(default_factory=list)
    allowed_netgroups: list[str] = Field(default_factory=list)
    netgroup_base:     str = ""
    netgroup_filter:   str = "(objectClass=nisNetgroup)"
    nested_groups:  bool = True
    tls_verify:     bool = True
    # Целое: ldap3 на Linux кладёт таймаут в pack('LL', ...), а struct
    # не принимает дробное и падает с "required argument is not an integer"
    timeout:        int  = 8
    nslcd_conf:     str  = "/etc/nslcd.conf"

    @property
    def search_base(self) -> str:
        return self.user_base or self.base_dn


class SSHSettings(BaseModel):
    """Один доступ на всё: установка экспортёров, чтение логов, туннель к БД."""
    user:    str = ""
    port:    int = 22
    key:     str = ""
    timeout: int = 25


class SQLSettings(BaseModel):
    timeout_s: int = 15
    max_rows:  int = 200
    via_ssh:   str = "direct"     # direct | tunnel | exec


class Settings(BaseModel):
    version:      str = "dev"
    port:         int = 5001
    root_path:    str = ""
    registry_path: str = "/opt/ai-alert-agent/clusters.json"
    web_dir:      str = "/opt/ai-alert-agent/web"
    ingest_tokens: list[str] = Field(default_factory=list)
    alert_dedup_minutes: int = 30
    chat_context_messages: int = 10
    log_max_lines: int = 400
    # Чтение логов идёт дольше обычной команды: на многогигабайтном
    # файле даже суженный поиск занимает десятки секунд
    log_read_timeout: int = 180

    llm:        LLMSettings        = Field(default_factory=LLMSettings)
    prometheus: PrometheusSettings = Field(default_factory=PrometheusSettings)
    db:         DatabaseSettings   = Field(default_factory=DatabaseSettings)
    auth:       AuthSettings       = Field(default_factory=AuthSettings)
    ldap:       LDAPSettings       = Field(default_factory=LDAPSettings)
    ssh:        SSHSettings        = Field(default_factory=SSHSettings)
    sql:        SQLSettings        = Field(default_factory=SQLSettings)

    @property
    def prefix(self) -> str:
        """Префикс пути за nginx, всегда без хвостового слэша."""
        p = "/" + self.root_path.strip().strip("/")
        return "" if p == "/" else p


def _database_url() -> str:
    """DB_URL или SQLite по пути из ALERTS_DB_PATH.

    Старые установки задают только ALERTS_DB_PATH — оставляем их работать
    без правки конфига.
    """
    url = _env("DB_URL").strip()
    if url:
        return url
    path = _env("ALERTS_DB_PATH", "/opt/ai-alert-agent/alerts.db")
    return "sqlite+aiosqlite:///" + path.lstrip("/").join(("/", ""))


def load_settings() -> Settings:
    """Собрать настройки из окружения. Вызывается один раз при старте."""
    return Settings(
        version       = _env("AGENT_VERSION", "dev"),
        port          = int(_env("AGENT_PORT", "5001")),
        root_path     = _env("ROOT_PATH"),
        registry_path = _env("REGISTRY_PATH", "/opt/ai-alert-agent/clusters.json"),
        web_dir       = _env("WEB_DIR", "/opt/ai-alert-agent/web"),
        ingest_tokens = [t.strip() for t in _env("INGEST_TOKENS").split(",") if t.strip()],
        alert_dedup_minutes   = int(_env("ALERT_DEDUP_MINUTES", "30")),
        chat_context_messages = int(_env("CHAT_CONTEXT_MESSAGES", "10")),
        log_max_lines         = int(_env("LOG_MAX_LINES", "400")),
        log_read_timeout      = int(_env("LOG_READ_TIMEOUT", "180")),

        llm=LLMSettings(
            base_url    = _env("LLM_BASE_URL", "https://your-llm-server.com/v1"),
            api_key     = _env("LLM_API_KEY", "your-token-here"),
            model       = _env("LLM_MODEL", "gpt-4o-mini"),
            max_tokens  = int(_env("LLM_MAX_TOKENS", "2048")),
            temperature = float(_env("LLM_TEMPERATURE", "0.3")),
            tools       = _env("LLM_TOOLS", "auto").strip().lower(),
            tool_rounds = int(_env("LLM_TOOL_ROUNDS", "4")),
        ),
        prometheus=PrometheusSettings(
            url                  = _env("PROMETHEUS_URL", "http://localhost:9090"),
            max_metrics_hours    = int(_env("MAX_METRICS_HOURS", "24")),
            baseline_offset_days = int(_env("BASELINE_OFFSET_DAYS", "7")),
            baseline_weeks       = max(1, min(12, int(_env("BASELINE_WEEKS", "4")))),
            series_max_rows      = int(_env("SERIES_MAX_ROWS", "500")),
        ),
        db=DatabaseSettings(
            url   = _database_url(),
            echo  = _flag("DB_ECHO"),
            alerts_retention_days = int(_env("ALERTS_RETENTION_DAYS", "30")),
            chats_retention_days  = int(_env("CHATS_RETENTION_DAYS", "30")),
        ),
        auth=AuthSettings(
            enabled             = _flag("AUTH_ENABLED", "true"),
            admin_user          = _env("AUTH_ADMIN_USER", "admin"),
            admin_password_hash = _env("AUTH_ADMIN_PASSWORD_HASH"),
            secret              = _env("AUTH_SECRET"),
            session_ttl_hours   = float(_env("AUTH_SESSION_TTL_HOURS", "12")),
        ),
        ldap=LDAPSettings(
            enabled         = _flag("LDAP_ENABLED"),
            url             = _env("LDAP_URL"),
            bind_template   = _env("LDAP_BIND_TEMPLATE", "{username}"),
            base_dn         = _env("LDAP_BASE_DN"),
            user_base       = _env("LDAP_USER_BASE").strip(),
            user_filter     = _env("LDAP_USER_FILTER", "(sAMAccountName={username})"),
            search_user     = _env("LDAP_SEARCH_USER"),
            search_password = _env("LDAP_SEARCH_PASSWORD"),
            search_filter   = _env("LDAP_SEARCH_FILTER").strip(),
            search_mode     = _env("LDAP_SEARCH_MODE", "prefix").strip().lower(),
            allowed_groups    = _list("LDAP_ALLOWED_GROUPS"),
            allowed_netgroups = _list("LDAP_ALLOWED_NETGROUPS"),
            netgroup_base     = _env("LDAP_NETGROUP_BASE").strip(),
            netgroup_filter   = _env("LDAP_NETGROUP_FILTER", "(objectClass=nisNetgroup)"),
            nested_groups   = _flag("LDAP_NESTED_GROUPS", "true"),
            tls_verify      = _flag("LDAP_TLS_VERIFY", "true"),
            timeout         = max(1, int(float(_env("LDAP_TIMEOUT") or 8))),
            nslcd_conf      = _env("NSLCD_CONF", "/etc/nslcd.conf"),
        ),
        ssh=SSHSettings(
            user    = _env("SSH_USER"),
            port    = int(_env("SSH_PORT", "22")),
            key     = _env("SSH_KEY"),
            timeout = int(_env("LOG_SSH_TIMEOUT", "25")),
        ),
        sql=SQLSettings(
            timeout_s = int(_env("SQL_TIMEOUT_S", "15")),
            max_rows  = int(_env("SQL_MAX_ROWS", "200")),
            via_ssh   = _env("DB_VIA_SSH", "direct").strip().lower(),
        ),
    )


settings: Settings = load_settings()
