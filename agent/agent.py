"""
MySQL AI Agent v3 — WebSocket streaming chat + мульти-кластер
================================================================
Возможности:
  - WebSocket-чат (/ws) со стримингом токенов от удалённой LLM
  - REST API (совместимость: /chat, /status, /clusters, /alerts/history)
  - Мульти-кластерный реестр (clusters.json)
  - Определение города и временного окна из вопроса на русском
  - Анализ алертов Alertmanager через вебхук
  - Статический веб-интерфейс из /opt/ai-alert-agent/web/
"""

import os
import json
import logging
import datetime
import asyncio
import re
import sqlite3
import secrets
import hmac
import hashlib
import base64
import time
import urllib.parse
import httpx
from contextlib import closing
from pathlib import Path
from typing import Optional, AsyncGenerator
from fastapi import (FastAPI, Request, Response, HTTPException,
                     WebSocket, WebSocketDisconnect)
from fastapi.responses import (HTMLResponse, JSONResponse,
                               RedirectResponse, PlainTextResponse)
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# ══════════════════════════════════════════════════════════════════════════════
#  КОНФИГУРАЦИЯ
# ══════════════════════════════════════════════════════════════════════════════

LLM_BASE_URL    = os.environ.get("LLM_BASE_URL",    "https://your-llm-server.com/v1")
LLM_API_KEY     = os.environ.get("LLM_API_KEY",     "your-token-here")
LLM_MODEL       = os.environ.get("LLM_MODEL",       "gpt-4o-mini")
LLM_MAX_TOKENS  = int(os.environ.get("LLM_MAX_TOKENS", "2048"))
LLM_TEMPERATURE = float(os.environ.get("LLM_TEMPERATURE", "0.3"))
PROMETHEUS_URL  = os.environ.get("PROMETHEUS_URL",  "http://localhost:9090")
AGENT_PORT      = int(os.environ.get("AGENT_PORT",  "5001"))
REGISTRY_PATH   = os.environ.get("REGISTRY_PATH",   "/opt/ai-alert-agent/clusters.json")
WEB_DIR         = os.environ.get("WEB_DIR",         "/opt/ai-alert-agent/web")

# Префикс, под которым агент виден снаружи через nginx (например "/ai-agent").
# Пусто = агент отдаётся в корне. Сами маршруты FastAPI остаются без префикса:
# префикс срезает nginx (proxy_pass со слэшем на конце), а ROOT_PATH нужен лишь
# чтобы страница знала, от какого адреса строить свои ссылки.
ROOT_PATH       = "/" + os.environ.get("ROOT_PATH", "").strip().strip("/")
ROOT_PATH       = "" if ROOT_PATH == "/" else ROOT_PATH

# История алертов: SQLite рядом с агентом, окно хранения в днях
ALERTS_DB_PATH        = os.environ.get("ALERTS_DB_PATH", "/opt/ai-alert-agent/alerts.db")
ALERTS_RETENTION_DAYS = int(os.environ.get("ALERTS_RETENTION_DAYS", "30"))

# История чатов: та же БД. Пользователь опознаётся по client_id из localStorage
# браузера (см. web/app.js), логина в системе нет.
CHATS_RETENTION_DAYS  = int(os.environ.get("CHATS_RETENTION_DAYS", "30"))
CHAT_CONTEXT_MESSAGES = int(os.environ.get("CHAT_CONTEXT_MESSAGES", "16"))

# ══════════════════════════════════════════════════════════════════════════════
#  АУТЕНТИФИКАЦИЯ
#  Три источника, проверяются в этом порядке: SSO-заголовок от доверенного
#  прокси → LDAP/AD → локальный админ. Любой можно выключить.
# ══════════════════════════════════════════════════════════════════════════════

AUTH_ENABLED            = os.environ.get("AUTH_ENABLED", "true").lower() == "true"
AUTH_ADMIN_USER         = os.environ.get("AUTH_ADMIN_USER", "admin")
AUTH_ADMIN_PASSWORD_HASH = os.environ.get("AUTH_ADMIN_PASSWORD_HASH", "")
AUTH_SESSION_TTL_HOURS  = float(os.environ.get("AUTH_SESSION_TTL_HOURS", "12"))
# Секрет подписи сессионных cookie. Если не задан — генерируем на старте,
# но тогда сессии инвалидируются при каждом рестарте агента.
AUTH_SECRET             = os.environ.get("AUTH_SECRET", "") or secrets.token_hex(32)
AUTH_COOKIE             = "mysql_ai_session"

# ── LDAP / Active Directory ──────────────────────────────────────────────────
LDAP_ENABLED          = os.environ.get("LDAP_ENABLED", "false").lower() == "true"
LDAP_URL              = os.environ.get("LDAP_URL", "")
# Шаблон для bind: {username} подставляется. Для AD обычно достаточно UPN:
#   {username}@company.ru      либо   COMPANY\{username}
LDAP_BIND_TEMPLATE    = os.environ.get("LDAP_BIND_TEMPLATE", "{username}")
LDAP_BASE_DN          = os.environ.get("LDAP_BASE_DN", "")
LDAP_USER_FILTER      = os.environ.get("LDAP_USER_FILTER", "(sAMAccountName={username})")
LDAP_REQUIRED_GROUP   = os.environ.get("LDAP_REQUIRED_GROUP", "")
LDAP_TLS_VERIFY       = os.environ.get("LDAP_TLS_VERIFY", "true").lower() == "true"
LDAP_TIMEOUT          = float(os.environ.get("LDAP_TIMEOUT", "8"))
# Сервисная учётка для поиска по каталогу (выбор пользователей из списка).
# Пользовательский bind тут не годится: доступ выдают ДО первого входа.
LDAP_SEARCH_USER      = os.environ.get("LDAP_SEARCH_USER", "")
LDAP_SEARCH_PASSWORD  = os.environ.get("LDAP_SEARCH_PASSWORD", "")
LDAP_SEARCH_FILTER    = os.environ.get(
    "LDAP_SEARCH_FILTER",
    "(&(objectClass=user)(|(sAMAccountName=*{query}*)"
    "(displayName=*{query}*)(mail=*{query}*)))")

# ── SSO через доверенный обратный прокси ─────────────────────────────────────
# nginx с Kerberos/SAML/oauth2-proxy аутентифицирует пользователя и передаёт
# его имя заголовком. Заголовку можно верить ТОЛЬКО если запрос пришёл с
# известного адреса — иначе кто угодно подставит себе любое имя.
SSO_ENABLED           = os.environ.get("SSO_ENABLED", "false").lower() == "true"
SSO_HEADER            = os.environ.get("SSO_HEADER", "X-Remote-User")
SSO_TRUSTED_PROXIES   = [p.strip() for p in
                         os.environ.get("SSO_TRUSTED_PROXIES", "127.0.0.1,::1").split(",")
                         if p.strip()]
SSO_LOGOUT_URL        = os.environ.get("SSO_LOGOUT_URL", "")

# ── Приём алертов из внешних систем (Zabbix и т.п.) ──────────────────────────
# Внешняя система не умеет логиниться cookie, поэтому отдельный токен.
# Несколько токенов через запятую — чтобы отозвать один, не трогая остальные.
INGEST_TOKENS = [t.strip() for t in
                 os.environ.get("INGEST_TOKENS", "").split(",") if t.strip()]

# ── OIDC / OAuth2 (встроенный) ───────────────────────────────────────────────
OIDC_ENABLED        = os.environ.get("OIDC_ENABLED", "false").lower() == "true"
OIDC_ISSUER         = os.environ.get("OIDC_ISSUER", "")
OIDC_CLIENT_ID      = os.environ.get("OIDC_CLIENT_ID", "")
OIDC_CLIENT_SECRET  = os.environ.get("OIDC_CLIENT_SECRET", "")
# Должен совпадать с зарегистрированным у провайдера. За прокси вычислить
# его автоматически нельзя — схему и хост подменяет nginx.
OIDC_REDIRECT_URL   = os.environ.get("OIDC_REDIRECT_URL", "")
OIDC_SCOPES         = os.environ.get("OIDC_SCOPES", "openid profile email")
# Какое поле userinfo считать логином. Для AD/Entra обычно preferred_username
OIDC_USERNAME_CLAIM = os.environ.get("OIDC_USERNAME_CLAIM", "preferred_username")
OIDC_TLS_VERIFY     = os.environ.get("OIDC_TLS_VERIFY", "true").lower() == "true"
OIDC_BUTTON_TEXT    = os.environ.get("OIDC_BUTTON_TEXT", "Войти через SSO")

AUTH_HEADER = LLM_API_KEY if LLM_API_KEY.startswith("Bearer ") else f"Bearer {LLM_API_KEY}"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(),
              logging.FileHandler("/var/log/ai-alert-agent.log")],
)
logger = logging.getLogger("agent")

app = FastAPI(title="MySQL AI Agent v3", version="3.0.0", root_path=ROOT_PATH)
app.add_middleware(CORSMiddleware, allow_origins=["*"],
                   allow_methods=["*"], allow_headers=["*"])


# ══════════════════════════════════════════════════════════════════════════════
#  АУТЕНТИФИКАЦИЯ: пароли, сессии, источники
# ══════════════════════════════════════════════════════════════════════════════

PBKDF2_ITERATIONS = 200_000


def hash_password(password: str, salt: str = "", iterations: int = PBKDF2_ITERATIONS) -> str:
    """pbkdf2_sha256$<итераций>$<соль>$<хеш>. Только stdlib, без bcrypt."""
    salt = salt or secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                             salt.encode("utf-8"), iterations)
    return f"pbkdf2_sha256${iterations}${salt}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, iterations, salt, digest = stored.split("$")
        if algo != "pbkdf2_sha256":
            return False
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                                 salt.encode("utf-8"), int(iterations))
        # сравнение постоянного времени — не даём подбирать хеш по таймингу
        return hmac.compare_digest(dk.hex(), digest)
    except Exception:
        return False


# ── Сессия: подписанный cookie, состояние на сервере не хранится ─────────────

def make_session(username: str, source: str) -> str:
    exp     = int(time.time() + AUTH_SESSION_TTL_HOURS * 3600)
    payload = f"{username}|{source}|{exp}"
    sig     = hmac.new(AUTH_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return base64.urlsafe_b64encode(f"{payload}|{sig}".encode()).decode()


def read_session(token: str) -> Optional[dict]:
    try:
        raw = base64.urlsafe_b64decode(token.encode()).decode()
        username, source, exp, sig = raw.rsplit("|", 3)
        expected = hmac.new(AUTH_SECRET.encode(),
                            f"{username}|{source}|{exp}".encode(),
                            hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected):
            return None
        if int(exp) < time.time():
            return None
        return {"username": username, "source": source, "expires": int(exp)}
    except Exception:
        return None


# ── Источник 1: SSO-заголовок от доверенного прокси ──────────────────────────

def sso_username(request: Request) -> Optional[str]:
    if not SSO_ENABLED:
        return None
    peer = request.client.host if request.client else ""
    if peer not in SSO_TRUSTED_PROXIES:
        # Критично: без этой проверки любой клиент подставит себе чужое имя
        logger.warning(f"SSO-заголовок с недоверенного адреса {peer} — игнорирую")
        return None
    user = (request.headers.get(SSO_HEADER) or "").strip()
    return user or None


# ── Источник 2: LDAP / Active Directory ──────────────────────────────────────

def ldap_authenticate(username: str, password: str) -> bool:
    if not (LDAP_ENABLED and LDAP_URL and username and password):
        return False
    try:
        from ldap3 import Server, Connection, Tls, ALL, SUBTREE
        import ssl as _ssl
    except ImportError:
        logger.error("LDAP включён, но пакет ldap3 не установлен. "
                     "Поставьте: /opt/ai-alert-agent/venv/bin/pip install ldap3")
        return False
    try:
        tls = Tls(validate=_ssl.CERT_REQUIRED if LDAP_TLS_VERIFY else _ssl.CERT_NONE)
        server = Server(LDAP_URL, get_info=ALL, tls=tls,
                        connect_timeout=LDAP_TIMEOUT)
        bind_dn = LDAP_BIND_TEMPLATE.format(username=username)

        conn = Connection(server, user=bind_dn, password=password,
                          auto_bind=True, receive_timeout=LDAP_TIMEOUT)

        # Проверка членства в группе — если она задана
        if LDAP_REQUIRED_GROUP:
            if not LDAP_BASE_DN:
                logger.error("LDAP_REQUIRED_GROUP задан, но LDAP_BASE_DN пуст")
                conn.unbind()
                return False
            flt = ("(&" + LDAP_USER_FILTER.format(username=username) +
                   f"(memberOf={LDAP_REQUIRED_GROUP}))")
            conn.search(LDAP_BASE_DN, flt, search_scope=SUBTREE, attributes=["cn"])
            allowed = bool(conn.entries)
            conn.unbind()
            if not allowed:
                logger.warning(f"LDAP: {username} не состоит в {LDAP_REQUIRED_GROUP}")
            return allowed

        conn.unbind()
        return True
    except Exception as e:
        logger.warning(f"LDAP-аутентификация {username} не прошла: {e}")
        return False


# ── Источник 3: локальный админ ──────────────────────────────────────────────

def local_authenticate(username: str, password: str) -> bool:
    if not AUTH_ADMIN_PASSWORD_HASH:
        return False
    # сравниваем имя тоже за постоянное время
    user_ok = hmac.compare_digest(username or "", AUTH_ADMIN_USER)
    pass_ok = verify_password(password or "", AUTH_ADMIN_PASSWORD_HASH)
    return user_ok and pass_ok


ERR_BAD_CREDS = "Неверный логин или пароль"
ERR_NO_ACCESS = ("Учётная запись найдена, но доступ к системе не выдан. "
                 "Обратитесь к администратору.")


def authenticate(username: str, password: str) -> tuple[Optional[str], str]:
    """(источник, ошибка). Источник None — вход отклонён.

    Локальный админ проверяется первым и не требует записи в списке доступов:
    это bootstrap-учётка, которой список и наполняют.
    """
    if local_authenticate(username, password):
        return "local", ""

    if ldap_authenticate(username, password):
        # Пароль в домене верный — но этого мало, нужен выданный доступ
        if not user_allowed(username):
            logger.warning(f"LDAP-вход {username}: доступ не выдан")
            return None, ERR_NO_ACCESS
        return "ldap", ""

    return None, ERR_BAD_CREDS


def sso_denied(request: Request) -> bool:
    """Прокси аутентифицировал пользователя, но доступ ему не выдавали."""
    name = sso_username(request)
    return bool(name) and not user_allowed(name)


def current_user(request: Request) -> Optional[dict]:
    """Пользователь запроса: сначала SSO, затем сессионный cookie."""
    name = sso_username(request)
    if name:
        if not user_allowed(name):
            logger.warning(f"SSO-вход {name}: доступ не выдан")
            return None
        return {"username": name, "source": "sso"}
    token = request.cookies.get(AUTH_COOKIE, "")
    if not token:
        return None
    sess = read_session(token)
    if not sess:
        return None

    # Подписи и срока мало: доступ могли отозвать уже после выдачи cookie.
    # Локальный админ — исключение, его в списке доступов нет по определению.
    if sess.get("source") != "local" and not user_allowed(sess["username"]):
        logger.warning(f"Сессия {sess['username']}: доступ отозван — вход закрыт")
        return None
    return sess

alert_history: list[dict] = []   # запасная копия в памяти, если БД недоступна
ws_sessions:   dict[str, list[dict]] = {}   # session_id -> messages
# Живые WebSocket-соединения. Без их принудительного закрытия uvicorn
# при остановке ждёт, пока клиенты отключатся сами — а вкладка чата
# держит сокет часами, и рестарт растягивался на минуты.
ws_clients: set = set()


# ══════════════════════════════════════════════════════════════════════════════
#  ХРАНИЛИЩЕ АЛЕРТОВ
#  SQLite из стандартной библиотеки — переживает рестарт агента, новых
#  pip-зависимостей не требует. Записи старше ALERTS_RETENTION_DAYS удаляются.
# ══════════════════════════════════════════════════════════════════════════════

def agent_db() -> sqlite3.Connection:
    conn = sqlite3.connect(ALERTS_DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


def alerts_cutoff() -> str:
    """Нижняя граница окна хранения, ISO-8601 UTC (формат совпадает с ts)."""
    return (datetime.datetime.utcnow()
            - datetime.timedelta(days=ALERTS_RETENTION_DAYS)).isoformat()


def alerts_init() -> bool:
    try:
        Path(ALERTS_DB_PATH).parent.mkdir(parents=True, exist_ok=True)
        with closing(agent_db()) as conn, conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    id            INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts            TEXT NOT NULL,
                    alert         TEXT,
                    cluster       TEXT,
                    cluster_label TEXT,
                    instance      TEXT,
                    severity      TEXT,
                    summary       TEXT,
                    analysis      TEXT
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts)")
            # Миграция: в БД прошлых версий колонки source нет.
            # Всё, что записано до неё, пришло из Alertmanager.
            cols = {r[1] for r in conn.execute("PRAGMA table_info(alerts)")}
            if "source" not in cols:
                conn.execute("ALTER TABLE alerts ADD COLUMN source TEXT")
                conn.execute("UPDATE alerts SET source = 'prometheus'"
                             " WHERE source IS NULL")
                logger.info("В таблицу alerts добавлена колонка source")
            conn.execute("DELETE FROM alerts WHERE ts < ?", (alerts_cutoff(),))
        logger.info(f"История алертов: {ALERTS_DB_PATH}, хранение {ALERTS_RETENTION_DAYS} дн.")
        return True
    except Exception as e:
        logger.error(f"Хранилище алертов недоступно ({ALERTS_DB_PATH}): {e}. "
                     f"История будет только в памяти и потеряется при рестарте.")
        return False


ALERTS_DB_OK = alerts_init()


def alerts_save(rec: dict) -> None:
    """Записать алерт в БД. Копия в памяти — страховка на случай сбоя БД."""
    alert_history.insert(0, rec)
    if len(alert_history) > 200:
        alert_history.pop()

    if not ALERTS_DB_OK:
        return
    try:
        with closing(agent_db()) as conn, conn:
            conn.execute(
                "INSERT INTO alerts (ts, alert, cluster, cluster_label,"
                " instance, severity, summary, analysis, source)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (rec["timestamp"], rec["alert"], rec["cluster"],
                 rec["cluster_label"], rec["instance"], rec["severity"],
                 rec["summary"], rec["analysis"],
                 rec.get("source", "prometheus")))
            conn.execute("DELETE FROM alerts WHERE ts < ?", (alerts_cutoff(),))
    except Exception as e:
        logger.error(f"Не удалось сохранить алерт в {ALERTS_DB_PATH}: {e}")


def alerts_query(cluster: Optional[str] = None,
                 hours: Optional[float] = None,
                 limit: int = 20) -> list[dict]:
    """Выборка алертов для чата: по кластеру и/или окну времени."""
    if not ALERTS_DB_OK:
        rows = [r for r in alert_history
                if not cluster or r.get("cluster") == cluster]
        return rows[:limit]
    try:
        since = alerts_cutoff()
        if hours and hours > 0:
            asked = (datetime.datetime.utcnow()
                     - datetime.timedelta(hours=hours)).isoformat()
            # обе метки в одном ISO-формате, поэтому сравнение строк корректно:
            # не выходим за пределы окна хранения, даже если спросили больше
            since = max(since, asked)

        sql    = ("SELECT ts AS timestamp, alert, cluster, cluster_label,"
                  "       instance, severity, summary, analysis,"
                  "       COALESCE(source, 'prometheus') AS source"
                  "  FROM alerts WHERE ts >= ?")
        params: list = [since]
        if cluster:
            sql += " AND cluster = ?"
            params.append(cluster)
        sql += " ORDER BY ts DESC LIMIT ?"
        params.append(limit)

        with closing(agent_db()) as conn:
            return [dict(r) for r in conn.execute(sql, params).fetchall()]
    except Exception as e:
        logger.error(f"Не удалось выбрать алерты для чата: {e}")
        return []


def alerts_load(limit: int) -> tuple[int, list[dict]]:
    """Отдать историю за окно хранения: (всего за период, последние limit)."""
    if not ALERTS_DB_OK:
        return len(alert_history), alert_history[:limit]
    try:
        cutoff = alerts_cutoff()
        with closing(agent_db()) as conn:
            total = conn.execute(
                "SELECT COUNT(*) FROM alerts WHERE ts >= ?", (cutoff,)).fetchone()[0]
            rows = conn.execute(
                "SELECT id, ts AS timestamp, alert, cluster, cluster_label,"
                "       instance, severity, summary, analysis,"
                "       COALESCE(source, 'prometheus') AS source"
                "  FROM alerts WHERE ts >= ? ORDER BY ts DESC LIMIT ?",
                (cutoff, limit)).fetchall()
        return total, [dict(r) for r in rows]
    except Exception as e:
        logger.error(f"Не удалось прочитать историю алертов: {e}")
        return len(alert_history), alert_history[:limit]


def alerts_delete(alert_id: int) -> bool:
    """Удалить одну запись истории. Ложные срабатывания незачем хранить:
    они попадают в контекст ИИ и искажают разбор следующих инцидентов."""
    if not ALERTS_DB_OK:
        return False
    try:
        with closing(agent_db()) as conn, conn:
            cur = conn.execute("DELETE FROM alerts WHERE id = ?", (alert_id,))
        if cur.rowcount:
            logger.info(f"Удалена запись алерта id={alert_id}")
        return bool(cur.rowcount)
    except Exception as e:
        logger.error(f"Не удалось удалить алерт {alert_id}: {e}")
        return False


def alerts_delete_by_name(name: str) -> int:
    """Удалить все записи одного типа — когда правило ошибочно нагенерировало
    пачку одинаковых срабатываний."""
    if not ALERTS_DB_OK or not name:
        return 0
    try:
        with closing(agent_db()) as conn, conn:
            cur = conn.execute("DELETE FROM alerts WHERE alert = ?", (name,))
        logger.info(f"Удалено записей алерта {name}: {cur.rowcount}")
        return cur.rowcount
    except Exception as e:
        logger.error(f"Не удалось удалить алерты {name}: {e}")
        return 0




def ldap_search_users(query: str, limit: int = 25) -> list[dict]:
    """Поиск по каталогу для выбора кандидатов на доступ.

    Нужна сервисная учётка (LDAP_SEARCH_USER): пользовательский bind тут
    не подходит — админ выбирает людей до того, как они впервые вошли.
    """
    if not (LDAP_ENABLED and LDAP_URL and LDAP_BASE_DN):
        return []
    if not LDAP_SEARCH_USER:
        logger.error("Поиск по каталогу требует сервисной учётки LDAP_SEARCH_USER")
        return []
    q = (query or "").strip()
    if len(q) < 2:
        return []
    try:
        from ldap3 import Server, Connection, Tls, ALL, SUBTREE
        from ldap3.utils.conv import escape_filter_chars
        import ssl as _ssl
    except ImportError:
        logger.error("Поиск по каталогу требует пакета ldap3")
        return []
    try:
        safe = escape_filter_chars(q)      # защита от инъекции в LDAP-фильтр
        tls = Tls(validate=_ssl.CERT_REQUIRED if LDAP_TLS_VERIFY else _ssl.CERT_NONE)
        server = Server(LDAP_URL, get_info=ALL, tls=tls, connect_timeout=LDAP_TIMEOUT)
        conn = Connection(server, user=LDAP_SEARCH_USER,
                          password=LDAP_SEARCH_PASSWORD, auto_bind=True,
                          receive_timeout=LDAP_TIMEOUT)
        flt = LDAP_SEARCH_FILTER.replace("{query}", safe)
        conn.search(LDAP_BASE_DN, flt, search_scope=SUBTREE,
                    attributes=["sAMAccountName", "userPrincipalName",
                                "displayName", "cn", "mail"],
                    size_limit=limit)
        out = []
        for e in conn.entries:
            def attr(name):
                v = getattr(e, name, None)
                return str(v) if v and str(v) != "[]" else ""
            login = attr("sAMAccountName") or attr("userPrincipalName")
            if not login:
                continue
            out.append({
                "username":     norm_username(login),
                "display_name": attr("displayName") or attr("cn") or login,
                "email":        attr("mail"),
            })
        conn.unbind()
        return out
    except Exception as e:
        logger.error(f"Поиск по каталогу не удался: {e}")
        return []


# ══════════════════════════════════════════════════════════════════════════════
#  СПИСОК ДОСТУПОВ
#  Успешная проверка пароля в домене — ещё не право входа. Пользователь должен
#  быть заранее выдан администратором (таблица users). Локальный админ — это
#  bootstrap-учётка, она в списке не нуждается.
# ══════════════════════════════════════════════════════════════════════════════

def users_init() -> bool:
    if not ALERTS_DB_OK:
        return False
    try:
        with closing(agent_db()) as conn, conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    username     TEXT PRIMARY KEY,
                    display_name TEXT,
                    email        TEXT,
                    role         TEXT NOT NULL DEFAULT 'user',
                    enabled      INTEGER NOT NULL DEFAULT 1,
                    granted_by   TEXT,
                    granted_at   TEXT
                )
            """)
        return True
    except Exception as e:
        logger.error(f"Таблица доступов недоступна: {e}")
        return False


USERS_DB_OK = users_init()


def norm_username(name: str) -> str:
    """Приводит к единому виду: домен-префикс отбрасывается, регистр нижний."""
    n = (name or "").strip()
    if "\\" in n:
        n = n.split("\\", 1)[1]
    return n.lower()


def user_get(username: str) -> Optional[dict]:
    if not USERS_DB_OK:
        return None
    try:
        with closing(agent_db()) as conn:
            row = conn.execute(
                "SELECT username, display_name, email, role, enabled,"
                "       granted_by, granted_at"
                "  FROM users WHERE username = ?",
                (norm_username(username),)).fetchone()
        return dict(row) if row else None
    except Exception as e:
        logger.error(f"Не удалось прочитать доступ {username}: {e}")
        return None


def user_allowed(username: str) -> bool:
    """Есть ли у доменного/SSO/OIDC пользователя право входа."""
    u = user_get(username)
    return bool(u and u["enabled"])


def users_list() -> list[dict]:
    if not USERS_DB_OK:
        return []
    try:
        with closing(agent_db()) as conn:
            rows = conn.execute(
                "SELECT username, display_name, email, role, enabled,"
                "       granted_by, granted_at FROM users"
                " ORDER BY enabled DESC, username").fetchall()
        return [dict(r) for r in rows]
    except Exception as e:
        logger.error(f"Не удалось получить список доступов: {e}")
        return []


def user_grant(username: str, display_name: str = "", email: str = "",
               role: str = "user", granted_by: str = "") -> bool:
    if not USERS_DB_OK:
        return False
    uname = norm_username(username)
    if not uname:
        return False
    if role not in ("user", "admin"):
        role = "user"
    try:
        with closing(agent_db()) as conn, conn:
            conn.execute(
                "INSERT INTO users (username, display_name, email, role,"
                "                   enabled, granted_by, granted_at)"
                " VALUES (?, ?, ?, ?, 1, ?, ?)"
                " ON CONFLICT(username) DO UPDATE SET"
                "   display_name = excluded.display_name,"
                "   email        = excluded.email,"
                "   role         = excluded.role,"
                "   enabled      = 1,"
                "   granted_by   = excluded.granted_by,"
                "   granted_at   = excluded.granted_at",
                (uname, display_name, email, role, granted_by,
                 datetime.datetime.utcnow().isoformat()))
        logger.info(f"Доступ выдан: {uname} (роль {role}, выдал {granted_by})")
        return True
    except Exception as e:
        logger.error(f"Не удалось выдать доступ {uname}: {e}")
        return False


def user_revoke(username: str, by: str = "") -> bool:
    """Отзыв мягкий: запись остаётся, чтобы был виден факт выдачи и отзыва."""
    if not USERS_DB_OK:
        return False
    try:
        with closing(agent_db()) as conn, conn:
            cur = conn.execute("UPDATE users SET enabled = 0 WHERE username = ?",
                               (norm_username(username),))
        if cur.rowcount:
            logger.info(f"Доступ отозван: {norm_username(username)} (отозвал {by})")
        return bool(cur.rowcount)
    except Exception as e:
        logger.error(f"Не удалось отозвать доступ: {e}")
        return False


def user_delete(username: str) -> bool:
    if not USERS_DB_OK:
        return False
    try:
        with closing(agent_db()) as conn, conn:
            cur = conn.execute("DELETE FROM users WHERE username = ?",
                               (norm_username(username),))
        return bool(cur.rowcount)
    except Exception as e:
        logger.error(f"Не удалось удалить запись доступа: {e}")
        return False


def is_admin(user: Optional[dict]) -> bool:
    """Локальный админ — всегда админ; доменный — по роли в списке доступов."""
    if not user:
        return False
    if user.get("source") == "local":
        return True
    rec = user_get(user.get("username", ""))
    return bool(rec and rec["enabled"] and rec["role"] == "admin")


# ══════════════════════════════════════════════════════════════════════════════
#  ХРАНИЛИЩЕ ЧАТОВ
#  Та же SQLite. Пользователь опознаётся по client_id — стабильному
#  идентификатору из localStorage браузера (web/app.js). Логина в системе нет,
#  поэтому история приватна ровно в той мере, в какой приватен сам браузер.
# ══════════════════════════════════════════════════════════════════════════════

def chats_cutoff() -> str:
    return (datetime.datetime.utcnow()
            - datetime.timedelta(days=CHATS_RETENTION_DAYS)).isoformat()


def chats_init() -> bool:
    if not ALERTS_DB_OK:
        return False
    try:
        with closing(agent_db()) as conn, conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS chat_messages (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    client_id   TEXT NOT NULL,
                    session_id  TEXT,
                    ts          TEXT NOT NULL,
                    role        TEXT NOT NULL,
                    content     TEXT NOT NULL,
                    fingerprint TEXT
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_chat_client_ts"
                         " ON chat_messages(client_id, ts)")
            conn.execute("DELETE FROM chat_messages WHERE ts < ?", (chats_cutoff(),))
        logger.info(f"История чатов: {ALERTS_DB_PATH}, хранение {CHATS_RETENTION_DAYS} дн.")
        return True
    except Exception as e:
        logger.error(f"Хранилище чатов недоступно: {e}. "
                     f"История чатов будет только в памяти.")
        return False


CHATS_DB_OK = chats_init()


def chat_save(client_id: str, session_id: str, role: str,
              content: str, fingerprint: str = "") -> None:
    if not CHATS_DB_OK or not client_id:
        return
    try:
        with closing(agent_db()) as conn, conn:
            conn.execute(
                "INSERT INTO chat_messages"
                " (client_id, session_id, ts, role, content, fingerprint)"
                " VALUES (?, ?, ?, ?, ?, ?)",
                (client_id, session_id,
                 datetime.datetime.utcnow().isoformat(),
                 role, content, fingerprint))
            conn.execute("DELETE FROM chat_messages WHERE ts < ?", (chats_cutoff(),))
    except Exception as e:
        logger.error(f"Не удалось сохранить сообщение чата: {e}")


def chat_load(client_id: str, limit: int = 40) -> list[dict]:
    """Последние сообщения пользователя в хронологическом порядке."""
    if not CHATS_DB_OK or not client_id:
        return []
    try:
        with closing(agent_db()) as conn:
            rows = conn.execute(
                "SELECT ts, role, content FROM chat_messages"
                "  WHERE client_id = ? AND ts >= ?"
                "  ORDER BY ts DESC, id DESC LIMIT ?",
                (client_id, chats_cutoff(), limit)).fetchall()
        # из БД пришло от новых к старым — разворачиваем для показа и для LLM
        return [{"role": r["role"], "content": r["content"], "ts": r["ts"]}
                for r in reversed(rows)]
    except Exception as e:
        logger.error(f"Не удалось прочитать историю чата: {e}")
        return []


def chat_clear(client_id: str) -> int:
    if not CHATS_DB_OK or not client_id:
        return 0
    try:
        with closing(agent_db()) as conn, conn:
            cur = conn.execute("DELETE FROM chat_messages WHERE client_id = ?",
                               (client_id,))
            return cur.rowcount
    except Exception as e:
        logger.error(f"Не удалось очистить историю чата: {e}")
        return 0


def chat_restore(client_id: str) -> list[dict]:
    """Поднять историю для LLM: последняя выжимка + всё, что после неё.

    Так после рестарта агента разговор продолжается с того же места, а не
    с обрывка последних реплик.
    """
    rows = chat_load(client_id, CHAT_CONTEXT_MESSAGES * 3)
    if not rows:
        return []
    # индекс последней выжимки — всё, что до неё, уже в ней учтено
    last_sum = max((k for k, m in enumerate(rows) if m["role"] == "summary"),
                   default=None)
    if last_sum is not None:
        rows = rows[last_sum:]
    return [{"role": m["role"], "content": m["content"]}
            for m in rows][-CHAT_CONTEXT_MESSAGES:]


async def chat_summarize(client_id: str, older: list[dict]) -> str:
    """Сжать вытесняемую часть переписки в короткую выжимку.

    Вызывается, когда история упирается в окно контекста. Без этого старые
    сообщения просто отбрасывались, и агент «забывал» ранее выясненное —
    например, что отставание реплики уже разобрали и оно плановое.
    """
    if not older:
        return ""
    dialog = "\n".join(
        f"{'Пользователь' if m['role'] == 'user' else 'Агент'}: {m['content']}"
        for m in older)[:12000]

    prompt = [
        {"role": "system",
         "content": "Ты ведёшь конспект технической переписки по мониторингу MySQL."},
        {"role": "user",
         "content": (
             "Сожми переписку ниже в выжимку до 15 строк. Сохрани только то, "
             "что понадобится дальше: какие кластеры обсуждали, какие проблемы "
             "нашли и чем закончилось, какие выводы уже сделаны (в том числе "
             "«проблемы нет»), какие значения метрик назывались, что решили "
             "сделать. Без вступлений и без воды.\n\n" + dialog)},
    ]
    try:
        return (await llm_complete(prompt)).strip()
    except Exception as e:
        logger.error(f"Не удалось построить выжимку истории: {e}")
        return ""


def chat_save_summary(client_id: str, session_id: str, text: str) -> None:
    if not text:
        return
    chat_save(client_id, session_id, "summary", text)


async def chat_compact(client_id: str, session_id: str,
                       history: list[dict]) -> list[dict]:
    """Ужать историю до окна контекста, вытесненное — в выжимку.

    Возвращает новую историю: [выжимка] + последние сообщения.
    """
    if len(history) <= CHAT_CONTEXT_MESSAGES:
        return history

    keep  = CHAT_CONTEXT_MESSAGES // 2          # что оставляем дословно
    older = [m for m in history[:-keep] if m.get("role") in ("user", "assistant")]
    tail  = history[-keep:]

    digest = await chat_summarize(client_id, older)
    if not digest:
        # выжимка не получилась — ведём себя как раньше, просто обрезаем
        return history[-CHAT_CONTEXT_MESSAGES:]

    chat_save_summary(client_id, session_id, digest)
    logger.info(f"История {client_id}: {len(older)} сообщений сжаты в выжимку")
    return [{"role": "summary", "content": digest}] + tail


def history_to_messages(history: list[dict]) -> list[dict]:
    """Роль summary в OpenAI-совместимый API отправлять нельзя — подаём
    её как системное сообщение с пометкой, что это конспект."""
    out = []
    for m in history:
        if m.get("role") == "summary":
            out.append({"role": "system",
                        "content": "Конспект более ранней части разговора:\n"
                                   + m["content"]})
        else:
            out.append({"role": m["role"], "content": m["content"]})
    return out


# ══════════════════════════════════════════════════════════════════════════════
#  РЕЕСТР КЛАСТЕРОВ
# ══════════════════════════════════════════════════════════════════════════════

def load_registry() -> dict:
    try:
        with open(REGISTRY_PATH, encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        logger.warning(f"Реестр не загружен ({REGISTRY_PATH}): {e}")
        return {"clusters": []}


def enabled_clusters() -> list[dict]:
    return [c for c in load_registry()["clusters"] if c.get("enabled", True)]


def find_cluster(name: str) -> Optional[dict]:
    for c in enabled_clusters():
        if c["name"].lower() == name.lower():
            return c
    return None


def find_cluster_by_ip(ip: str) -> Optional[dict]:
    for c in enabled_clusters():
        if c.get("primary_ip") == ip or c.get("replica_ip") == ip:
            return c
    return None


def detect_cluster_in_text(text: str) -> Optional[dict]:
    """Найти кластер по названию города в тексте (регистронезависимо, с учётом падежей)."""
    t = text.lower()
    for c in enabled_clusters():
        label = c["label"].lower()
        # Точное вхождение label / name
        if label in t or c["name"].lower() in t:
            return c
        # Морфологическая обрезка: "Кемерово" находит "в Кемерове",
        # "Новосибирск" находит "в Новосибирске"
        stem = label[:max(4, len(label) - 2)]
        if len(stem) >= 4 and stem in t:
            return c
        for tag in c.get("tags", []):
            if tag.lower() in t:
                return c
    return None


def clusters_index_text() -> str:
    cs = enabled_clusters()
    if not cs:
        return "Кластеры не настроены."
    lines = []
    for c in cs:
        lines.append(
            f"  - name={c['name']}  город='{c['label']}'  "
            f"primary={c['primary_ip']}  replica={c.get('replica_ip') or 'нет'}  "
            f"описание='{c.get('description', '')}'"
        )
    return "\n".join(lines)


# ══════════════════════════════════════════════════════════════════════════════
#  ВРЕМЕННЫЕ ОКНА (для "вчера", "2 часа назад" и т.п.)
# ══════════════════════════════════════════════════════════════════════════════

TIME_KEYWORDS = {
    "позавчера": 54, "вчера": 30,
    "прошлый день": 30, "прошлой ночью": 16,
    "утром": 14, "ночью": 12, "вечером": 12, "днём": 12, "днем": 12,
    "сегодня": 24, "за сегодня": 24,
    "последние сутки": 26, "за сутки": 26, "сутки": 26, "за день": 26,
    "на прошлой неделе": 170, "прошлой неделе": 170,
    "за неделю": 170, "неделю": 170, "недели": 170,
    "за две недели": 340, "за месяц": 730, "месяц": 730,
    "час назад": 2, "часа назад": 4, "часов назад": 8,
}

# Вопросы про историю без явного периода: «покажи динамику», «был ли рост».
# Для них берём окно по умолчанию, иначе агент отвечает, что данных нет,
# хотя Prometheus их хранит.
# Вопросы, при которых в контекст подмешивается история алертов из БД.
# Держим список узким: лишний блок только раздувает промпт.
ALERT_KEYWORDS = (
    "алерт", "alert", "инцидент", "авари", "срабатыв", "сработа",
    "тревог", "происшеств", "что случилось", "сбой", "сбои", "сбоя",
    "были проблем", "была проблем", "проблемы были", "падал", "падени",
)


def detect_alert_intent(text: str) -> bool:
    t = text.lower()
    return any(kw in t for kw in ALERT_KEYWORDS)


HISTORY_KEYWORDS = (
    "истори", "динамик", "тренд", "за период", "график", "графики",
    "как менялось", "как менялась", "как изменил", "рост", "росла", "рос ли",
    "падал", "падени", "снижал", "было раньше", "в прошлом",
    "статистик", "средн", "пик", "максимум за", "минимум за",
)
DEFAULT_HISTORY_HOURS = 24.0
# Потолок окна для МЕТРИК: за более длинный период выборка распухает,
# а пользы в разборе не прибавляется. История алертов живёт отдельно
# и этим потолком не ограничена (ALERTS_RETENTION_DAYS).
MAX_METRICS_HOURS = float(os.environ.get("MAX_METRICS_HOURS", "24"))


def detect_history_intent(text: str) -> bool:
    t = text.lower()
    return any(kw in t for kw in HISTORY_KEYWORDS)


# «за последний час» цифры не содержит, но период назван вполне однозначно.
# Раньше такие фразы проваливались в дефолт 24 ч.
WORD_PERIODS = {
    "последние полчаса": 0.5, "полчаса": 0.5, "последних полчаса": 0.5,
    "последний час": 1.5, "последнего часа": 1.5, "последнюю часу": 1.5,
    "за час": 1.5, "последний часа": 1.5,
    "пару часов": 2.5, "пары часов": 2.5, "несколько часов": 4,
    "последние два часа": 2.5, "последние три часа": 3.5,
    "последние сутки": 26, "последних суток": 26,
    "последнюю неделю": 170, "последней недели": 170,
    "последний месяц": 730, "последнего месяца": 730,
}


def detect_time_hours(text: str) -> float:
    """Окно в часах из фразы. 0 — период не назван."""
    t = text.lower()

    # словесные периоды проверяем ПЕРВЫМИ: они длиннее и однозначнее
    for kw, hours in sorted(WORD_PERIODS.items(), key=lambda kv: -len(kv[0])):
        if kw in t:
            return float(hours)

    # минуты — для коротких окон вида «за последние 30 минут»
    m = re.search(r'за\s+(?:послед[а-яё]+\s+)?(\d+)\s+минут', t)
    if m:
        return max(float(m.group(1)) / 60 + 0.25, 0.5)

    m = re.search(r'за\s+(?:послед[а-яё]+\s+)?(\d+)\s+час', t)
    if m:
        return float(m.group(1)) + 0.5
    m = re.search(r'(\d+)\s+час[а-яё]*\s+назад', t)
    if m:
        return float(m.group(1)) + 1

    # дни и недели: «за 3 дня», «за последние 2 недели», «5 дней назад»
    m = re.search(r'за\s+(?:послед[а-яё]+\s+)?(\d+)\s+(?:дн|сут)', t)
    if m:
        return float(m.group(1)) * 24 + 2
    m = re.search(r'(\d+)\s+(?:дн|сут)[а-яё]*\s+назад', t)
    if m:
        return float(m.group(1)) * 24 + 12
    m = re.search(r'за\s+(?:послед[а-яё]+\s+)?(\d+)\s+недел', t)
    if m:
        return float(m.group(1)) * 168 + 2
    m = re.search(r'за\s+(?:послед[а-яё]+\s+)?(\d+)\s+месяц', t)
    if m:
        return float(m.group(1)) * 730

    for kw, hours in TIME_KEYWORDS.items():
        if kw in t:
            return float(hours)

    # Период не назван, но спрашивают про историю или детализацию —
    # берём окно по умолчанию. Без этого «детально по Владивостоку» давало
    # окно 0, и таблица не строилась вовсе.
    if detect_history_intent(t) or detect_breakdown_intent(t):
        return DEFAULT_HISTORY_HOURS
    return 0.0


# ══════════════════════════════════════════════════════════════════════════════
#  PROMETHEUS
# ══════════════════════════════════════════════════════════════════════════════

async def prom_query(client: httpx.AsyncClient, query: str) -> Optional[float]:
    try:
        r = await client.get(f"{PROMETHEUS_URL}/api/v1/query",
                             params={"query": query}, timeout=10.0)
        d = r.json()
        if d.get("status") == "success" and d["data"]["result"]:
            return round(float(d["data"]["result"][0]["value"][1]), 3)
    except Exception:
        pass
    return None


async def prom_range_summary(client: httpx.AsyncClient, query: str,
                             hours: float) -> dict:
    """Мин/макс/среднее за период + время пиков."""
    end   = datetime.datetime.utcnow()
    start = end - datetime.timedelta(hours=hours)
    step  = "300" if hours > 6 else "60"
    try:
        r = await client.get(
            f"{PROMETHEUS_URL}/api/v1/query_range",
            params={"query": query,
                    "start": start.isoformat() + "Z",
                    "end":   end.isoformat() + "Z",
                    "step":  step},
            timeout=15.0)
        d = r.json()
        if d.get("status") == "success" and d["data"]["result"]:
            vals = [(v[0], float(v[1])) for v in d["data"]["result"][0]["values"]]
            if not vals:
                return {}
            vs      = [v[1] for v in vals]
            max_i   = vs.index(max(vs))
            min_i   = vs.index(min(vs))
            fmt     = lambda ts: datetime.datetime.utcfromtimestamp(ts).strftime("%H:%M UTC")
            return {
                "min":      round(min(vs), 2),
                "max":      round(max(vs), 2),
                "avg":      round(sum(vs) / len(vs), 2),
                "max_time": fmt(vals[max_i][0]),
                "min_time": fmt(vals[min_i][0]),
            }
    except Exception:
        pass
    return {}


# ══════════════════════════════════════════════════════════════════════════════
#  ДАННЫЕ ДЛЯ ГРАФИКОВ
#  Ряды отдаются как есть, рисует их браузер инлайновым SVG. Так не нужны ни
#  библиотеки графиков (закрытый контур — CDN недоступен), ни серверный рендер.
# ══════════════════════════════════════════════════════════════════════════════

# Набор показателей для графиков и отчёта. {inst} — primary, {node} — его node,
# {repl} — реплика. Панели без нужных плейсхолдеров пропускаются.
CHART_SPECS = [
    {"key": "qps", "title": "Запросы в секунду", "unit": "/с",
     "expr": 'rate(mysql_global_status_queries{{instance="{inst}"}}[5m])'},
    {"key": "slow", "title": "Медленные запросы", "unit": "/с",
     "expr": 'rate(mysql_global_status_slow_queries{{instance="{inst}"}}[5m])'},
    {"key": "conn", "title": "Подключения", "unit": "",
     "expr": 'mysql_global_status_threads_connected{{instance="{inst}"}}'},
    {"key": "conn_pct", "title": "Использование лимита подключений", "unit": "%",
     "expr": 'mysql_global_status_threads_connected{{instance="{inst}"}}'
             '/mysql_global_variables_max_connections{{instance="{inst}"}}*100'},
    {"key": "innodb_hit", "title": "InnoDB buffer pool hit rate", "unit": "%",
     "expr": '100*(1-(rate(mysql_global_status_innodb_buffer_pool_reads{{instance="{inst}"}}[5m])'
             '/clamp_min(rate(mysql_global_status_innodb_buffer_pool_read_requests'
             '{{instance="{inst}"}}[5m]),1)))'},
    {"key": "cpu", "title": "CPU сервера", "unit": "%",
     "expr": '100-(avg by(instance)(rate(node_cpu_seconds_total'
             '{{mode="idle",instance="{node}"}}[5m]))*100)'},
    {"key": "iowait", "title": "CPU iowait", "unit": "%",
     "expr": 'avg by(instance)(rate(node_cpu_seconds_total'
             '{{mode="iowait",instance="{node}"}}[5m]))*100'},
    {"key": "mem", "title": "Занято памяти", "unit": "%",
     "expr": '100*(1-(node_memory_MemAvailable_bytes{{instance="{node}"}}'
             '/node_memory_MemTotal_bytes{{instance="{node}"}}))'},
    {"key": "disk_io", "title": "Дисковый ввод-вывод", "unit": "Б/с",
     "expr": 'sum(rate(node_disk_read_bytes_total{{instance="{node}"}}[5m])'
             '+rate(node_disk_written_bytes_total{{instance="{node}"}}[5m]))'},
    {"key": "repl_lag", "title": "Отставание реплики сверх плана", "unit": "с",
     "expr": 'mysql:replica_effective_lag_seconds{{instance="{repl}"}}',
     "needs_replica": True},
]


async def prom_range_series(client: httpx.AsyncClient, query: str,
                            hours: float) -> list[list]:
    """Сырой ряд [[unix_ts, значение], ...] — для отрисовки графика."""
    end   = datetime.datetime.utcnow()
    start = end - datetime.timedelta(hours=hours)
    # ~200 точек на график: больше браузеру не нужно, меньше — теряется форма
    step  = max(int(hours * 3600 / 200), 15)
    try:
        r = await client.get(
            f"{PROMETHEUS_URL}/api/v1/query_range",
            params={"query": query,
                    "start": start.isoformat() + "Z",
                    "end":   end.isoformat() + "Z",
                    "step":  str(step)},
            timeout=20.0)
        d = r.json()
        if d.get("status") != "success" or not d["data"]["result"]:
            return []
        return [[int(float(v[0])), round(float(v[1]), 3)]
                for v in d["data"]["result"][0]["values"]]
    except Exception as e:
        logger.error(f"Не удалось получить ряд для графика: {e}")
        return []


async def build_charts(cluster: dict, hours: float,
                       keys: Optional[list[str]] = None) -> list[dict]:
    """Собрать данные графиков по кластеру за период."""
    prim = cluster["primary_ip"]
    repl = cluster.get("replica_ip", "")
    ctx  = {"inst": f"{prim}:9104", "node": f"{prim}:9100",
            "repl": f"{repl}:9104" if repl else ""}

    specs = [s for s in CHART_SPECS
             if (not s.get("needs_replica") or repl)
             and (not keys or s["key"] in keys)]

    async with httpx.AsyncClient() as client:
        series = await asyncio.gather(
            *[prom_range_series(client, s["expr"].format(**ctx), hours)
              for s in specs])

    charts = []
    for spec, points in zip(specs, series):
        if not points:
            continue
        vals = [p[1] for p in points]
        charts.append({
            "key":    spec["key"],
            "title":  spec["title"],
            "unit":   spec["unit"],
            "points": points,
            "min":    round(min(vals), 2),
            "max":    round(max(vals), 2),
            "avg":    round(sum(vals) / len(vals), 2),
            "last":   vals[-1],
        })
    return charts


async def collect_current(cluster: dict) -> dict:
    """Текущие метрики кластера (async, параллельно)."""
    async with httpx.AsyncClient() as client:
        async def metrics_for(ip: str) -> dict:
            inst  = f"{ip}:9104"
            node  = f"{ip}:9100"
            queries = {
                "mysql_up":            f'mysql_up{{instance="{inst}"}}',
                "qps":                 f'rate(mysql_global_status_queries{{instance="{inst}"}}[5m])',
                "slow_qps":            f'rate(mysql_global_status_slow_queries{{instance="{inst}"}}[5m])',
                "connections_pct":     f'mysql_global_status_threads_connected{{instance="{inst}"}}/mysql_global_variables_max_connections{{instance="{inst}"}}*100',
                "connections_now":     f'mysql_global_status_threads_connected{{instance="{inst}"}}',
                "innodb_hit_pct":      f'(1-rate(mysql_global_status_innodb_buffer_pool_reads{{instance="{inst}"}}[5m])/rate(mysql_global_status_innodb_buffer_pool_read_requests{{instance="{inst}"}}[5m]))*100',
                "row_lock_waits":      f'rate(mysql_global_status_innodb_row_lock_waits{{instance="{inst}"}}[5m])',
                "aborted_connects":    f'rate(mysql_global_status_aborted_connects{{instance="{inst}"}}[5m])',
                "cpu_pct":             f'100-(avg by(instance)(rate(node_cpu_seconds_total{{mode="idle",instance="{node}"}}[5m]))*100)',
                "memory_pct":          f'(node_memory_MemTotal_bytes{{instance="{node}"}}-node_memory_MemAvailable_bytes{{instance="{node}"}})/node_memory_MemTotal_bytes{{instance="{node}"}}*100',
                "disk_free_pct":       f'node_filesystem_avail_bytes{{instance="{node}",mountpoint="/"}}/node_filesystem_size_bytes{{instance="{node}",mountpoint="/"}}*100',
                "iowait_pct":          f'avg by(instance)(rate(node_cpu_seconds_total{{mode="iowait",instance="{node}"}}[5m]))*100',
            }
            keys    = list(queries.keys())
            results = await asyncio.gather(*[prom_query(client, queries[k]) for k in keys])
            return {k: (str(v) if v is not None else "нет данных")
                    for k, v in zip(keys, results)}

        out = {
            "cluster_name":  cluster["name"],
            "cluster_label": cluster["label"],
            "primary":       await metrics_for(cluster["primary_ip"]),
        }
        repl_ip = cluster.get("replica_ip")
        if repl_ip:
            rep  = await metrics_for(repl_ip)
            inst = f"{repl_ip}:9104"
            lag, io, sql, planned = await asyncio.gather(
                prom_query(client, f'mysql_slave_status_seconds_behind_master{{instance="{inst}"}}'),
                prom_query(client, f'mysql_slave_status_slave_io_running{{instance="{inst}"}}'),
                prom_query(client, f'mysql_slave_status_slave_sql_running{{instance="{inst}"}}'),
                # Плановая задержка — из SQL_Delay самой реплики (recording rule
                # его вычисляет и подставляет запасное значение из реестра)
                prom_query(client, f'mysql:replica_configured_delay_seconds{{instance="{inst}"}}'),
            )
            # Отставание СВЕРХ плана считает Prometheus тем же правилом, что
            # питает дашборд и алерты. Не дублируем расчёт здесь: разъехавшиеся
            # цифры в чате и на графике — худшее, что может быть при разборе.
            over = await prom_query(
                client, f'mysql:replica_effective_lag_seconds{{instance="{inst}"}}')

            plan_s = float(planned) if planned is not None else 0.0
            if over is None and lag is not None:
                # правило ещё не подгрузилось — считаем сами, чтобы не молчать
                over = max(float(lag) - plan_s, 0)

            rep["replication_planned_delay_s"]  = (
                str(plan_s) if planned is not None else "нет данных")
            rep["replication_lag_over_plan_s"]  = (
                str(over) if over is not None else "нет данных")
            rep["replication_lag_raw_s"] = str(lag) if lag is not None else "нет данных"
            rep["replication_io_up"]  = str(io)  if io  is not None else "нет данных"
            rep["replication_sql_up"] = str(sql) if sql is not None else "нет данных"
            out["replica"] = rep
        return out


async def collect_history(cluster: dict, hours: float) -> dict:
    """История: min/avg/max + время пиков по ключевым метрикам."""
    prim = cluster["primary_ip"]
    repl = cluster.get("replica_ip", "")
    inst = f"{prim}:9104"

    async with httpx.AsyncClient() as client:
        queries = {
            "qps":             f'rate(mysql_global_status_queries{{instance="{inst}"}}[5m])',
            "slow_qps":        f'rate(mysql_global_status_slow_queries{{instance="{inst}"}}[5m])',
            "connections_pct": f'mysql_global_status_threads_connected{{instance="{inst}"}}/mysql_global_variables_max_connections{{instance="{inst}"}}*100',
            "cpu_pct":         f'100-(avg by(instance)(rate(node_cpu_seconds_total{{mode="idle",instance="{prim}:9100"}}[5m]))*100)',
            "iowait_pct":      f'avg by(instance)(rate(node_cpu_seconds_total{{mode="iowait",instance="{prim}:9100"}}[5m]))*100',
            "row_lock_waits":  f'rate(mysql_global_status_innodb_row_lock_waits{{instance="{inst}"}}[5m])',
        }
        if repl:
            # Тот же recording rule, что у дашборда и алертов
            queries["replication_lag_over_plan_s"] = (
                f'mysql:replica_effective_lag_seconds{{instance="{repl}:9104"}}')

        keys    = list(queries.keys())
        results = await asyncio.gather(
            *[prom_range_summary(client, queries[k], hours) for k in keys])

        return {"period_hours": hours,
                **{k: v for k, v in zip(keys, results)}}


# ══════════════════════════════════════════════════════════════════════════════
#  LLM — обычный вызов и стриминг


# ══════════════════════════════════════════════════════════════════════════════
#  SQL-ЗАПРОСЫ К КЛАСТЕРАМ
#  Только чтение. Учётка задаётся в clusters.json (db_user/db_password), одна
#  на все серверы кластера. Прав нужно ровно SELECT — писать агент не должен
#  ни при каких обстоятельствах, поэтому запрет проверяется до отправки.
# ══════════════════════════════════════════════════════════════════════════════

SQL_MAX_ROWS    = int(os.environ.get("SQL_MAX_ROWS", "200"))
SQL_TIMEOUT_S   = int(os.environ.get("SQL_TIMEOUT_S", "15"))

# Разрешены только читающие формы. SHOW/EXPLAIN/DESCRIBE нужны для диагностики.
SQL_ALLOWED_HEADS = ("select", "show", "explain", "describe", "desc", "with")

# Явный чёрный список — вторая линия после проверки первого слова: WITH ... может
# в MySQL 8 содержать изменяющие конструкции, а комментарии умеют их прятать.
SQL_FORBIDDEN = (
    "insert", "update", "delete", "drop", "truncate", "alter", "create",
    "rename", "replace", "grant", "revoke", "set", "call", "lock", "unlock",
    "load", "handler", "flush", "kill", "start", "commit", "rollback",
    "savepoint", "prepare", "execute", "outfile", "dumpfile",
)


def sql_strip_comments(sql: str) -> str:
    """Убрать комментарии: без этого запрет обходится через /*!*/ и -- ."""
    sql = re.sub(r"/\*.*?\*/", " ", sql, flags=re.S)
    sql = re.sub(r"--[^\n]*", " ", sql)
    sql = re.sub(r"#[^\n]*", " ", sql)
    return sql.strip()


def sql_validate(sql: str) -> tuple[bool, str]:
    """(можно ли выполнять, причина отказа)."""
    # MySQL ИСПОЛНЯЕТ содержимое /*! ... */ и /*+ ... */. Если просто вырезать
    # комментарии перед проверкой, туда прячется что угодно — поэтому такие
    # конструкции отклоняем целиком, до разбора.
    if re.search(r"/\*[!+]", sql):
        return False, "Исполняемые комментарии MySQL (/*! …) запрещены"

    clean = sql_strip_comments(sql)
    if not clean:
        return False, "Пустой запрос"

    # Несколько инструкций в одном запросе не пропускаем: точка с запятой
    # допустима только как завершающая.
    body = clean.rstrip(";").strip()
    if ";" in body:
        return False, "Разрешён только один запрос без ';' внутри"

    low = body.lower()
    head = low.split(None, 1)[0] if low.split() else ""
    if head not in SQL_ALLOWED_HEADS:
        return False, f"Разрешены только {', '.join(SQL_ALLOWED_HEADS).upper()}"

    # Границы слова с ОБЕИХ сторон: без хвостовой границы «created» ловился
    # как CREATE, и нормальные запросы отклонялись.
    flat = re.sub(r"\s+", " ", low)
    for bad in SQL_FORBIDDEN:
        if re.search(r"(?<![a-z0-9_])" + re.escape(bad) + r"(?![a-z0-9_])", flat):
            return False, f"Запрещённая конструкция: {bad.upper()}"

    return True, ""


def sql_add_limit(sql: str) -> str:
    """Дописать LIMIT, если его нет — чтобы не вытащить миллион строк."""
    body = sql_strip_comments(sql).rstrip(";").strip()
    if re.search(r"(?<![a-z_])limit\s+\d", body, re.I):
        return body
    if body.lower().startswith(("show", "explain", "describe", "desc")):
        return body           # у них LIMIT либо не нужен, либо не поддержан
    return f"{body} LIMIT {SQL_MAX_ROWS}"


def cluster_db_creds(cluster: dict) -> Optional[tuple]:
    user = (cluster.get("db_user") or "").strip()
    if not user:
        return None
    return user, cluster.get("db_password") or ""


def sql_run(cluster: dict, sql: str, host: Optional[str] = None) -> dict:
    """Выполнить читающий запрос. Возвращает {columns, rows, error, ...}."""
    creds = cluster_db_creds(cluster)
    if not creds:
        return {"error": "Для этого кластера не задана учётка db_user — "
                         "SQL-запросы отключены"}
    ok, why = sql_validate(sql)
    if not ok:
        logger.warning(f"SQL отклонён ({why}): {sql[:120]}")
        return {"error": f"Запрос отклонён: {why}"}

    try:
        import pymysql
    except ImportError:
        return {"error": "Не установлен pymysql — переустановите агента "
                         "с заполненным db_user в clusters.json"}

    user, password = creds
    ip = host or cluster["primary_ip"]
    query = sql_add_limit(sql)
    try:
        conn = pymysql.connect(
            host=ip, user=user, password=password,
            connect_timeout=SQL_TIMEOUT_S, read_timeout=SQL_TIMEOUT_S,
            charset="utf8mb4", cursorclass=pymysql.cursors.Cursor,
            autocommit=True)
    except Exception as e:
        return {"error": f"Не удалось подключиться к {ip}: {e}"}

    try:
        with conn.cursor() as cur:
            # Страховка на стороне сервера: даже если валидатор что-то упустил,
            # сессия не сможет писать.
            try:
                cur.execute("SET SESSION TRANSACTION READ ONLY")
            except Exception:
                pass          # на реплике может быть уже read_only
            cur.execute(f"SET SESSION MAX_EXECUTION_TIME={SQL_TIMEOUT_S * 1000}")
            cur.execute(query)
            cols = [d[0] for d in (cur.description or [])]
            rows = cur.fetchmany(SQL_MAX_ROWS)
        return {"host": ip, "query": query, "columns": cols,
                "rows": [list(r) for r in rows], "truncated": len(rows) >= SQL_MAX_ROWS}
    except Exception as e:
        return {"error": f"Ошибка выполнения на {ip}: {e}"}
    finally:
        try:
            conn.close()
        except Exception:
            pass


def fmt_sql_result(res: dict) -> str:
    if res.get("error"):
        return f"## Результат SQL\n\n  {res['error']}"
    cols, rows = res["columns"], res["rows"]
    head = [f"## Результат SQL ({res['host']})",
            f"  Запрос: {res['query']}", ""]
    if not rows:
        head.append("  Строк не найдено.")
        return "\n".join(head)

    def cell(v):
        s = "NULL" if v is None else str(v)
        return s[:60] + "…" if len(s) > 60 else s

    widths = [max(len(c), *(len(cell(r[i])) for r in rows)) for i, c in enumerate(cols)]
    head.append("  " + " | ".join(c.ljust(w) for c, w in zip(cols, widths)))
    head.append("  " + "-+-".join("-" * w for w in widths))
    for r in rows:
        head.append("  " + " | ".join(cell(v).ljust(w) for v, w in zip(r, widths)))
    if res.get("truncated"):
        head.append(f"  (показаны первые {SQL_MAX_ROWS} строк)")
    return "\n".join(head)


# ── Версии СУБД: получаем на старте, чтобы LLM знала, о чём пишет ────────────
DB_VERSIONS: dict = {}


def refresh_db_versions() -> None:
    """Спросить версию у каждого кластера. Без этого агент советует синтаксис
    наугад: у 5.7 и 8.0 разные имена таблиц performance_schema и разный SHOW."""
    for c in enabled_clusters():
        if not cluster_db_creds(c):
            continue
        res = sql_run(c, "SELECT VERSION() AS v, @@version_comment AS c")
        if res.get("error") or not res.get("rows"):
            logger.warning(f"Версия БД {c['name']} не получена: "
                           f"{res.get('error', 'пустой ответ')}")
            continue
        ver = str(res["rows"][0][0])
        note = str(res["rows"][0][1]) if len(res["rows"][0]) > 1 else ""
        DB_VERSIONS[c["name"]] = f"{ver} ({note})".strip()
        logger.info(f"MySQL {c['label']}: {DB_VERSIONS[c['name']]}")


def db_versions_text() -> str:
    if not DB_VERSIONS:
        return ""
    lines = ["Версии MySQL (учитывай синтаксис именно этих версий):"]
    for c in enabled_clusters():
        v = DB_VERSIONS.get(c["name"])
        if v:
            lines.append(f"  {c['label']}: {v}")
    return "\n".join(lines) if len(lines) > 1 else ""
# ══════════════════════════════════════════════════════════════════════════════

def system_prompt() -> str:
    return f"""Ты — опытный DBA и SRE со специализацией на MySQL/InnoDB и репликации.
Ты обслуживаешь MySQL-кластеры (primary + replica) в разных городах.

Доступные кластеры:
{clusters_index_text()}

{db_versions_text()}

Правила:
1. Отвечай ТОЛЬКО на русском языке.
2. Структурируй ответ, давай конкретные команды MySQL/Linux.
3. Если есть исторические данные — ссылайся на конкретные значения и время пиков.
4. Если данных недостаточно — честно об этом говори.
5. Интерпретируй числа, а не пересказывай их.
6. Если приложен блок «Алерты за …» — это реальная история срабатываний
   за {ALERTS_RETENTION_DAYS} дн. Опирайся на неё: называй даты и время,
   ищи повторяющиеся и связанные инциденты. Блок с фразой «Ни одного алерта
   за этот период не было» означает именно это — не придумывай инциденты.

7. ОТСТАВАНИЕ РЕПЛИКИ. Многие реплики работают с ЗАПЛАНИРОВАННОЙ задержкой
   (MASTER_DELAY, часто 2 часа) — это защита от ошибочного DROP, а не авария.
   В метриках три величины:
     replication_lag_raw_s        — сырой Seconds_Behind_Master
     replication_planned_delay_s  — запланированная задержка (SQL_Delay)
     replication_lag_over_plan_s  — отставание СВЕРХ плана
   Судить о здоровье репликации можно ТОЛЬКО по replication_lag_over_plan_s.
   Пример: raw=7217, planned=7200, over_plan=17 — реплика отстаёт на 17 секунд,
   это НОРМА. Называть это проблемой, писать про «отставание более 2 часов»
   и предлагать чинить репликацию в такой ситуации — грубая ошибка.
   Проблема есть, только если over_plan заметно больше нуля и растёт, либо
   io/sql-поток не работает.

8. КОНСОЛИДИРОВАННЫЙ ОТВЕТ. В контексте есть метрики и СУБД, и сервера
   (CPU, iowait, память, диски, сеть). Не разбирай их порознь — связывай:
     - медленные запросы и рост latency при высоком iowait и загрузке дисков
       обычно упираются в диск, а не в сам MySQL;
     - рост отставания реплики при высоком CPU на реплике — часто однопоточный
       SQL-поток, а не сеть;
     - всплеск подключений при нехватке памяти — риск OOM;
     - если метрики сервера в норме, так и скажи: узкое место внутри СУБД.
   Структура ответа: (1) вывод одной фразой — есть проблема или нет;
   (2) что показывают метрики СУБД; (3) что показывают метрики сервера;
   (4) как они связаны; (5) что делать. Если проблемы нет — так и напиши
   в первой фразе и не выдумывай рекомендации на пустом месте.

9. ДЕТАЛЬНАЯ СТАТИСТИКА. Если приложен блок «Детальная статистика … шаг N» —
   это реальные значения по интервалам, а не агрегаты. Пользуйся им: называй
   конкретное время всплесков, показывай, что происходило с ресурсами ОС
   в ту же минуту, ищи совпадения между колонками (рост QPS при росте iowait,
   провал CPU при падении conn). Не отвечай «есть только min/avg/max», если
   такая таблица приложена. Если её нет, а спрашивают детализацию — скажи,
   что нужно уточнить период и шаг, например «за 3 часа с разбивкой по 5 минут».

10. SQL. Если приложен блок «Результат SQL» — это реальные строки из БД,
    опирайся на них. Версии MySQL указаны выше: предлагай синтаксис и имена
    таблиц именно для этих версий (у 5.7 и 8.0 разные performance_schema
    и разный SHOW). Агент умеет только ЧИТАТЬ: не предлагай ему выполнить
    INSERT/UPDATE/DELETE/ALTER — такие запросы отклоняются. Команды на
    изменение давай пользователю для ручного выполнения, отдельно и с
    предупреждением."""


def fmt_alerts(rows: list[dict], period: str, label: Optional[str] = None) -> str:
    scope = f" по кластеру {label}" if label else ""
    if not rows:
        return (f"## Алерты{scope} за {period}\n\n"
                f"  Ни одного алерта за этот период не было.")

    counts: dict[str, int] = {}
    for r in rows:
        counts[r["alert"]] = counts.get(r["alert"], 0) + 1

    lines = [f"## Алерты{scope} за {period} — записей: {len(rows)}", "",
             "Сводка: " + ", ".join(f"{k}: {v}" for k, v in
                                    sorted(counts.items(), key=lambda kv: -kv[1])),
             ""]
    for i, r in enumerate(rows):
        ts = (r.get("timestamp") or "")[:19].replace("T", " ")
        lines.append(f"  [{ts} UTC] {(r.get('severity') or '?'):8} "
                     f"{r.get('alert')} — {r.get('cluster_label') or '—'} / "
                     f"{r.get('instance') or '—'}")
        if r.get("summary"):
            lines.append(f"      {r['summary']}")
        # Разбор от LLM только для трёх последних: он длинный, а промпт не резиновый
        if i < 3 and r.get("analysis"):
            a = " ".join(r["analysis"].split())
            lines.append(f"      прошлый разбор: {a[:400]}"
                         f"{'…' if len(a) > 400 else ''}")
    return "\n".join(lines)


def fmt_current(m: dict) -> str:
    lines = [f"## Текущие метрики: {m['cluster_label']} ({m['cluster_name']})",
             "\n### Primary"]
    lines += [f"  {k}: {v}" for k, v in m["primary"].items()]
    if "replica" in m:
        lines.append("\n### Replica")
        lines += [f"  {k}: {v}" for k, v in m["replica"].items()]
    return "\n".join(lines)


def fmt_history(h: dict, label: str) -> str:
    lines = [f"## История кластера {label} за последние {h['period_hours']} ч. "
             f"(min / avg / max, время пиков в UTC)"]
    for k, v in h.items():
        if k == "period_hours":
            continue
        if v:
            lines.append(f"  {k}: min={v['min']} avg={v['avg']} max={v['max']} "
                         f"(пик в {v['max_time']}, минимум в {v['min_time']})")
        else:
            lines.append(f"  {k}: нет данных")
    return "\n".join(lines)


# ══════════════════════════════════════════════════════════════════════════════
#  ДЕТАЛЬНАЯ СТАТИСТИКА ПО ИНТЕРВАЛАМ
#  min/avg/max прячут форму нагрузки: по ним не видно, когда именно был всплеск
#  и совпал ли он с ростом iowait. Здесь отдаём ряд по шагам как таблицу.
#  Сами данные хранит Prometheus (retention из PROMETHEUS_RETENTION), мы их
#  только читаем и прореживаем до запрошенного шага.
# ══════════════════════════════════════════════════════════════════════════════

# Больше строк LLM всё равно не осмыслит, а контекст выест. При превышении
# шаг увеличивается автоматически, и об этом пишется в заголовке таблицы.
SERIES_MAX_ROWS = int(os.environ.get("SERIES_MAX_ROWS", "200"))

# Что показываем в детальной таблице: ресурсы ОС + основное по СУБД
SERIES_SPECS = [
    ("CPU%",     '100-(avg by(instance)(rate(node_cpu_seconds_total'
                 '{{mode="idle",instance="{node}"}}[{w}]))*100)'),
    ("iowait%",  'avg by(instance)(rate(node_cpu_seconds_total'
                 '{{mode="iowait",instance="{node}"}}[{w}]))*100'),
    ("MEM%",     '100*(1-(node_memory_MemAvailable_bytes{{instance="{node}"}}'
                 '/node_memory_MemTotal_bytes{{instance="{node}"}}))'),
    ("LA1",      'node_load1{{instance="{node}"}}'),
    ("diskR/s",  'sum(rate(node_disk_read_bytes_total{{instance="{node}"}}[{w}]))'),
    ("diskW/s",  'sum(rate(node_disk_written_bytes_total{{instance="{node}"}}[{w}]))'),
    ("netRX/s",  'sum(rate(node_network_receive_bytes_total'
                 '{{instance="{node}",device!~"lo|veth.*"}}[{w}]))'),
    ("QPS",      'rate(mysql_global_status_queries{{instance="{inst}"}}[{w}])'),
    ("slow/s",   'rate(mysql_global_status_slow_queries{{instance="{inst}"}}[{w}])'),
    ("conn",     'mysql_global_status_threads_connected{{instance="{inst}"}}'),
]


def parse_step_seconds(text: str) -> Optional[int]:
    """Шаг разбивки из фразы: «по 5 минут», «поминутно», «по часам»."""
    t = text.lower()
    m = re.search(r'(?:по|шаг[ом]*|интервал[ом]*|разбивк\w*\s+по)\s+(\d+)\s*'
                  r'(секунд|сек|минут|мин|час)', t)
    if m:
        n, unit = int(m.group(1)), m.group(2)
        if unit.startswith(("секунд", "сек")):
            return max(n, 15)
        if unit.startswith(("минут", "мин")):
            return n * 60
        return n * 3600
    if "поминутно" in t or "по минутам" in t:
        return 60
    if "по часам" in t or "почасов" in t:
        return 3600
    if "по секундам" in t:
        return 15
    return None


# Явная просьба показать графики. Без неё графики не строятся: десять картинок
# под каждым ответом про метрики — это шум, а не польза.
CHART_KEYWORDS = (
    "график", "графики", "графиком", "графиках", "диаграмм", "чарт",
    "нарисуй", "визуал", "покажи картин", "в картинках",
)

# Просьба выгрузить отчёт
EXPORT_KEYWORDS = (
    "pdf", "пдф", "выгруз", "экспорт", "отчёт", "отчет", "распечат", "печат",
)


def detect_chart_intent(text: str) -> bool:
    t = text.lower()
    return any(kw in t for kw in CHART_KEYWORDS)


def detect_export_intent(text: str) -> bool:
    t = text.lower()
    return any(kw in t for kw in EXPORT_KEYWORDS)


BREAKDOWN_KEYWORDS = (
    "разбивк", "детальн", "подробн", "по интервал", "по шагам", "поминутно",
    "по минутам", "по часам", "почасов", "по секундам", "таблиц",
    "по точкам", "сырые данные", "raw", "каждые",
    # Просьба «дай статистику» тоже означает подробные данные, а не агрегаты:
    # min/avg/max отвечают на вопрос «сколько», но не «когда и с чем совпало».
    "статистик", "метрик", "показател", "ресурс",
)


# SQL прямо в сообщении: «выполни SELECT ...» или запрос в блоке ```sql
SQL_IN_TEXT = re.compile(
    r"```(?:sql)?\s*(.+?)```|((?:select|show|explain|describe)\s+.+)",
    re.I | re.S)


def extract_sql(text: str) -> Optional[str]:
    """Вытащить запрос из сообщения, если пользователь его написал."""
    m = SQL_IN_TEXT.search(text)
    if not m:
        return None
    sql = (m.group(1) or m.group(2) or "").strip()
    # Отсекаем случайные совпадения вида «покажи show slave status» без смысла
    return sql if len(sql) > 10 else None


def detect_breakdown_intent(text: str) -> bool:
    t = text.lower()
    return any(kw in t for kw in BREAKDOWN_KEYWORDS) or parse_step_seconds(t) is not None


async def collect_series_table(cluster: dict, hours: float, step_s: int,
                               max_rows: Optional[int] = None,
                               host: Optional[str] = None,
                               role: str = "primary") -> dict:
    """Ряды всех показателей ОДНОГО СЕРВЕРА на общей сетке времени.

    host — адрес сервера; по умолчанию primary. У кластера с репликой серверов
    два, ресурсы у них разные, и сводить их в одну таблицу нельзя.

    max_rows — бюджет строк: когда таблиц несколько, общий лимит делится.
    """
    limit = max_rows or SERIES_MAX_ROWS
    ip    = host or cluster["primary_ip"]
    ctx   = {"inst": f"{ip}:9104", "node": f"{ip}:9100"}

    points = int(hours * 3600 / max(step_s, 15))
    if points > limit:
        step_s = int(hours * 3600 / limit)
        step_s = max(int((step_s + 59) // 60) * 60, 60)
        adjusted = True
    else:
        adjusted = False

    # Окно rate() не меньше минуты: на редкой сетке иначе считается по одной
    # точке и даёт пустоту
    w = f"{max(step_s, 60)}s"

    end   = datetime.datetime.utcnow()
    start = end - datetime.timedelta(hours=hours)

    async def one(client, expr):
        try:
            r = await client.get(
                f"{PROMETHEUS_URL}/api/v1/query_range",
                params={"query": expr, "start": start.isoformat() + "Z",
                        "end": end.isoformat() + "Z", "step": str(step_s)},
                timeout=30.0)
            d = r.json()
            if d.get("status") != "success" or not d["data"]["result"]:
                return {}
            return {int(float(v[0])): float(v[1])
                    for v in d["data"]["result"][0]["values"]}
        except Exception as e:
            logger.error(f"Ряд не получен: {e}")
            return {}

    async with httpx.AsyncClient() as client:
        series = await asyncio.gather(
            *[one(client, expr.format(w=w, **ctx)) for _, expr in SERIES_SPECS])

    names  = [n for n, _ in SERIES_SPECS]
    stamps = sorted({t for s in series for t in s})
    return {"step_s": step_s, "adjusted": adjusted, "hours": hours,
            "host": ip, "role": role,
            "names": names, "stamps": stamps, "series": series}


def cluster_hosts(cluster: dict) -> list:
    """[(адрес, роль)] всех серверов кластера — primary и, если есть, replica."""
    hosts = [(cluster["primary_ip"], "primary")]
    if cluster.get("replica_ip"):
        hosts.append((cluster["replica_ip"], "replica"))
    return hosts


async def collect_series_tables(cluster: dict, hours: float, step_s: int,
                                max_rows: Optional[int] = None) -> list:
    """Отдельная таблица на КАЖДЫЙ сервер кластера.

    Раньше отдавалась одна таблица по primary, и статистика реплики просто
    терялась — при вопросе про кластер с двумя серверами это неверно.
    """
    hosts  = cluster_hosts(cluster)
    budget = max((max_rows or SERIES_MAX_ROWS) // len(hosts), 40)
    return list(await asyncio.gather(
        *[collect_series_table(cluster, hours, step_s, budget, ip, role)
          for ip, role in hosts]))


def fmt_series_table(data: dict, label: str) -> str:
    names, stamps, series = data["names"], data["stamps"], data["series"]
    if not stamps:
        return (f"## Детальная статистика {label}\n\n"
                f"  За этот период данных нет.")

    step_min = data["step_s"] / 60
    step_txt = (f"{step_min:.0f} мин" if step_min >= 1
                else f"{data['step_s']} с")
    who = f"{label} · {data.get('role', 'primary')} {data.get('host', '')}"
    head = [f"## Детальная статистика {who}: шаг {step_txt}, "
            f"период {data['hours']:g} ч, точек {len(stamps)}"]
    if data["adjusted"]:
        head.append("  (шаг увеличен: запрошенный дал бы слишком длинную "
                    "таблицу для одного ответа)")
    head.append("  Время в UTC. Пустая ячейка — метрики за этот момент нет.")
    head.append("")

    def cell(v):
        if v is None:
            return "—"
        if abs(v) >= 1e6:
            return f"{v/1e6:.1f}M"
        if abs(v) >= 1e3:
            return f"{v/1e3:.1f}k"
        return f"{v:.1f}" if abs(v) < 100 else f"{v:.0f}"

    widths = [max(len(n), 8) for n in names]
    # ширина колонки времени та же, что у строк данных, иначе шапка едет
    head.append("  " + "время".ljust(12) +
                " ".join(n.rjust(w) for n, w in zip(names, widths)))
    rows = []
    for ts in stamps:
        t = datetime.datetime.utcfromtimestamp(ts).strftime("%d.%m %H:%M")
        rows.append("  " + t.ljust(12) +
                    " ".join(cell(s.get(ts)).rjust(w)
                             for s, w in zip(series, widths)))
    return "\n".join(head + rows)


async def build_chat_context(user_message: str) -> tuple[str, Optional[dict], float]:
    """Определить кластер и временное окно, собрать контекст метрик."""
    cluster = detect_cluster_in_text(user_message)
    hours   = detect_time_hours(user_message)
    blocks  = []

    # Обрезаем окно метрик, но не молча: если просили неделю, а отдаём сутки,
    # LLM должна об этом сказать, иначе ответ будет вводить в заблуждение.
    asked_hours = hours
    if hours > MAX_METRICS_HOURS:
        hours = MAX_METRICS_HOURS
        blocks.append(
            f"## Ограничение периода\n\n"
            f"  Запрошено {asked_hours:g} ч, метрики отданы за последние "
            f"{hours:g} ч — это максимум для одного разбора.\n"
            f"  Обязательно предупреди об этом в ответе.")

    if cluster:
        if hours > 0:
            hist = await collect_history(cluster, hours)
            blocks.append(fmt_history(hist, cluster["label"]))
            # Просили разбивку по интервалам — агрегатов недостаточно:
            # по min/avg/max не видно, когда был всплеск и с чем он совпал
            if detect_breakdown_intent(user_message):
                step = parse_step_seconds(user_message) or 300
                # по таблице на каждый сервер: у кластера с репликой их два,
                # и ресурсы у них разные
                for tb in await collect_series_tables(cluster, hours, step):
                    blocks.append(fmt_series_table(tb, cluster["label"]))
        current = await collect_current(cluster)
        blocks.append(fmt_current(current))

        # Пользователь написал SQL — выполняем и кладём результат рядом
        # с метриками. Валидатор пропустит только читающие конструкции.
        user_sql = extract_sql(user_message)
        if user_sql and cluster_db_creds(cluster):
            blocks.append(fmt_sql_result(sql_run(cluster, user_sql)))
    else:
        # Обзор всех
        clusters = enabled_clusters()
        results  = await asyncio.gather(*[collect_current(c) for c in clusters])
        lines = ["## Краткий статус всех кластеров\n"]
        for s in results:
            p   = s["primary"]
            lag = s.get("replica", {}).get("replication_lag_over_plan_s", "—")
            lines.append(
                f"  {s['cluster_label']:20} up={p.get('mysql_up','?')}  "
                f"QPS={p.get('qps','?')}  slow={p.get('slow_qps','?')}/s  "
                f"conn={p.get('connections_pct','?')}%  "
                f"CPU={p.get('cpu_pct','?')}%  лаг={lag}s")
        blocks.append("\n".join(lines))

        # Спросили про историю, но город не назвали — раньше в контекст
        # уходил только текущий статус, и агент отвечал, что данных нет.
        # Собираем историю по всем кластерам (их обычно единицы).
        if hours > 0 and clusters:
            hists = await asyncio.gather(
                *[collect_history(c, hours) for c in clusters])
            for c, h in zip(clusters, hists):
                if h:
                    blocks.append(fmt_history(h, c["label"]))

            # И детализацию тоже: раньше таблица строилась только когда
            # в вопросе назван город, а «по метрикам ОС» города не содержит
            if detect_breakdown_intent(user_message):
                step = parse_step_seconds(user_message) or 300
                # бюджет строк делим между кластерами, иначе контекст распухнет
                budget = max(SERIES_MAX_ROWS // max(len(clusters), 1), 40)
                grouped = await asyncio.gather(
                    *[collect_series_tables(c, hours, step, budget)
                      for c in clusters])
                for c, tables in zip(clusters, grouped):
                    for tb in tables:
                        blocks.append(fmt_series_table(tb, c["label"]))

    # Спросили про алерты/инциденты — подмешиваем историю из БД
    if detect_alert_intent(user_message):
        period = (f"последние {hours:g} ч."
                  if hours > 0 else f"последние {ALERTS_RETENTION_DAYS} дн.")
        rows = alerts_query(cluster=cluster["name"] if cluster else None,
                            hours=hours if hours > 0 else None,
                            limit=20)
        blocks.append(fmt_alerts(rows, period,
                                 cluster["label"] if cluster else None))

    return "\n\n".join(blocks), cluster, hours


async def llm_stream(messages: list[dict]) -> AsyncGenerator[str, None]:
    """Стриминг токенов из удалённой LLM (SSE)."""
    headers = {"Content-Type": "application/json", "Authorization": AUTH_HEADER}
    payload = {
        "model":       LLM_MODEL,
        "max_tokens":  LLM_MAX_TOKENS,
        "temperature": LLM_TEMPERATURE,
        "messages":    messages,
        "stream":      True,
    }
    try:
        async with httpx.AsyncClient() as client:
            async with client.stream(
                "POST", f"{LLM_BASE_URL}/chat/completions",
                headers=headers, json=payload, timeout=120.0,
            ) as resp:
                if resp.status_code != 200:
                    body = await resp.aread()
                    yield f"[Ошибка LLM: HTTP {resp.status_code}] {body.decode()[:200]}"
                    return
                async for line in resp.aiter_lines():
                    line = line.strip()
                    if not line or not line.startswith("data:"):
                        continue
                    data = line[5:].strip()
                    if data == "[DONE]":
                        return
                    try:
                        chunk = json.loads(data)
                        delta = chunk["choices"][0].get("delta", {})
                        token = delta.get("content", "")
                        if token:
                            yield token
                    except (json.JSONDecodeError, KeyError, IndexError):
                        continue
    except httpx.ConnectError:
        yield f"[Ошибка: не удалось подключиться к LLM {LLM_BASE_URL}]"
    except Exception as e:
        yield f"[Ошибка LLM: {e}]"


async def llm_complete(messages: list[dict]) -> str:
    """Обычный (нестриминговый) вызов — для вебхуков алертов."""
    headers = {"Content-Type": "application/json", "Authorization": AUTH_HEADER}
    payload = {"model": LLM_MODEL, "max_tokens": LLM_MAX_TOKENS,
               "temperature": LLM_TEMPERATURE, "messages": messages}
    try:
        async with httpx.AsyncClient() as client:
            r = await client.post(f"{LLM_BASE_URL}/chat/completions",
                                  headers=headers, json=payload, timeout=90.0)
            r.raise_for_status()
            return r.json()["choices"][0]["message"]["content"].strip()
    except httpx.HTTPStatusError as e:
        logger.error(f"LLM HTTP {e.response.status_code}")
        return f"[Ошибка LLM: HTTP {e.response.status_code}]"
    except Exception as e:
        logger.error(f"LLM error: {e}")
        return f"[Ошибка LLM: {e}]"


# ══════════════════════════════════════════════════════════════════════════════
#  WEBSOCKET ЧАТ
# ══════════════════════════════════════════════════════════════════════════════

# ══════════════════════════════════════════════════════════════════════════════
#  OIDC (Authorization Code Flow + PKCE)
#  Подпись ID-токена не проверяем: вместо этого личность берём с userinfo,
#  запрошенного по TLS напрямую у провайдера с полученным access-токеном.
#  Так не нужен JWKS/JWT-разбор, а доверие опирается на TLS к issuer.
# ══════════════════════════════════════════════════════════════════════════════

# state -> (code_verifier, срок годности). Поток живёт секунды, процесс один.
_oidc_states: dict[str, tuple[str, float]] = {}
_OIDC_STATE_TTL = 600


def _oidc_states_gc() -> None:
    now = time.time()
    for k in [k for k, (_, exp) in _oidc_states.items() if exp < now]:
        _oidc_states.pop(k, None)


async def oidc_discover() -> dict:
    """Метаданные провайдера. Кешируем — конфиг меняется редко."""
    global _OIDC_META
    if _OIDC_META:
        return _OIDC_META
    url = OIDC_ISSUER.rstrip("/") + "/.well-known/openid-configuration"
    async with httpx.AsyncClient(timeout=10, verify=OIDC_TLS_VERIFY) as client:
        r = await client.get(url)
        r.raise_for_status()
        _OIDC_META = r.json()
    return _OIDC_META


_OIDC_META: dict = {}


def _pkce_pair() -> tuple[str, str]:
    verifier  = secrets.token_urlsafe(64)[:96]
    digest    = hashlib.sha256(verifier.encode()).digest()
    challenge = base64.urlsafe_b64encode(digest).decode().rstrip("=")
    return verifier, challenge


async def oidc_exchange_code(code: str, verifier: str, redirect_uri: str) -> dict:
    meta = await oidc_discover()
    data = {
        "grant_type":    "authorization_code",
        "code":          code,
        "redirect_uri":  redirect_uri,
        "client_id":     OIDC_CLIENT_ID,
        "code_verifier": verifier,
    }
    if OIDC_CLIENT_SECRET:
        data["client_secret"] = OIDC_CLIENT_SECRET
    async with httpx.AsyncClient(timeout=15, verify=OIDC_TLS_VERIFY) as client:
        r = await client.post(meta["token_endpoint"], data=data)
        r.raise_for_status()
        return r.json()


async def oidc_userinfo(access_token: str) -> dict:
    meta = await oidc_discover()
    endpoint = meta.get("userinfo_endpoint")
    if not endpoint:
        raise RuntimeError("Провайдер не сообщил userinfo_endpoint")
    async with httpx.AsyncClient(timeout=15, verify=OIDC_TLS_VERIFY) as client:
        r = await client.get(endpoint,
                             headers={"Authorization": f"Bearer {access_token}"})
        r.raise_for_status()
        return r.json()


def oidc_redirect_uri(request: Request) -> str:
    """Явный OIDC_REDIRECT_URL надёжнее: за прокси схема и хост подменяются."""
    if OIDC_REDIRECT_URL:
        return OIDC_REDIRECT_URL
    prefix = (request.scope.get("root_path") or ROOT_PATH).rstrip("/")
    return str(request.base_url).rstrip("/") + prefix + "/auth/oidc/callback"


# ══════════════════════════════════════════════════════════════════════════════
#  ЗАЩИТА ЗАПРОСОВ
# ══════════════════════════════════════════════════════════════════════════════

# Открытые пути: страница входа, её API, статика и health для мониторинга
PUBLIC_PATHS = {"/login", "/api/login", "/api/logout", "/health",
                # без этих двух OIDC уйдёт в бесконечный редирект:
                # чтобы войти, до них надо дойти без сессии
                "/auth/oidc/login", "/auth/oidc/callback",
                # защищён своим токеном, cookie у Zabbix нет
                "/api/alerts/ingest"}


def _is_public(path: str) -> bool:
    return path in PUBLIC_PATHS or path.startswith("/static/")


@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    if not AUTH_ENABLED:
        return await call_next(request)

    path = request.url.path
    if _is_public(path):
        return await call_next(request)

    # Вебхук зовёт Alertmanager, который не умеет логиниться.
    # Пускаем только с локального адреса.
    if path == "/webhook":
        peer = request.client.host if request.client else ""
        if peer in ("127.0.0.1", "::1", "localhost"):
            return await call_next(request)
        logger.warning(f"Вебхук с внешнего адреса {peer} отклонён")
        return JSONResponse({"detail": "Forbidden"}, status_code=403)

    user = current_user(request)
    if not user:
        # Браузеру — редирект на форму, API-клиенту — честный 401
        denied = sso_denied(request)
        accept = request.headers.get("accept", "")
        if "text/html" in accept:
            prefix = (request.scope.get("root_path") or ROOT_PATH).rstrip("/")
            # denied=1 — чтобы форма объяснила, что дело не в пароле
            return RedirectResponse(f"{prefix}/login" + ("?denied=1" if denied else ""),
                                    status_code=302)
        return JSONResponse({"detail": ERR_NO_ACCESS if denied else "Требуется вход"},
                            status_code=403 if denied else 401)

    request.state.user = user
    return await call_next(request)


class LoginRequest(BaseModel):
    username: str
    password: str


@app.post("/api/login")
def api_login(req: LoginRequest, response: Response):
    if not AUTH_ENABLED:
        return {"ok": True, "username": "anonymous", "source": "disabled"}

    source, err = authenticate(req.username.strip(), req.password)
    if not source:
        logger.warning(f"Неудачный вход: {req.username!r} — {err}")
        # 403 для «доступ не выдан»: учётка верна, не хватает прав
        code = 403 if err == ERR_NO_ACCESS else 401
        raise HTTPException(status_code=code, detail=err)

    token = make_session(req.username.strip(), source)
    response.set_cookie(
        AUTH_COOKIE, token,
        max_age=int(AUTH_SESSION_TTL_HOURS * 3600),
        httponly=True,      # недоступен из JS — защита от XSS-кражи сессии
        samesite="lax",
        path="/",
    )
    logger.info(f"Вход: {req.username} (источник: {source})")
    return {"ok": True, "username": req.username.strip(), "source": source}


@app.post("/api/logout")
def api_logout(response: Response):
    response.delete_cookie(AUTH_COOKIE, path="/")
    return {"ok": True, "sso_logout_url": SSO_LOGOUT_URL or None}


@app.get("/api/me")
def api_me(request: Request):
    if not AUTH_ENABLED:
        return {"authenticated": True, "username": "anonymous", "source": "disabled"}
    user = current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Требуется вход")
    return {"authenticated": True, "is_admin": is_admin(user), **user}


# ── OIDC: вход и возврат от провайдера ───────────────────────────────────────

@app.get("/auth/oidc/login")
async def oidc_login(request: Request):
    if not (OIDC_ENABLED and OIDC_ISSUER and OIDC_CLIENT_ID):
        raise HTTPException(status_code=404, detail="OIDC не настроен")
    try:
        meta = await oidc_discover()
    except Exception as e:
        logger.error(f"OIDC discovery не удался: {e}")
        raise HTTPException(status_code=502, detail="Провайдер OIDC недоступен")

    _oidc_states_gc()
    verifier, challenge = _pkce_pair()
    state = secrets.token_urlsafe(32)
    _oidc_states[state] = (verifier, time.time() + _OIDC_STATE_TTL)

    params = {
        "response_type":         "code",
        "client_id":             OIDC_CLIENT_ID,
        "redirect_uri":          oidc_redirect_uri(request),
        "scope":                 OIDC_SCOPES,
        "state":                 state,
        "code_challenge":        challenge,
        "code_challenge_method": "S256",
    }
    return RedirectResponse(
        meta["authorization_endpoint"] + "?" + urllib.parse.urlencode(params),
        status_code=302)


@app.get("/auth/oidc/callback")
async def oidc_callback(request: Request, code: str = "", state: str = "",
                        error: str = ""):
    prefix = (request.scope.get("root_path") or ROOT_PATH).rstrip("/")

    def back(reason: str):
        return RedirectResponse(f"{prefix}/login?oidc_error=" +
                                urllib.parse.quote(reason), status_code=302)

    if error:
        return back(error)
    if not code or not state:
        return back("Провайдер не вернул код авторизации")

    _oidc_states_gc()
    entry = _oidc_states.pop(state, None)      # state одноразовый — защита от CSRF
    if not entry:
        return back("Cессия входа истекла, попробуйте ещё раз")
    verifier, _ = entry

    try:
        tokens = await oidc_exchange_code(code, verifier, oidc_redirect_uri(request))
        info   = await oidc_userinfo(tokens["access_token"])
    except Exception as e:
        logger.error(f"OIDC: обмен кода не удался: {e}")
        return back("Не удалось получить данные пользователя")

    raw_name = str(info.get(OIDC_USERNAME_CLAIM) or info.get("email") or "").strip()
    if not raw_name:
        logger.error(f"OIDC: в userinfo нет поля {OIDC_USERNAME_CLAIM}")
        return back("Провайдер не сообщил имя пользователя")

    username = norm_username(raw_name)
    if not user_allowed(username):
        logger.warning(f"OIDC-вход {username}: доступ не выдан")
        return RedirectResponse(f"{prefix}/login?denied=1", status_code=302)

    token = make_session(username, "oidc")
    resp  = RedirectResponse(f"{prefix}/" if prefix else "/", status_code=302)
    resp.set_cookie(AUTH_COOKIE, token,
                    max_age=int(AUTH_SESSION_TTL_HOURS * 3600),
                    httponly=True, samesite="lax", path="/")
    logger.info(f"Вход: {username} (источник: oidc)")
    return resp


# ── Управление доступами (только для админов) ────────────────────────────────

def require_admin(request: Request) -> dict:
    if not AUTH_ENABLED:
        return {"username": "anonymous", "source": "disabled"}
    user = current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Требуется вход")
    if not is_admin(user):
        raise HTTPException(status_code=403, detail="Требуются права администратора")
    return user


class GrantRequest(BaseModel):
    username: str
    display_name: str = ""
    email: str = ""
    role: str = "user"


@app.get("/api/users")
def api_users(request: Request):
    require_admin(request)
    return {"items": users_list(),
            "ldap_search": bool(LDAP_ENABLED and LDAP_SEARCH_USER)}


@app.post("/api/users")
def api_users_grant(req: GrantRequest, request: Request):
    admin = require_admin(request)
    if not user_grant(req.username, req.display_name, req.email,
                      req.role, admin.get("username", "")):
        raise HTTPException(status_code=400, detail="Не удалось выдать доступ")
    return {"ok": True, "username": norm_username(req.username)}


@app.delete("/api/users/{username}")
def api_users_revoke(username: str, request: Request, hard: bool = False):
    admin = require_admin(request)
    ok = user_delete(username) if hard else user_revoke(username,
                                                        admin.get("username", ""))
    if not ok:
        raise HTTPException(status_code=404, detail="Пользователь не найден")
    return {"ok": True, "username": norm_username(username), "hard": hard}


@app.get("/api/directory/search")
def api_directory_search(request: Request, q: str = "", limit: int = 25):
    """Поиск в AD, чтобы выдавать доступ выбором из списка, а не вводом руками."""
    require_admin(request)
    found   = ldap_search_users(q, min(limit, 100))
    granted = {u["username"] for u in users_list() if u["enabled"]}
    for f in found:
        f["already_granted"] = f["username"] in granted
    return {"items": found, "query": q}


@app.get("/report", response_class=HTMLResponse)
def report_page(request: Request):
    """Печатная версия отчёта. PDF делает браузер (Ctrl+P → Сохранить как PDF):
    так не нужны ни серверный рендер, ни новые pip-зависимости."""
    path = Path(WEB_DIR) / "report.html"
    if not path.exists():
        return HTMLResponse("<h1>report.html не найден</h1>", status_code=500)
    prefix = (request.scope.get("root_path") or ROOT_PATH).rstrip("/")
    html = path.read_text(encoding="utf-8")
    html = html.replace('<base href="/">', f'<base href="{prefix}/">', 1)
    return HTMLResponse(html)


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    path = Path(WEB_DIR) / "login.html"
    if not path.exists():
        return HTMLResponse("<h1>login.html не найден</h1>", status_code=500)
    prefix = (request.scope.get("root_path") or ROOT_PATH).rstrip("/")
    html = path.read_text(encoding="utf-8")
    html = html.replace('<base href="/">', f'<base href="{prefix}/">', 1)
    # Подсказка на форме: если включён только SSO, пароль вводить незачем
    html = html.replace("{{SSO_ONLY}}", "true" if (SSO_ENABLED and not
                        (LDAP_ENABLED or AUTH_ADMIN_PASSWORD_HASH)) else "false")
    html = html.replace("{{OIDC_ENABLED}}",
                        "true" if (OIDC_ENABLED and OIDC_ISSUER and OIDC_CLIENT_ID)
                        else "false")
    html = html.replace("{{OIDC_BUTTON_TEXT}}", OIDC_BUTTON_TEXT)
    return HTMLResponse(html)


@app.websocket("/ws")
async def websocket_chat(ws: WebSocket):
    """
    Протокол:
      Клиент → {"type": "message", "text": "...", "session_id": "...",
                "client_id": "...", "fingerprint": "..."}
      Сервер → {"type": "context",  "cluster": "...", "hours": N}   — что определил агент
      Сервер → {"type": "token",    "text": "..."}                  — стриминг токенов
      Сервер → {"type": "done"}                                     — конец ответа
      Сервер → {"type": "error",    "text": "..."}
      Клиент → {"type": "ping"} / Сервер → {"type": "pong"}
      Клиент → {"type": "stop"}  — прервать генерацию текущего ответа
    """
    await ws.accept()

    # HTTP-middleware на WebSocket не распространяется — проверяем отдельно.
    # У WebSocket те же .cookies/.headers/.client, поэтому current_user подходит.
    ws_user = None
    if AUTH_ENABLED:
        ws_user = current_user(ws)
        if not ws_user:
            await ws.send_json({"type": "error",
                                "text": "Сессия истекла — обновите страницу и войдите."})
            await ws.close(code=4401)
            return

    ws_clients.add(ws)
    session_id = f"ws-{id(ws)}"
    logger.info(f"WS connected: {session_id}"
                + (f" user={ws_user['username']}" if ws_user else ""))

    # Пока идёт стриминг, основной цикл занят и receive_text() не вызывается —
    # значит «стоп» никто бы не услышал. Поэтому чтение вынесено в отдельную
    # задачу: она разбирает служебные сообщения сразу, а вопросы кладёт в очередь.
    inbox: asyncio.Queue = asyncio.Queue()
    stop_event = asyncio.Event()

    async def reader():
        while True:
            raw = await ws.receive_text()
            try:
                m = json.loads(raw)
            except json.JSONDecodeError:
                await ws.send_json({"type": "error", "text": "Невалидный JSON"})
                continue
            kind = m.get("type")
            if kind == "ping":
                await ws.send_json({"type": "pong"})
            elif kind == "stop":
                stop_event.set()
            elif kind == "message":
                await inbox.put(m)

    reader_task = asyncio.create_task(reader())

    try:
        while True:
            msg = await inbox.get()
            stop_event.clear()

            text = msg.get("text", "").strip()
            sid  = msg.get("session_id", session_id)
            if not text:
                continue

            # Пользователь опознаётся по client_id из localStorage браузера.
            # Если его нет (старый клиент) — работаем как раньше, по session_id.
            cid = str(msg.get("client_id") or "").strip()[:128]
            fp  = str(msg.get("fingerprint") or "").strip()[:128]
            key = cid or sid

            history = ws_sessions.get(key)
            if history is None:
                # первое сообщение в этом процессе — поднимаем историю из БД
                history = chat_restore(cid) if cid else []
                ws_sessions[key] = history

            # 1. Собрать контекст (метрики) — сообщаем клиенту что нашли
            try:
                context_text, cluster, hours = await build_chat_context(text)
            except Exception as e:
                logger.error(f"Context error: {e}")
                await ws.send_json({"type": "error",
                                    "text": f"Ошибка сбора метрик: {e}"})
                continue

            await ws.send_json({
                "type":    "context",
                "cluster": cluster["label"] if cluster else None,
                "hours":   hours if hours > 0 else None,
            })

            # Графики строим ТОЛЬКО если их попросили. Иначе шлём лёгкое
            # предложение без данных: строка со ссылками под ответом, десять
            # запросов в Prometheus зря не делаем.
            if cluster and hours > 0:
                want_charts = detect_chart_intent(text)
                want_export = detect_export_intent(text)
                try:
                    charts = (await build_charts(cluster, hours)
                              if want_charts else [])
                    await ws.send_json({
                        "type":          "charts",
                        "mode":          "inline" if want_charts else "offer",
                        "highlight_pdf": want_export,
                        "cluster":       cluster["name"],
                        "cluster_label": cluster["label"],
                        "hours":         hours,
                        "charts":        charts,
                    })
                except Exception as e:
                    logger.error(f"Не удалось собрать графики: {e}")

            # 2. Собрать messages
            messages = [{"role": "system", "content": system_prompt()}]
            # Выжимка вытесненной части + последние реплики дословно
            messages += history_to_messages(history[-CHAT_CONTEXT_MESSAGES:])
            messages.append({
                "role": "user",
                "content": f"{context_text}\n\n## Вопрос\n\n{text}",
            })

            # 3. Стримить ответ
            full_answer = []
            stopped = False
            async for token in llm_stream(messages):
                if stop_event.is_set():
                    stopped = True
                    break
                full_answer.append(token)
                await ws.send_json({"type": "token", "text": token})

            answer = "".join(full_answer)
            if stopped:
                # Прерванный ответ всё равно сохраняем: пользователь его видел,
                # и в следующем вопросе на него может ссылаться.
                answer += "\n\n[генерация остановлена]"
                await ws.send_json({"type": "token",
                                    "text": "\n\n[остановлено]"})
                logger.info(f"Генерация остановлена пользователем: {sid}")
            await ws.send_json({"type": "done", "stopped": stopped})

            # 4. Сохранить историю (без огромного контекста метрик)
            history.append({"role": "user",      "content": text})
            history.append({"role": "assistant", "content": answer})
            chat_save(cid, sid, "user",      text,   fp)
            chat_save(cid, sid, "assistant", answer, fp)
            # Упёрлись в окно контекста — не выбрасываем старое, а сжимаем
            if len(history) > CHAT_CONTEXT_MESSAGES:
                history[:] = await chat_compact(cid, sid, history)

    except WebSocketDisconnect:
        logger.info(f"WS disconnected: {session_id}")
        ws_sessions.pop(session_id, None)
    except Exception as e:
        logger.error(f"WS error: {e}")
        try:
            await ws.close()
        except Exception:
            pass
    finally:
        ws_clients.discard(ws)
        # Без этого задача-читатель переживёт соединение и повиснет
        reader_task.cancel()
        try:
            await reader_task
        except (asyncio.CancelledError, Exception):
            pass


# ══════════════════════════════════════════════════════════════════════════════
#  ALERTMANAGER WEBHOOK
# ══════════════════════════════════════════════════════════════════════════════

@app.post("/webhook")
async def webhook(request: Request):
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(400, "Invalid JSON")

    processed = 0
    for alert in body.get("alerts", []):
        if alert.get("status") != "firing":
            continue

        labels   = alert.get("labels", {})
        name     = labels.get("alertname", "Unknown")
        instance = labels.get("instance", "")
        severity = labels.get("severity", "unknown")
        summary  = alert.get("annotations", {}).get("summary", "")

        cluster = (find_cluster(labels.get("cluster", ""))
                   or find_cluster_by_ip(instance.split(":")[0]))
        cluster_label = cluster["label"] if cluster else instance

        logger.info(f"[ALERT] {name} | {cluster_label} | {severity}")

        blocks = []
        if cluster:
            current = await collect_current(cluster)
            blocks.append(fmt_current(current))
            hist = await collect_history(cluster, 2)
            blocks.append(fmt_history(hist, cluster_label))
        ctx = "\n\n".join(blocks) if blocks else "Метрики недоступны."

        prompt = f"""## Алерт

**Кластер:** {cluster_label}
**Алерт:** {name}  (severity: {severity})
**Инстанс:** {instance}
**Описание:** {summary}

{ctx}

## Задача
1. Причина срабатывания (1-2 предложения).
2. Реальное влияние прямо сейчас.
3. 2-4 вероятных источника.
4. Немедленные команды для диагностики.
5. Шаги устранения.
6. Нужен ли срочный вызов DBA — да/нет."""

        analysis = await llm_complete([
            {"role": "system", "content": system_prompt()},
            {"role": "user",   "content": prompt},
        ])

        alerts_save({
            "timestamp":     datetime.datetime.utcnow().isoformat(),
            "alert":         name,
            "cluster":       cluster["name"] if cluster else None,
            "cluster_label": cluster_label,
            "instance":      instance,
            "severity":      severity,
            "summary":       summary,
            "analysis":      analysis,
        })
        processed += 1

    return {"processed": processed}


# ══════════════════════════════════════════════════════════════════════════════
#  REST API
# ══════════════════════════════════════════════════════════════════════════════

class ChatRequest(BaseModel):
    message: str
    session_id: Optional[str] = "rest"


@app.post("/chat")
async def rest_chat(req: ChatRequest):
    """REST-версия чата (без стриминга) — для curl и интеграций."""
    context_text, cluster, hours = await build_chat_context(req.message)
    history = ws_sessions.setdefault(req.session_id, [])

    messages = [{"role": "system", "content": system_prompt()}]
    for m in history[-6:]:
        messages.append(m)
    messages.append({"role": "user",
                     "content": f"{context_text}\n\n## Вопрос\n\n{req.message}"})

    answer = await llm_complete(messages)

    history.append({"role": "user",      "content": req.message})
    history.append({"role": "assistant", "content": answer})
    if len(history) > 16:
        history[:] = history[-16:]

    return {
        "answer":        answer,
        "cluster":       cluster["name"]  if cluster else None,
        "cluster_label": cluster["label"] if cluster else None,
        "hours":         hours if hours > 0 else None,
    }


@app.get("/chat")
async def rest_chat_get(message: str, session_id: str = "rest"):
    return await rest_chat(ChatRequest(message=message, session_id=session_id))


@app.get("/clusters")
def api_clusters():
    # Не отдаём пароли наружу
    safe = []
    for c in enabled_clusters():
        c2 = {k: v for k, v in c.items() if k != "mysql_exporter_password"}
        safe.append(c2)
    return {"clusters": safe}


@app.get("/clusters/{name}/status")
async def api_cluster_status(name: str):
    cluster = find_cluster(name)
    if not cluster:
        raise HTTPException(404, f"Кластер '{name}' не найден")
    return await collect_current(cluster)


@app.get("/clusters/{name}/history")
async def api_cluster_history(name: str, hours: float = 24):
    cluster = find_cluster(name)
    if not cluster:
        raise HTTPException(404, f"Кластер '{name}' не найден")
    return await collect_history(cluster, hours)


@app.get("/status")
async def api_all_status():
    clusters = enabled_clusters()
    results  = await asyncio.gather(*[collect_current(c) for c in clusters])
    return {"clusters": results}



@app.get("/chat/history")
def api_chat_history(client_id: str = "", limit: int = 50):
    """История чата конкретного браузера (client_id из localStorage)."""
    if not client_id:
        raise HTTPException(status_code=400, detail="client_id обязателен")
    items = chat_load(client_id, limit)
    return {"client_id": client_id, "total": len(items), "items": items,
            "retention_days": CHATS_RETENTION_DAYS, "persistent": CHATS_DB_OK}


@app.delete("/chat/history")
def api_chat_history_clear(client_id: str = ""):
    """Забыть историю этого браузера."""
    if not client_id:
        raise HTTPException(status_code=400, detail="client_id обязателен")
    removed = chat_clear(client_id)
    ws_sessions.pop(client_id, None)
    return {"client_id": client_id, "removed": removed}



# ── Приём алертов из внешних систем ──────────────────────────────────────────

class IngestAlert(BaseModel):
    alert:       str                      # имя/тип события
    summary:     str = ""                 # краткое описание
    severity:    str = "warning"          # critical | warning | info
    cluster:     str = ""                 # имя из clusters.json, если применимо
    instance:    str = ""                 # хост:порт или просто хост
    description: str = ""                 # подробности от внешней системы
    source:      str = "api"              # zabbix, nagios, custom…


def check_ingest_token(request: Request) -> bool:
    """Токен из Authorization: Bearer или X-API-Key."""
    if not INGEST_TOKENS:
        return False
    supplied = (request.headers.get("x-api-key") or "").strip()
    if not supplied:
        auth = (request.headers.get("authorization") or "").strip()
        if auth.lower().startswith("bearer "):
            supplied = auth[7:].strip()
    if not supplied:
        return False
    # постоянное время сравнения — токен не подобрать по таймингу
    return any(hmac.compare_digest(supplied, t) for t in INGEST_TOKENS)


@app.post("/api/alerts/ingest")
async def api_alert_ingest(payload: IngestAlert, request: Request):
    """Зарегистрировать алерт из внешней системы и разобрать его через LLM.

    Пример для Zabbix (действие → webhook):
      curl -X POST https://host/ai-agent/api/alerts/ingest \
           -H 'X-API-Key: <token>' -H 'Content-Type: application/json' \
           -d '{"alert":"Free disk space is low","severity":"critical",
                "cluster":"kemerovo","instance":"10.1.0.1",
                "summary":"/var 8% free","source":"zabbix"}'
    """
    if not INGEST_TOKENS:
        raise HTTPException(status_code=503,
                            detail="Приём алертов выключен: не задан INGEST_TOKENS")
    if not check_ingest_token(request):
        peer = request.client.host if request.client else "?"
        logger.warning(f"Приём алерта отклонён: неверный токен (с {peer})")
        raise HTTPException(status_code=401, detail="Неверный токен")

    name     = payload.alert.strip() or "ExternalAlert"
    severity = payload.severity.strip().lower() or "warning"
    if severity not in ("critical", "warning", "info"):
        severity = "warning"

    cluster       = find_cluster(payload.cluster) if payload.cluster else None
    cluster_label = cluster["label"] if cluster else (payload.cluster or "—")
    summary       = payload.summary.strip() or name

    # Тот же разбор, что и для алертов Alertmanager: если кластер известен,
    # подкладываем его метрики и историю, иначе разбираем по тексту события.
    blocks = [f"## Событие из внешней системы ({payload.source})",
              f"  Имя:        {name}",
              f"  Важность:   {severity}",
              f"  Объект:     {payload.instance or '—'}",
              f"  Кластер:    {cluster_label}",
              f"  Описание:   {summary}"]
    if payload.description.strip():
        blocks.append(f"  Подробности: {payload.description.strip()}")

    if cluster:
        try:
            current = await collect_current(cluster)
            blocks.append(fmt_current(current))
            hist = await collect_history(cluster, 2)
            blocks.append(fmt_history(hist, cluster["label"]))
        except Exception as e:
            logger.error(f"Не удалось собрать метрики для внешнего алерта: {e}")
    else:
        blocks.append("  (кластер не сопоставлен — метрик из Prometheus нет, "
                      "разбирай по описанию события)")

    prompt = "\n".join(blocks) + """

## Задача
1. Причина срабатывания (1-2 предложения).
2. Реальное влияние прямо сейчас.
3. 2-4 вероятных источника.
4. Немедленные команды для диагностики.
5. Шаги устранения.
6. Нужен ли срочный вызов DBA — да/нет."""

    try:
        analysis = await llm_complete([
            {"role": "system", "content": system_prompt()},
            {"role": "user",   "content": prompt},
        ])
    except Exception as e:
        logger.error(f"LLM не разобрала внешний алерт: {e}")
        analysis = f"Разбор не выполнен: LLM недоступна ({e})"

    alerts_save({
        "timestamp":     datetime.datetime.utcnow().isoformat(),
        "alert":         name,
        "cluster":       cluster["name"] if cluster else None,
        "cluster_label": cluster_label,
        "instance":      payload.instance or "—",
        "severity":      severity,
        "summary":       summary,
        "analysis":      analysis,
        "source":        payload.source.strip().lower() or "api",
    })
    logger.info(f"Принят алерт из {payload.source}: {name} ({severity})")
    return {"ok": True, "alert": name, "severity": severity,
            "cluster": cluster["name"] if cluster else None,
            "source": payload.source, "analyzed": not analysis.startswith("Разбор не выполнен")}

@app.delete("/api/alerts/{alert_id}")
def api_alert_delete(alert_id: int, request: Request):
    """Удалить одну запись истории алертов. Только для администраторов."""
    require_admin(request)
    if not alerts_delete(alert_id):
        raise HTTPException(status_code=404, detail="Запись не найдена")
    return {"ok": True, "id": alert_id}


@app.delete("/api/alerts")
def api_alerts_delete_by_name(request: Request, name: str = ""):
    """Удалить все записи одного типа — например, пачку ложных
    ReplicationLagCritical, нагенерированных ошибочным правилом."""
    require_admin(request)
    if not name:
        raise HTTPException(status_code=400, detail="Укажите параметр name")
    removed = alerts_delete_by_name(name)
    return {"ok": True, "alert": name, "removed": removed}




class SqlRequest(BaseModel):
    cluster: str
    sql:     str
    host:    str = ""      # пусто = primary


@app.post("/api/query")
def api_query(req: SqlRequest, request: Request):
    """Читающий SQL-запрос к кластеру. Только для администраторов."""
    require_admin(request)
    cluster = find_cluster(req.cluster)
    if not cluster:
        raise HTTPException(status_code=404, detail="Кластер не найден")
    res = sql_run(cluster, req.sql, req.host or None)
    if res.get("error"):
        raise HTTPException(status_code=400, detail=res["error"])
    return res


@app.get("/api/db/versions")
def api_db_versions(request: Request):
    """Версии MySQL, полученные на старте."""
    return {"versions": DB_VERSIONS,
            "clusters_without_creds": [
                c["name"] for c in enabled_clusters() if not cluster_db_creds(c)]}

@app.get("/api/series/{name}")
async def api_series(name: str, hours: float = 6, step: int = 300,
                     format: str = "json"):
    """Детальная статистика по интервалам: ресурсы ОС + основное по СУБД.

    step — шаг в секундах (300 = 5 минут). Если точек получается больше
    SERIES_MAX_ROWS, шаг увеличивается автоматически — это видно в ответе.
    format=csv отдаёт таблицу для выгрузки в Excel.
    """
    cluster = find_cluster(name)
    if not cluster:
        raise HTTPException(status_code=404, detail="Кластер не найден")

    tables = await collect_series_tables(cluster, max(hours, 0.1), max(step, 15))

    if format == "csv":
        # колонка server: в одном файле данные обоих серверов кластера
        rows = ["server,role,time," + ",".join(tables[0]["names"])]
        for data in tables:
            for ts in data["stamps"]:
                t = datetime.datetime.utcfromtimestamp(ts).isoformat() + "Z"
                rows.append(f'{data["host"]},{data["role"]},{t},' + ",".join(
                    ("" if s.get(ts) is None else f"{s[ts]:.3f}")
                    for s in data["series"]))
        return PlainTextResponse(
            "\n".join(rows), media_type="text/csv; charset=utf-8",
            headers={"Content-Disposition":
                     f'attachment; filename="{cluster["name"]}-series.csv"'})

    return {
        "cluster":       cluster["name"],
        "cluster_label": cluster["label"],
        "hours":         tables[0]["hours"],
        "step_seconds":  tables[0]["step_s"],
        "step_adjusted": tables[0]["adjusted"],
        "columns":       ["time"] + tables[0]["names"],
        # по блоку на каждый сервер кластера
        "servers": [
            {
                "host": d["host"],
                "role": d["role"],
                "rows": [
                    [datetime.datetime.utcfromtimestamp(ts).isoformat() + "Z"] +
                    [s.get(ts) for s in d["series"]]
                    for ts in d["stamps"]
                ],
            }
            for d in tables
        ],
    }

@app.get("/api/charts/{name}")
async def api_charts(name: str, hours: float = 6, keys: str = ""):
    """Ряды для графиков по кластеру. keys — список ключей через запятую."""
    cluster = find_cluster(name)
    if not cluster:
        raise HTTPException(status_code=404, detail="Кластер не найден")
    wanted = [k.strip() for k in keys.split(",") if k.strip()] or None
    charts = await build_charts(cluster, max(hours, 0.25), wanted)
    return {"cluster": cluster["name"], "cluster_label": cluster["label"],
            "hours": hours, "charts": charts}

@app.get("/alerts/history")
def api_alerts(limit: int = 30):
    total, items = alerts_load(limit)
    return {"total": total, "items": items,
            "retention_days": ALERTS_RETENTION_DAYS,
            "persistent": ALERTS_DB_OK}


@app.get("/health")
def health():
    return {
        "status":    "ok",
        "timestamp": datetime.datetime.utcnow().isoformat(),
        "clusters":  len(enabled_clusters()),
        "llm_model": LLM_MODEL,
    }


@app.get("/config")
def config_info():
    return {
        "llm_base_url":    LLM_BASE_URL,
        "llm_model":       LLM_MODEL,
        "auth_header_set": "your-token" not in AUTH_HEADER,
        "prometheus_url":  PROMETHEUS_URL,
        "registry_path":   REGISTRY_PATH,
        "clusters":        len(enabled_clusters()),
    }


# ══════════════════════════════════════════════════════════════════════════════
#  СТАТИКА (веб-интерфейс)
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    index_path = Path(WEB_DIR) / "index.html"
    if not index_path.exists():
        return HTMLResponse("<h1>MySQL AI Agent</h1><p>web/index.html не найден</p>")

    # Все ссылки страницы относительные, поэтому базовый адрес подставляется
    # здесь: под nginx на подпути это "/ai-agent/", в корне — "/".
    prefix = (request.scope.get("root_path") or ROOT_PATH).rstrip("/")
    html = index_path.read_text(encoding="utf-8")
    html = html.replace('<base href="/">', f'<base href="{prefix}/">', 1)
    return HTMLResponse(html)


if Path(WEB_DIR).exists():
    app.mount("/static", StaticFiles(directory=WEB_DIR), name="static")


@app.on_event("shutdown")
async def on_shutdown():
    """Разорвать сокеты, чтобы uvicorn не ждал клиентов при остановке."""
    for ws in list(ws_clients):
        try:
            await ws.close(code=1001)   # 1001 = сервер уходит
        except Exception:
            pass
    ws_clients.clear()
    logger.info("Соединения закрыты, агент останавливается")


if __name__ == "__main__":
    import uvicorn
    logger.info(f"MySQL AI Agent v3 | :{AGENT_PORT} | LLM={LLM_BASE_URL} model={LLM_MODEL}")
    # Версии БД спрашиваем ДО старта: без них LLM советует синтаксис наугад
    try:
        refresh_db_versions()
    except Exception as e:
        logger.error(f"Версии БД не получены: {e}")
    # timeout_graceful_shutdown обязателен: по умолчанию uvicorn ждёт
    # закрытия соединений без ограничения времени
    uvicorn.run(app, host="0.0.0.0", port=AGENT_PORT, log_level="info",
                timeout_graceful_shutdown=5)
