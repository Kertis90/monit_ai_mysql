#!/usr/bin/env python3
"""
Проверки агента: слой данных, совместимость со старой базой и приложение
целиком.

Ни Prometheus, ни LLM, ни каталог не нужны — база берётся временная, а
внешние вызовы либо не делаются, либо их отказ считается штатным. Поэтому
запускать можно где угодно:

    python3 tests/test_agent.py
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import secrets
import sqlite3
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

FAILED: list[str] = []


def check(label: str, got, expected=None, show=None) -> None:
    ok = (got == expected) if expected is not None else bool(got)
    mark = "ок " if ok else "СБОЙ"
    print("  [%s] %-42s %s" % (mark, label, show if show is not None else got))
    if not ok:
        FAILED.append(label)


def test_registry() -> str:
    """Реестр без учёток БД.

    С боевым агент на старте пошёл бы спрашивать версию MySQL по реальным
    адресам и ждал бы сетевых таймаутов. Проверки должны идти где угодно и
    ни к чему снаружи не обращаться.
    """
    path = os.path.join(tempfile.gettempdir(), "clusters_test.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"clusters": [{"name": "kemerovo", "label": "Кемерово",
                                 "primary_ip": "10.1.0.1",
                                 "replica_ip": "10.1.0.2",
                                 "enabled": True, "tags": []}]}, f,
                  ensure_ascii=False)
    return path


def tmp_db(name: str) -> str:
    path = os.path.join(tempfile.gettempdir(), name)
    if os.path.exists(path):
        os.remove(path)
    return path


# ── 1. Слой данных ───────────────────────────────────────────────────────────

async def data_layer() -> None:
    from agent.db.base import dispose, init_models, session_scope
    from agent.db.repositories.alerts import AlertRepository
    from agent.db.repositories.chats import ChatRepository, FeedbackRepository
    from agent.db.repositories.users import UserRepository, normalize

    await init_models()

    async with session_scope() as s:
        alerts = AlertRepository(s)
        await alerts.add(alert="MySQLDown", cluster="kemerovo",
                         instance="10.1.0.1:9104", severity="critical",
                         summary="БД недоступна", analysis="Разбор")
        check("повтор того же события отсекается",
              await alerts.is_duplicate(alert="MySQLDown", cluster="kemerovo",
                                        instance="10.1.0.1:9104"), True)
        check("событие другого кластера не дубль",
              await alerts.is_duplicate(alert="MySQLDown", cluster="novosibirsk",
                                        instance="10.2.0.1:9104"), False)

    async with session_scope() as s:
        alerts = AlertRepository(s)
        rows = await alerts.recent(hours=1)
        check("свежие события читаются", len(rows), 1)
        await alerts.resolve(rows[0].id, "Перезапустили mysqld", "admin")

    async with session_scope() as s:
        past = await AlertRepository(s).similar("MySQLDown", "kemerovo")
        check("память инцидентов помнит решение",
              past[0].resolution if past else "", "Перезапустили mysqld")

    async with session_scope() as s:
        users = UserRepository(s)
        await users.grant("MSK" + chr(92) + "IvKop", display_name="Иванов И.",
                          role="user", granted_by="admin")
        check("логин из DOMAIN\\user нормализован",
              normalize("MSK" + chr(92) + "IvKop"), "ivkop")
        check("вход по нему разрешён", await users.allowed("ivkop@mts.ru"), True)
        await users.grant("ivkop", role="admin", granted_by="admin")
        check("повторная выдача меняет роль", await users.is_admin("IVKOP"), True)
        await users.revoke("ivkop", "admin")
        check("после отзыва вход закрыт", await users.allowed("ivkop"), False)
        check("запись осталась в списке", len(await users.list()), 1)

    async with session_scope() as s:
        chats = ChatRepository(s)
        for i in range(15):
            await chats.add(client_id="web-1", role="user", content="вопрос %d" % i)
        await chats.add(client_id="web-2", role="user", content="чужой вопрос")
        hist = await chats.history("web-1", limit=5)
        check("история чужого клиента не видна",
              all("чужой" not in m.content for m in hist), True)
        check("порядок хронологический",
              hist[0].content < hist[-1].content, True)
        await FeedbackRepository(s).add(rating=-1, question="что с базой")
        check("оценка сохранена",
              (await FeedbackRepository(s).stats(30))["negative"], 1)

    await dispose()


# ── 2. Существующая база подхватывается без переноса данных ──────────────────

OLD_SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, alert TEXT,
    cluster TEXT, cluster_label TEXT, instance TEXT, severity TEXT,
    summary TEXT, analysis TEXT, source TEXT, resolution TEXT,
    resolved_by TEXT, resolved_at TEXT);
CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY, display_name TEXT, email TEXT,
    role TEXT NOT NULL DEFAULT 'user', enabled INTEGER NOT NULL DEFAULT 1,
    granted_by TEXT, granted_at TEXT);
CREATE TABLE IF NOT EXISTS feedback (
    id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, client_id TEXT,
    username TEXT, rating INTEGER NOT NULL, question TEXT, answer TEXT,
    comment TEXT);
CREATE TABLE IF NOT EXISTS chat_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT, client_id TEXT NOT NULL,
    session_id TEXT, ts TEXT NOT NULL, role TEXT NOT NULL,
    content TEXT NOT NULL, fingerprint TEXT);
"""


async def old_database(path: str) -> None:
    from agent.db.base import dispose, init_models, session_scope
    from agent.db.models import to_iso
    from agent.db.repositories.alerts import AlertRepository
    from agent.db.repositories.users import UserRepository

    conn = sqlite3.connect(path)
    conn.executescript(OLD_SCHEMA)
    conn.execute("INSERT INTO alerts (ts, alert, cluster, resolution)"
                 " VALUES (?,?,?,?)", (to_iso(), "MySQLSlow", "kemerovo", "почистили"))
    conn.execute("INSERT INTO users (username, role, enabled)"
                 " VALUES ('petrov','admin',1)")
    conn.commit()
    conn.close()

    await init_models()          # не должно ломать готовую базу
    async with session_scope() as s:
        rows = await AlertRepository(s).recent(hours=24)
        check("старые события читаются", rows[0].alert if rows else "", "MySQLSlow")
        user = await UserRepository(s).get("petrov")
        check("старые доступы читаются", user.is_admin if user else False, True)
        await AlertRepository(s).add(alert="Новый", cluster="kemerovo")
    async with session_scope() as s:
        check("запись в старую базу проходит",
              await AlertRepository(s).count(hours=24), 2)
    await dispose()

    conn = sqlite3.connect(path)
    cols = [r[1] for r in conn.execute("PRAGMA table_info(alerts)")]
    conn.close()
    check("схема не изменилась", "resolved_at" in cols and len(cols), 13)


# ── 3. Приложение целиком ────────────────────────────────────────────────────

def application() -> None:
    from fastapi.testclient import TestClient

    from agent.main import app

    password = "Секрет123!"
    with TestClient(app) as c:
        check("живость", c.get("/health").status_code, 200)
        check("без входа данные закрыты", c.get("/api/users").status_code, 401)
        check("без входа состояние закрыто", c.get("/status").status_code, 401)
        check("неверный пароль отклонён",
              c.post("/api/login", json={"username": "admin",
                                         "password": "нет"}).status_code, 401)

        # Страница входа: незаполненный плейсхолдер попадает прямо в
        # JavaScript и ломает скрипт целиком — форма перестаёт отправляться,
        # а внешне это выглядит как «нажимаю, и ничего»
        page = c.get("/login")
        check("страница входа отдаётся", page.status_code, 200)
        check("шаблон заполнен полностью", "{{" not in page.text, True)

        r = c.post("/api/login", json={"username": "admin", "password": password})
        check("вход администратором", r.status_code, 200)
        check("права администратора", c.get("/api/me").json().get("is_admin"), True)
        # После входа браузер идёт на корень: он должен отдать интерфейс,
        # а не отправить обратно на форму
        home = c.get("/", follow_redirects=False)
        check("после входа открывается интерфейс", home.status_code, 200)

        r = c.post("/api/users", json={"username": "MSK" + chr(92) + "IvKop",
                                       "role": "admin"})
        check("выдача доступа", r.json().get("username"), "ivkop")
        check("недопустимая роль отклонена",
              c.post("/api/users", json={"username": "x",
                                         "role": "root"}).status_code, 422)
        check("отзыв доступа", c.delete("/api/users/ivkop").status_code, 200)

        r = c.post("/api/alerts/ingest", headers={"X-Ingest-Token": "test-token"},
                   json={"alert": "DiskLow", "severity": "critical",
                         "summary": "/var 8%", "source": "zabbix"})
        check("приём события извне", r.json().get("alert"), "DiskLow")
        # Токен латиницей: в заголовки HTTP кириллица не помещается
        check("чужой токен отклонён",
              c.post("/api/alerts/ingest", headers={"X-Ingest-Token": "wrong"},
                     json={"alert": "X"}).status_code, 401)

        items = c.get("/alerts/history?hours=24").json()["items"]
        check("событие в истории", len(items), 1)
        check("запись решения",
              c.post("/api/alerts/%d/resolve" % items[0]["id"],
                     json={"resolution": "почистили /var"}).status_code, 200)
        check("инцидент запомнен",
              c.get("/api/incidents/DiskLow").json()["total"], 1)
        followup_check(c, items[0]["id"])

        check("оценка ответа", c.post("/api/feedback",
                                      json={"rating": -1}).status_code, 200)
        check("сводка оценок", c.get("/api/feedback/stats").json()["negative"], 1)
        check("Swagger опубликован",
              len(c.get("/openapi.json").json()["paths"]) > 20, True)

        extras(c)
        websocket(c)

        c.post("/api/logout")
        check("после выхода доступ закрыт", c.get("/api/users").status_code, 401)


def extras(client) -> None:
    """Ограничение приёма, журнал действий и сводка."""
    from agent.services import ratelimit

    # 1. Ограничение частоты: зациклившийся отправитель должен упереться
    ratelimit.reset()
    codes = set()
    for _ in range(ratelimit.INGEST_RATE_PER_MIN + 2):
        codes.add(client.post("/api/alerts/ingest",
                              headers={"X-Ingest-Token": "test-token"},
                              json={"alert": "Flood", "source": "loop"}).status_code)
    check("поток событий отсекается", 429 in codes, True)
    ratelimit.reset()
    check("после сброса приём возобновляется",
          client.post("/api/alerts/ingest", headers={"X-Ingest-Token": "test-token"},
                      json={"alert": "Ok", "source": "zabbix"}).status_code, 200)

    # 2. Журнал действий: в нём должны быть вход и выдача доступа
    log = client.get("/api/audit?days=1&limit=200").json()
    actions = {row["action"] for row in log["items"]}
    check("вход записан в журнал", "вход" in actions, True)
    check("выдача доступа записана", "доступ выдан" in actions, True)
    check("отказ во входе записан", "вход отклонён" in actions, True)
    denied = [r for r in log["items"] if r["action"] == "вход отклонён"]
    check("отказ помечен как неуспех", denied[0]["ok"], False)
    only = client.get("/api/audit?days=1&action=доступ выдан").json()
    check("фильтр по действию работает",
          {r["action"] for r in only["items"]}, {"доступ выдан"})

    # 3. Сводка собирается и содержит нерешённые события
    data = client.get("/api/digest?rebuild=true&hours=24").json()
    check("сводка собрана", "text" in data and bool(data["text"]), True)
    check("страница сводки отдаётся", client.get("/digest").status_code, 200)


def followup_check(client, alert_id: int) -> None:
    """Проверка «помогло ли решение».

    Запускаем немедленно, а не через четверть часа: важно, что вывод
    дописывается к решению и различает повтор от его отсутствия.
    """
    from anyio.from_thread import start_blocking_portal

    from agent.services import followup

    def verify() -> str:
        with start_blocking_portal("asyncio") as portal:
            portal.call(followup._verify, alert_id)
        rows = client.get("/api/incidents/DiskLow").json()["items"]
        return next((r["resolution"] or "") for r in rows if r["id"] == alert_id)

    text = verify()
    check("вывод о решении дописан", followup.MARK in text, True)
    check("повтора не было — решение рабочее", "не повторялось" in text, True)

    # Событие повторилось УЖЕ ПОСЛЕ записи решения — вывод должен смениться.
    # Повтор до записи доказательством провала не считается: тогда решение
    # ещё не применяли.
    client.post("/api/alerts/%d/resolve" % alert_id,
                json={"resolution": "почистили /var"})
    client.post("/api/alerts/ingest", headers={"X-Ingest-Token": "test-token"},
                json={"alert": "DiskLow", "severity": "critical",
                      "summary": "снова", "source": "zabbix"})
    check("повтор после решения замечен", "ПОВТОРИЛОСЬ" in verify(), True)


def websocket(client) -> None:
    """Разговор по WebSocket от начала до конца.

    Модель и сбор метрик подменяются: проверяем протокол и то, что обработчик
    доходит до конца. Именно здесь ломается перенос кода — забытый импорт
    роняет соединение, а внешне это выглядит как «связь прервана».
    """
    from agent.api.routes import chat as chat_routes

    async def fake_context(text):
        return "## Метрики\n  всё в порядке", None, 0

    async def fake_stream(messages):
        for piece in ("Всё ", "в ", "порядке."):
            yield piece

    async def no_tools():
        return False

    original = (chat_routes.build_chat_context, chat_routes.llm_stream,
                chat_routes.llm_probe_tools)
    chat_routes.build_chat_context = fake_context
    chat_routes.llm_stream = fake_stream
    chat_routes.llm_probe_tools = no_tools
    try:
        with client.websocket_connect("/ws") as ws:
            ws.send_json({"type": "ping"})
            check("сокет отвечает на ping", ws.receive_json().get("type"), "pong")

            ws.send_json({"type": "message", "text": "как дела",
                          "client_id": "web-1", "session_id": "s1"})
            kinds, answer = [], ""
            for _ in range(12):
                msg = ws.receive_json()
                kinds.append(msg.get("type"))
                if msg.get("type") == "token":
                    answer += msg.get("text", "")
                if msg.get("type") in ("done", "error"):
                    break
            check("соединение не оборвалось", kinds[-1], "done")
            check("контекст пришёл до ответа", "context" in kinds, True)
            check("ответ дошёл целиком", answer, "Всё в порядке.")
    finally:
        (chat_routes.build_chat_context, chat_routes.llm_stream,
         chat_routes.llm_probe_tools) = original

    saved = client.get("/chat/history?limit=10").json()
    check("переписка сохранена", saved["total"] >= 2, True)


def main() -> int:
    salt, iterations = secrets.token_hex(16), 200000
    digest = hashlib.pbkdf2_hmac("sha256", "Секрет123!".encode(),
                                 salt.encode(), iterations).hex()
    os.environ.update({
        "DB_URL": "sqlite+aiosqlite:///" + tmp_db("agent_test.db").replace(chr(92), "/"),
        "AUTH_ENABLED": "true",
        "AUTH_ADMIN_USER": "admin",
        "AUTH_ADMIN_PASSWORD_HASH":
            "pbkdf2_sha256$%d$%s$%s" % (iterations, salt, digest),
        "AUTH_SECRET": secrets.token_hex(32),
        "WEB_DIR": str(ROOT / "web"),
        "REGISTRY_PATH": test_registry(),
        "INGEST_TOKENS": "test-token",
        "LDAP_ENABLED": "false",
        "NSLCD_CONF": "",
        # Заведомо закрытый порт: обращение к модели должно падать сразу,
        # а не ждать разрешения несуществующего имени
        "LLM_BASE_URL": "http://127.0.0.1:9/v1",
        # Prometheus в проверках недоступен намеренно: отказ должен быть
        # мгновенным, а не по таймауту в пятнадцать секунд
        "PROMETHEUS_URL": "http://127.0.0.1:9",
        # Маленький предел: проверяем саму логику отсечения, а гонять сотню
        # событий ради этого незачем
        "INGEST_RATE_PER_MIN": "5",
        "LLM_TOOLS": "off",
    })

    print("1. Слой данных")
    asyncio.run(data_layer())

    print("")
    print("2. Существующая база")
    old = tmp_db("agent_old.db")
    os.environ["DB_URL"] = "sqlite+aiosqlite:///" + old.replace(chr(92), "/")
    for mod in [m for m in sys.modules if m.startswith("agent.")]:
        del sys.modules[mod]
    asyncio.run(old_database(old))

    print("")
    print("3. Приложение целиком")
    os.environ["DB_URL"] = ("sqlite+aiosqlite:///"
                            + tmp_db("agent_app.db").replace(chr(92), "/"))
    for mod in [m for m in sys.modules if m.startswith("agent.")]:
        del sys.modules[mod]
    application()

    print("")
    if FAILED:
        print("СБОЙ в проверках: %s" % ", ".join(FAILED))
        return 1
    print("Все проверки пройдены.")
    return 0


if __name__ == "__main__":
    code = main()
    # Явный выход вместо sys.exit: TestClient держит собственный поток с
    # циклом событий (anyio portal), и после сессии с WebSocket он остаётся
    # жив — интерпретатор ждёт его и не завершается. В бою этого механизма
    # нет, он только у тестового клиента, поэтому проще выйти сразу.
    sys.stdout.flush()
    sys.stderr.flush()
    os._exit(code)
