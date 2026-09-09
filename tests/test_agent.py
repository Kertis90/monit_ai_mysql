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
        threads(c)
        gui_endpoints(c)
        foresight(c)
        knowledge(c)
        ssh_access(c)
        background_answer(c)

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


def threads(client) -> None:
    """Создание чатов, переключение и изоляция.

    Сообщения из разных чатов не должны смешиваться: разбор аварии и вопрос
    про настройку — разные истории.
    """
    first = client.get("/chat/threads").json()["items"]
    check("прежняя переписка собрана в чат", len(first) >= 1, True)

    # Чтение истории не должно ничего создавать: из-за этого открытие
    # страницы заводило чат, и «Новый чат» давал сразу два
    before = len(client.get("/chat/threads").json()["items"])
    client.get("/chat/history?limit=10")
    check("чтение истории не создаёт чат",
          len(client.get("/chat/threads").json()["items"]), before)

    created = client.post("/chat/threads?title=Разбор аварии").json()
    check("чат создан", bool(created["id"]), True)
    listed = client.get("/chat/threads").json()["items"]
    check("чат появился в списке",
          any(t["title"] == "Разбор аварии" for t in listed), True)

    client.patch("/chat/threads/%s?title=Ночная авария" % created["id"])
    listed = client.get("/chat/threads").json()["items"]
    check("переименование применилось",
          any(t["title"] == "Ночная авария" for t in listed), True)

    # История нового чата пуста, хотя в прежнем сообщения есть
    fresh = client.get("/chat/history?thread=%s" % created["id"]).json()
    check("новый чат начинается с чистого листа", fresh["total"], 0)
    old_id = next(t["id"] for t in listed if t["id"] != created["id"])
    check("прежний чат сохранил сообщения",
          client.get("/chat/history?thread=%s" % old_id).json()["total"] > 0, True)

    check("чужой чат не отдаётся",
          client.get("/chat/history?thread=t-нетакого").status_code, 404)

    removed = client.delete("/chat/threads/%s" % created["id"])
    check("чат удалён", removed.status_code, 200)
    check("удаление несуществующего",
          client.delete("/chat/threads/%s" % created["id"]).status_code, 404)
    check("в списке его больше нет",
          any(t["id"] == created["id"]
              for t in client.get("/chat/threads").json()["items"]), False)


def gui_endpoints(client) -> None:
    """Данные для новых экранов интерфейса."""
    # Поиск идёт и по переписке, и по событиям
    found = client.get("/api/search?q=DiskLow").json()
    check("поиск находит событие",
          any(a["alert"] == "DiskLow" for a in found["alerts"]), True)
    check("короткий запрос отклоняется",
          client.get("/api/search?q=a").status_code, 400)

    # Готовые запросы для вкладки SQL
    tpl = client.get("/api/diagnostics/templates").json()["items"]
    check("шаблоны запросов отдаются", len(tpl) > 3, True)
    check("у шаблона есть текст запроса",
          all(t["sql"] and t["title"] for t in tpl), True)

    # Профиль и репликация: без базы возвращают понятную причину, а не падают
    load = client.get("/api/workload/kemerovo").json()
    check("профиль нагрузки отвечает", "error" in load or "queries" in load, True)
    repl = client.get("/api/replication/kemerovo").json()
    check("состояние репликации отвечает", "items" in repl, True)
    check("несуществующий кластер", client.get("/api/workload/нет").status_code, 404)

    # Логи: сервера нет, но ответ должен быть осмысленным
    logs = client.get("/api/logs/kemerovo?hours=1&kind=slow").json()
    check("логи отвечают текстом", isinstance(logs.get("text"), str), True)


def foresight(client) -> None:
    """Прогноз, разбор настроек, рост, отклонения, готовность, самопроверка."""
    from agent.services import anomaly, config_audit, forecast

    # Разбор настроек — чистая функция, её проверяем на данных, а не на сервере
    bad = {"version": "5.7.44", "innodb_flush_log_at_trx_commit": "2",
           "sync_binlog": "0", "innodb_buffer_pool_size": str(1024 ** 3),
           "query_cache_type": "ON", "slow_query_log": "OFF",
           "performance_schema": "OFF", "log_bin": "OFF",
           "max_connections": "1000"}
    found = config_audit.analyse(bad, {"max_used_connections": "950",
                                       "uptime": "100000"}, 16 * 1024 ** 3)
    names = {f["name"] for f in found}
    check("плохие настройки замечены", len(found) >= 6, True)
    check("выключенный binlog — важное",
          any(f["level"] == "critical" and f["name"] == "log_bin" for f in found), True)
    check("сказано, что нужен перезапуск",
          any(f["restart"] for f in found), True)

    good = {"version": "8.0.36", "innodb_flush_log_at_trx_commit": "1",
            "sync_binlog": "1",
            "innodb_buffer_pool_size": str(int(16 * 1024 ** 3 * 0.7)),
            "innodb_redo_log_capacity": str(int(16 * 1024 ** 3 * 0.2)),
            "query_cache_type": "0", "slow_query_log": "ON",
            "long_query_time": "1", "performance_schema": "ON",
            "log_bin": "ON", "binlog_format": "ROW",
            "binlog_expire_logs_seconds": "604800", "max_connections": "500",
            "gtid_mode": "ON", "innodb_file_per_table": "ON",
            "innodb_print_all_deadlocks": "ON"}
    check("на разумных настройках молчит",
          len(config_audit.analyse(good, {"max_used_connections": "200",
                                          "uptime": "100000"}, 16 * 1024 ** 3)), 0)

    # Отклонения: падение вдвое и рост втрое должны замечаться, шум — нет
    now  = {"qps": {"avg": 40}, "slow_qps": {"avg": 0.1},
            "connections_pct": {"avg": 20}, "iowait_pct": {"avg": 4}}
    base = {"qps": {"avg": 100}, "slow_qps": {"avg": 0.1},
            "connections_pct": {"avg": 18}, "iowait_pct": {"avg": 4}}
    drop = anomaly.compare(now, base)
    check("падение потока запросов замечено",
          any(d["metric"] == "qps" and d["kind"] == "drop" for d in drop), True)
    check("мелкие колебания не тревожат", len(drop), 1)
    check("на одинаковых значениях молчит", len(anomaly.compare(base, base)), 0)
    check("малые величины не сравниваются",
          len(anomaly.compare({"slow_qps": {"avg": 0.08}},
                              {"slow_qps": {"avg": 0.01}})), 0)

    # Предельные значения типов для автоинкремента
    check("предел int без знака",
          forecast.INT_LIMITS["int"][1], 4294967295)
    check("порог тревоги в сутках", forecast.CRITICAL_DAYS <= 7, True)

    # Методы отвечают даже без доступной базы
    for path in ("api/forecast/kemerovo", "api/config-audit/kemerovo",
                 "api/growth/kemerovo", "api/anomalies/kemerovo",
                 "api/readiness/kemerovo?action=restart"):
        r = client.get("/" + path)
        check("отвечает /" + path.split("?")[0], r.status_code, 200)
    check("недопустимое действие отклоняется",
          client.get("/api/readiness/kemerovo?action=drop").status_code, 400)

    deep = client.get("/health/deep").json()
    check("самопроверка отвечает", isinstance(deep.get("checks"), list), True)
    check("самопроверка видит проблемы", deep["ok"], False)


def knowledge(client) -> None:
    """Заметки, история настроек, лишние индексы, копии, правила прогноза."""
    import json as _json
    import subprocess
    import sys as _sys

    from agent.services import indexes

    # ── Заметки: подмешиваются в разбор, поэтому важно, что они хранятся ────
    made = client.post("/api/notes/kemerovo?text=Всплеск в 3:00 — это бэкап")
    check("заметка добавлена", made.status_code, 200)
    listed = client.get("/api/notes/kemerovo").json()["items"]
    check("заметка в списке", any("бэкап" in n["text"] for n in listed), True)
    note_id = listed[0]["id"]
    client.patch("/api/notes/%d?enabled=false" % note_id)
    check("заметка выключается",
          client.get("/api/notes/kemerovo").json()["items"][0]["enabled"], False)
    check("пустая заметка отклоняется",
          client.post("/api/notes/kemerovo?text=   ").status_code, 400)
    check("заметка удаляется",
          client.delete("/api/notes/%d" % note_id).status_code, 200)
    check("несуществующая заметка",
          client.delete("/api/notes/%d" % note_id).status_code, 404)

    # ── Лишние индексы: разбор схемы без обращения к данным ────────────────
    rows = []
    def idx(tbl, name, cols, unique=False):
        for i, col in enumerate(cols, 1):
            rows.append({"db": "billing", "tbl": tbl, "idx": name, "pos": i,
                         "col": col, "non_unique": "0" if unique else "1",
                         "cardinality": 10})
    idx("vgroups", "PRIMARY", ["id"], unique=True)
    idx("vgroups", "ix_agrm", ["agrm_id"])
    idx("vgroups", "ix_agrm_date", ["agrm_id", "created"])
    idx("vgroups", "ix_copy", ["agrm_id", "created"])
    idx("payments", "ix_uniq", ["ext_id"], unique=True)
    idx("payments", "ix_ext_date", ["ext_id", "paid_at"])
    idx("logs", "ix_ts", ["ts"])

    tables = indexes.build(rows)
    found = indexes.find_duplicates(tables) + indexes.find_redundant(tables)
    names = {i["index"] for i in found}
    check("дубликат индекса найден", "ix_copy" in names, True)
    check("префиксный индекс найден", "ix_agrm" in names, True)
    check("уникальный не трогаем", "ix_uniq" not in names, True)
    check("первичный ключ не трогаем", "PRIMARY" not in names, True)
    check("одиночный индекс не лишний", "ix_ts" not in names, True)
    check("готовая команда удаления",
          all("DROP INDEX" in indexes.fmt_indexes(
              {"host": "h", "tables": 3, "indexes": 7, "items": found})
              for _ in [0]), True)

    # ── Методы отвечают даже без доступной базы ────────────────────────────
    for path in ("api/indexes/kemerovo", "api/backups/kemerovo",
                 "api/config-changes/kemerovo?days=30"):
        check("отвечает /" + path.split("?")[0],
              client.get("/" + path).status_code, 200)
    check("копии не настроены — сказано прямо",
          client.get("/api/backups/kemerovo").json().get("configured"), False)

    # ── Правила прогноза для Prometheus ────────────────────────────────────
    out = os.path.join(tempfile.gettempdir(), "forecast_test.yml")
    code = subprocess.run([_sys.executable, str(ROOT / "scripts" / "gen_forecast_rules.py"),
                           os.environ["REGISTRY_PATH"], out],
                          capture_output=True, text=True).returncode
    check("генератор правил отработал", code, 0)
    body = open(out, encoding="utf-8").read()
    check("правило по дискам есть", "DiskWillFillIn3Days" in body, True)
    check("правило по соединениям есть", "ConnectionsWillHitLimit" in body, True)
    check("экстраполяция, а не порог", "predict_linear" in body, True)
    try:
        import yaml
        parsed = yaml.safe_load(body)
        check("YAML разбирается", len(parsed["groups"][0]["rules"]), 3)
    except ImportError:
        check("YAML не проверен (нет PyYAML)", True, True)
    os.remove(out)


def ssh_access(client) -> None:
    """Учётка и ключ для серверов: причина должна называться до подключения."""
    from agent.core.config import settings
    from agent.services.ssh import access_problem

    user, key = settings.ssh.user, settings.ssh.key
    try:
        settings.ssh.user, settings.ssh.key = "monitor", ""
        check("учётка задана, ключ по умолчанию", access_problem(), "")

        settings.ssh.key = os.path.join(tempfile.gettempdir(), "нет-такого-ключа")
        check("отсутствующий ключ назван прямо",
              "не найден" in access_problem(), True)

        real = os.path.join(tempfile.gettempdir(), "agent_test_key")
        with open(real, "w", encoding="utf-8") as f:
            f.write("не настоящий ключ")
        settings.ssh.key = real
        check("читаемый ключ претензий не вызывает", access_problem(), "")
        os.remove(real)

        settings.ssh.user = ""
        check("без учётки сказано, что заполнить",
              "SSH_USER" in access_problem(), True)
    finally:
        settings.ssh.user, settings.ssh.key = user, key


def background_answer(client) -> None:
    """Ответ переживает закрытие вкладки.

    Раньше генерация шла в обработчике сокета: обновил страницу — и разбор,
    на который агент потратил сбор метрик, пропадал целиком.
    """
    import time

    from agent.api.routes import chat as chat_routes
    from agent.services import jobs

    slow = {"go": False}

    async def fake_ctx(text):
        return "", None, 0

    async def fake_stream(messages):
        # Первый кусок сразу, остальное — после «перезагрузки страницы»
        yield "начало "
        for _ in range(50):
            if slow["go"]:
                break
            await asyncio.sleep(0.05)
        yield "и конец"

    async def no_tools():
        return False

    original = (chat_routes.build_chat_context, chat_routes.llm_stream,
                chat_routes.llm_probe_tools)
    chat_routes.build_chat_context = fake_ctx
    chat_routes.llm_stream = fake_stream
    chat_routes.llm_probe_tools = no_tools
    try:
        thread = client.post("/chat/threads?title=Фоновый").json()["id"]

        # Спросили и оборвали соединение, не дождавшись ответа
        with client.websocket_connect("/ws") as ws:
            ws.send_json({"type": "message", "text": "долгий вопрос",
                          "client_id": "web-1", "thread_id": thread})
            kinds = []
            for _ in range(4):
                kinds.append(ws.receive_json().get("type"))
                if "token" in kinds:
                    break
            check("ответ начал приходить", "token" in kinds, True)

        check("задача пережила разрыв", jobs.running(thread) is not None, True)
        check("вопрос сохранён до ответа",
              client.get("/chat/history?thread=%s" % thread).json()["total"], 1)

        # Вернулись — должны получить накопленное и продолжение
        slow["go"] = True
        with client.websocket_connect("/ws") as ws:
            ws.send_json({"type": "attach", "thread_id": thread,
                          "client_id": "web-1"})
            seen, answer = [], ""
            for _ in range(12):
                msg = ws.receive_json()
                seen.append(msg.get("type"))
                if msg.get("type") == "token":
                    answer += msg.get("text", "")
                if msg.get("type") == "done":
                    break
            check("возврат к ответу распознан", "resume" in seen, True)
            check("накопленное не потеряно", answer.startswith("начало"), True)
            check("ответ дописан до конца", answer.endswith("и конец"), True)

        for _ in range(20):
            if client.get("/chat/history?thread=%s" % thread).json()["total"] >= 2:
                break
            time.sleep(0.1)
        saved = client.get("/chat/history?thread=%s" % thread).json()
        check("ответ сохранён в историю", saved["total"], 2)

        # Завершённая задача не должна мешать следующему вопросу
        check("разговор снова свободен", jobs.running(thread) is None, True)
    finally:
        (chat_routes.build_chat_context, chat_routes.llm_stream,
         chat_routes.llm_probe_tools) = original


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
