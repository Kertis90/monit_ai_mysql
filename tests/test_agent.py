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
        mysql_hints()
        tool_calls_in_text()
        log_bisect()
        shared_tasks()
        json_safety()
        row_cap()
        forecast_wording()
        insight_blocks()
        prometheus_series()
        forecast_sources()
        web_behaviour()
        audit_paging(c)
        insight_endpoint(c)
        diagnose_endpoint(c)
        login_redirect(c)
        internal_http()
        cluster_page_shape()
        processlist_block()
        diagnose_budget()
        sql_aliases()
        long_values()
        version_detection()
        diag_by_version()
        skipped_reported()
        time_window()
        range_request()
        charts_range_route(c)
        range_ui()

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

    async def fake_ctx(text, progress=None):
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


def mysql_hints() -> None:
    """Отказ подключения объясняется, а не пересказывается.

    Сообщение драйвера про caching_sha2_password выглядит как поломка сервера,
    хотя это отсутствующий пакет на стороне агента.
    """
    from agent.services.mysql import conn_hint

    plugin = conn_hint(Exception(
        "Authentication plugin 'caching_sha2_password' requires the "
        "cryptography package"))
    check("про caching_sha2 сказано, чего не хватает",
          "cryptography" in plugin and "install_agent.sh" in plugin, True)
    check("предложен запасной плагин",
          "mysql_native_password" in plugin, True)
    check("отказ в доступе отправляет в clusters.json",
          "clusters.json" in conn_hint(Exception("Access denied for user")), True)
    check("обычная сетевая ошибка не обрастает подсказками",
          conn_hint(Exception("timed out")), "")


def tool_calls_in_text() -> None:
    """Вызов инструмента, написанный текстом, не должен попадать в чат.

    Часть моделей не умеет штатный tool calling и пишет вызов прямо в
    ответ. Пользователь видел разметку вместо ответа.
    """
    from agent.services.toolcalls import StreamFilter, find_calls, strip_calls

    sample = ("Сейчас посмотрю.\n<tool_call><function><parameter=cluster>"
              "vladivostok</parameter><parameter=sql>SELECT 1</parameter>"
              "</function></tool_call>")
    calls = find_calls(sample)
    check("вызов без имени функции разобран", len(calls), 1)
    check("инструмент определён по параметрам", calls[0]["name"], "run_sql")
    check("аргументы разобраны", calls[0]["args"].get("cluster"), "vladivostok")
    check("разметка не показана", "tool_call" not in strip_calls(sample), True)

    # По одному символу: тег приходит кусками и не должен мелькать
    flt = StreamFilter()
    shown = "".join(flt.feed(ch) for ch in sample) + flt.finish()
    check("в потоке разметки нет", "<tool" not in shown, True)
    check("текст до вызова сохранён", shown.strip(), "Сейчас посмотрю.")
    check("вызовы видны вызывающему", len(flt.calls), 1)

    js = ('<tool_call>{"name": "get_history", "arguments": '
          '{"cluster": "kemerovo", "hours": 6}}</tool_call>')
    check("формат JSON тоже понят", find_calls(js)[0]["name"], "get_history")

    cut = "Проверяю<tool_call><function=run_sql><parameter=cluster>kem"
    check("оборванный вызов отрезан", strip_calls(cut), "Проверяю")

    plain = "Обычный текст, где встречается < и слово tool"
    f2 = StreamFilter()
    out = "".join(f2.feed(t + " ") for t in plain.split(" ")) + f2.finish()
    check("обычный текст не пострадал", out.strip(), plain)


def log_bisect() -> None:
    """Кусок большого лога ищется делением, а не полным чтением."""
    from agent.services import logscan

    script = logscan.bisect_script("/var/log/big.log", "20260907", "20260908",
                                   "grep -a -F -e X")
    check("файл экранирован", "F=/var/log/big.log" in script, True)
    check("границы периода переданы",
          "S=20260907" in script and "U=20260908" in script, True)
    check("две границы ищутся делением", script.count("while [ $(("), 2)
    check("читается только найденный кусок",
          "tail -c +$((st + 1))" in script, True)

    note, rest = logscan.take_slice_note(
        "##SLICE 0 52428800 18253611008\nстрока лога")
    check("отчёт о просмотренном", "50 МБ" in note and "17.0 ГБ" in note, True)
    check("служебная строка не в выводе", rest, "строка лога")
    check("обычный вывод не тронут",
          logscan.take_slice_note("просто строка")[1], "просто строка")

    # На маленьком файле деление не нужно: обычный grep быстрее
    check("порог включения разумен",
          logscan.BISECT_MIN_BYTES >= 128 * 1024 * 1024, True)


def shared_tasks() -> None:
    """Одинаковую работу делаем один раз на всех, кто её попросил."""
    from agent.services import tasks

    calls = {"n": 0}

    async def slow():
        calls["n"] += 1
        await asyncio.sleep(0.15)
        return {"value": calls["n"]}

    async def scenario():
        # Три одновременных запроса — одна работа
        got = await asyncio.gather(*[tasks.shared("проба", slow, ttl=5)
                                     for _ in range(3)])
        check("работа выполнена один раз", calls["n"], 1)
        check("все получили один результат",
              all(g["value"] == 1 for g in got), True)

        # Свежий результат отдаётся сразу, без повторной работы
        again = await tasks.shared("проба", slow, ttl=5)
        check("свежий результат переиспользован", again["value"], 1)
        check("повторной работы не было", calls["n"], 1)

        # Отменённый запрос не убивает работу: следующий получит готовое
        task = asyncio.create_task(tasks.shared("проба2", slow, ttl=5))
        await asyncio.sleep(0.02)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        await asyncio.sleep(0.3)
        check("работа пережила отменённый запрос",
              tasks.cached("проба2", ttl=5) is not None, True)
        await tasks.shutdown()

    asyncio.run(scenario())


def json_safety() -> None:
    """Одно нечисловое значение не должно ронять весь ответ."""
    import json as jsonlib

    from agent.api.responses import SafeJSONResponse, sanitize

    data = {"ok": 1.5, "bad": float("inf"), "nan": float("nan"),
            "deep": {"list": [1.0, float("nan")]}}
    clean = sanitize(data)
    check("бесконечность обезврежена", clean["bad"] is None, True)
    check("NaN обезврежен", clean["nan"] is None, True)
    check("вложенные тоже", clean["deep"]["list"][1] is None, True)
    check("нормальные числа целы", clean["ok"], 1.5)

    raw = SafeJSONResponse(content=data).render(data)
    back = jsonlib.loads(raw.decode("utf-8"))
    check("ответ разбирается как JSON", back["ok"], 1.5)


def row_cap() -> None:
    """SHOW GLOBAL VARIABLES не должен обрываться на двухстах строках."""
    from agent.services.mysql import SQL_MAX_ROWS, sql_add_limit

    check("предел по умолчанию на месте",
          sql_add_limit("SELECT 1").endswith("LIMIT %d" % SQL_MAX_ROWS), True)
    check("свой предел применяется",
          sql_add_limit("SELECT 1", 5000).endswith("LIMIT 5000"), True)
    check("к SHOW предел не дописывается",
          sql_add_limit("SHOW GLOBAL VARIABLES"), "SHOW GLOBAL VARIABLES")

    from agent.services import config_audit
    check("разбор настроек просит все строки",
          config_audit.ALL_ROWS >= 1000, True)


def forecast_wording() -> None:
    """Про соединения говорим по метрике, которая есть у любого экспортёра."""
    import inspect

    from agent.services import forecast

    src = inspect.getsource(forecast.connections_forecast)
    check("пик считается по threads_connected",
          "max_over_time" in src and "threads_connected" in src, True)
    check("предел спрашивается у базы, если его нет в метриках",
          "@@max_connections" in inspect.getsource(forecast), True)

    text = forecast.fmt_forecast({
        "label": "Кемерово", "disks": [], "auto_increment": [],
        "connections": {"peak": 120, "limit": 500, "used_pct": 24.0,
                        "now": 87, "days_left": None, "measured": False,
                        "level": "ok"}})
    check("видно и текущее, и пик", "сейчас 87" in text and "пик" in text, True)
    check("честно про отсутствие истории", "не известен" in text, True)


def insight_blocks() -> None:
    """Разбор собирает то, что видит человек, и не раздувается."""
    from agent.services import insight

    long_text = "строка данных " * 5000
    trimmed = insight._trim(long_text, 1000)
    check("длинный блок обрезан", len(trimmed) < 1200, True)
    check("вырезана середина, а не хвост",
          trimmed.startswith("строка") and trimmed.endswith("данных "), True)

    body = insight._blocks_text([{"title": "Репликация", "text": "лаг 0"},
                                 {"title": "Пусто", "text": "  "}])
    check("заголовок блока сохранён", "## Репликация" in body, True)
    check("пустые блоки отброшены", "Пусто" not in body, True)


def prometheus_series() -> None:
    """Рядов у запроса бывает много, и нужен не первый попавшийся.

    Раздел «Запас по ресурсам» разбирал ответ Prometheus как словарь, а
    prom_query отдаёт одно число: диски всегда получались пустыми, а
    соединения — «метрик нет».
    """
    from agent.services.prometheus import parse_series

    answer = {"status": "success", "data": {"result": [
        {"metric": {"mountpoint": "/", "instance": "10.0.0.5:9100"},
         "value": [1757000000, "12884901888"]},
        {"metric": {"mountpoint": "/var/lib/mysql"},
         "value": [1757000000, "53687091200"]},
    ]}}
    got = parse_series(answer, "mountpoint")
    check("все файловые системы разобраны", len(got), 2)
    check("значение по точке монтирования",
          got["/var/lib/mysql"], 53687091200.0)
    check("пустой ответ не роняет разбор",
          parse_series({"status": "success", "data": {"result": []}}), {})
    check("ошибка Prometheus даёт пусто",
          parse_series({"status": "error"}), {})

    # Без метки различаем по тому, что есть
    by_instance = parse_series({"status": "success", "data": {"result": [
        {"metric": {"instance": "10.0.0.5:9104"}, "value": [1, "42"]}]}})
    check("метка подбирается сама", by_instance["10.0.0.5:9104"], 42.0)


def forecast_sources() -> None:
    """Числа по соединениям берутся и из базы, когда метрик нет."""
    import inspect

    from agent.services import forecast

    src = inspect.getsource(forecast)
    check("есть запрос к базе про соединения",
          "_connections_from_db" in src and "@@max_connections" in src, True)
    check("причина отсутствия метрик разбирается",
          "_why_no_metrics" in src and "--collect.global_status" in src, True)
    check("диски читаются всеми рядами",
          "prom_query_map(client, base" in src, True)

    text = forecast.fmt_forecast({
        "label": "Кемерово", "disks": [], "auto_increment": [],
        "connections": {"peak": 300, "limit": 500, "used_pct": 60.0,
                        "now": 120, "days_left": None, "measured": False,
                        "source": "запрос к базе", "level": "ok"}})
    check("видно, что пик с запуска сервера",
          "пик с запуска сервера" in text, True)


def web_behaviour() -> None:
    """Поведение интерфейса, которое ломалось незаметно."""
    app = (ROOT / "web" / "app.js").read_text(encoding="utf-8")
    html = (ROOT / "web" / "index.html").read_text(encoding="utf-8")

    check("вкладка «Здоровье» не проверяет всё при открытии",
          "health: () => loadHealth()" not in app, True)
    check("проверка запускается кнопкой",
          "App.loadHealth(this)" in html, True)

    check("сторож ответа сбрасывается на каждом признаке работы",
          "if (state.awaitingReply && ALIVE.indexOf(msg.type) >= 0)" in app, True)
    check("ping сторож не продлевает", "'pong'" not in
          app[app.index("const ALIVE"):app.index("function armWatchdog")], True)

    check("вкладка «Кластер» больше не спрятана",
          'id="tab-btn-cluster"' in html and "display:none" not in
          html[html.index('id="tab-btn-cluster"'):
               html.index('id="tab-btn-cluster"') + 160], True)
    check("графики страницы кластера подписаны периодом",
          "'<h4>Метрики ' + esc(periodLabel()) + '</h4>'" in app, True)
    check("выгрузка PDF знает кластер и период",
          "'report?cluster=' + encodeURIComponent(name) +" in app, True)
    check("значок «Здоровья» из общедоступного набора",
          "🩺" not in html, True)


def audit_paging(client) -> None:
    """Журнал отдаётся страницами, а не тысячами записей разом."""
    # Записи заведём действиями, которые журналируются сами
    for i in range(7):
        client.post("/api/query", json={"cluster": "kemerovo",
                                        "sql": "SELECT %d" % i})

    first = client.get("/api/audit?days=1&limit=3&offset=0").json()
    check("страница отдана целиком", len(first["items"]), 3)
    check("total считает все подходящие", first["total"] >= 7, True)
    check("сказано, что есть продолжение", first["has_more"], True)
    check("смещение возвращается", first["offset"], 0)

    second = client.get("/api/audit?days=1&limit=3&offset=3").json()
    check("вторая страница другая",
          second["items"][0] != first["items"][0], True)
    check("границы страницы не пересекаются",
          all(a not in first["items"] for a in second["items"]), True)

    tail = client.get("/api/audit?days=1&limit=500&offset=0").json()
    check("последняя страница без продолжения", tail["has_more"], False)
    check("отдано столько, сколько есть",
          tail["returned"], len(tail["items"]))

    # Фильтр по действию считается вместе с общим числом
    only = client.get("/api/audit?days=1&limit=2&action=SQL-запрос").json()
    check("фильтр применён к обеим величинам",
          only["total"] >= 7 and len(only["items"]) == 2, True)


def insight_endpoint(client) -> None:
    """Разбор отвечает даже тогда, когда модель молчит.

    Журнал раньше вызывался как функция, хотя это репозиторий: запрос падал
    сразу после того, как модель отработала, и в интерфейсе кольцо крутилось
    без конца.
    """
    from agent.api.routes import clusters as cluster_routes

    async def fake_analyze(cluster, blocks, scope="all", question=""):
        return "Вывод: %d блоков, режим %s" % (len(blocks), scope)

    original = cluster_routes.insight.analyze
    cluster_routes.insight.analyze = fake_analyze
    try:
        r = client.post("/api/analyze", json={
            "cluster": "kemerovo", "scope": "one",
            "blocks": [{"title": "Репликация", "text": "лаг 0 с"}]})
        check("разбор отдан", r.status_code, 200)
        check("текст от модели дошёл", "1 блоков" in r.json()["text"], True)

        journal = client.get("/api/audit?days=1&limit=50&action=Разбор ИИ").json()
        check("действие попало в журнал", journal["total"] >= 1, True)

        r = client.post("/api/analyze", json={"cluster": "нет-такого",
                                              "blocks": []})
        check("несуществующий кластер отвергнут", r.status_code, 404)
    finally:
        cluster_routes.insight.analyze = original

    # Молчащая модель не должна оставлять запрос висеть
    async def never(cluster, blocks, scope="all", question=""):
        await asyncio.sleep(30)
        return "поздно"

    from agent.core.config import settings
    was, grace = settings.llm.timeout, cluster_routes.INSIGHT_GRACE_S
    settings.llm.timeout = 0.1
    cluster_routes.INSIGHT_GRACE_S = 0
    cluster_routes.insight.analyze = never
    try:
        r = client.post("/api/analyze", json={
            "cluster": "kemerovo",
            "blocks": [{"title": "Блок", "text": "данные" * 20}]})
        check("молчание модели не подвешивает запрос", r.status_code, 200)
        check("сказано, что модель не ответила",
              "не ответила" in r.json()["text"], True)
    finally:
        settings.llm.timeout = was
        cluster_routes.INSIGHT_GRACE_S = grace
        cluster_routes.insight.analyze = original


def diagnose_endpoint(client) -> None:
    """Диагностика отвечает, а не падает на сигнатуре форматтера.

    fmt_diagnostics ждёт метку и адрес, а роут звал её с одним аргументом —
    у пользователя это выглядело как TypeError вместо отчёта.
    """
    r = client.get("/api/diagnose/kemerovo")
    check("диагностика отвечает", r.status_code, 200)
    text = r.json().get("report", "")
    check("сказано, почему пусто", "db_user" in text, True)
    check("названа вторая возможная причина",
          "performance_schema" in text, True)

    deep = client.get("/api/diagnose/kemerovo?deep=true")
    check("глубокий разбор тоже отвечает", deep.status_code, 200)


def login_redirect(client) -> None:
    """Истёкшая сессия должна уводить на форму входа, а не оставлять пустой
    экран: браузеру нужен признак, что дело именно в сессии."""
    fresh = client.__class__(client.app) if hasattr(client, "app") else None
    r = (fresh or client).get("/api/users", cookies={})
    if r.status_code == 401:
        data = r.json()
        check("401 помечен как «нужен вход»", data.get("login_required"), True)
        check("указано, куда идти", str(data.get("login_url", "")).endswith("/login"),
              True)
    else:
        check("выход из сессии проверяется отдельно", True, True)

    app_js = (ROOT / "web" / "app.js").read_text(encoding="utf-8")
    check("браузер перехватывает 401 в одном месте",
          "window.fetch = async" in app_js and "goToLogin" in app_js, True)
    check("закрытый сокет с кодом 4401 тоже уводит",
          "ev.code === 4401" in app_js, True)


def internal_http() -> None:
    """К своим адресам ходим мимо системного прокси.

    httpx берёт прокси из окружения, а на Windows ещё и из реестра: запрос
    к собственному Prometheus уходил наружу и возвращался 503, а агент
    рапортовал «метрик нет» при исправном мониторинге.
    """
    from agent.services.prometheus import http_client

    client = http_client()
    check("клиент не доверяет окружению", client.trust_env, False)
    check("свои параметры проходят",
          http_client(timeout=7).timeout.read, 7)

    import inspect

    from agent.services import forecast, selfcheck
    check("прогноз ходит этим клиентом",
          "http_client(" in inspect.getsource(forecast), True)
    check("самопроверка тоже",
          "http_client(" in inspect.getsource(selfcheck), True)


def cluster_page_shape() -> None:
    """Страница кластера собирается из данных, а не из стены разметки."""
    app_js = (ROOT / "web" / "app.js").read_text(encoding="utf-8")

    check("блоки описаны списком", "CLUSTER_GROUPS" in app_js, True)
    check("групп четыре", app_js.count("blocks: ["), 4)
    for out in ("cluster-workload", "cluster-repl", "cluster-diag",
                "cluster-forecast", "cluster-config", "cluster-growth",
                "cluster-anomaly", "cluster-indexes", "cluster-changes",
                "cluster-backups", "cluster-ready"):
        if out not in app_js:
            check("блок %s на месте" % out, False, True)
    check("все одиннадцать блоков на месте", True, True)

    check("состояние подписано словом, а не только цветом",
          "'внимание'" in app_js and "'критично'" in app_js, True)
    check("вердикт по кластеру считается", "function verdict(" in app_js, True)
    check("графики строятся из карточек напрямую",
          "ch.charts.map(chartCard).join('')" in app_js, True)
    check("метрики-строки не роняют форматирование",
          "typeof value === 'number' ? value : parseFloat(value)" in app_js, True)

    css = (ROOT / "web" / "style.css").read_text(encoding="utf-8")
    check("уголок нарисован, а не набран шрифтом",
          ".blk-toggle .caret" in css and "border-left: 5px solid" in css, True)
    check("значение плитки цветом текста",
          "color: var(--text-hl);" in css, True)


def processlist_block() -> None:
    """Профиль нагрузки показывает и полный текст того, что идёт сейчас.

    Дайджест performance_schema нормализован: значения заменены на «?», а
    строка обрезана. По такому запросу нельзя ни повторить, ни объяснить,
    почему он сегодня читает миллион строк.
    """
    from agent.services import workload

    check("берётся именно полный список",
          workload.ACTIVE_SQL, "SHOW FULL PROCESSLIST")

    lines = workload._fmt_active({
        "total": 412, "sleeping": 409, "busy_total": 3,
        "items": [
            {"id": 771, "user": "billing", "from": "10.0.0.9:51844",
             "db": "lanbilling", "command": "Query", "time_s": 42.0,
             "state": "Sending data", "cut": False,
             "query": "SELECT `uid`, `agrm_id` FROM `agreements` "
                      "WHERE `archive` = 0 AND `balance` < -100"},
        ]})
    text = "\n".join(lines)
    check("виден полный запрос с значениями",
          "`balance` < -100" in text, True)
    check("видно, сколько соединений спит", "спящих 409" in text, True)
    check("видно, сколько запрос уже идёт", "42 с" in text, True)
    check("видно, кто и откуда", "billing@10.0.0.9" in text, True)

    idle = "\n".join(workload._fmt_active(
        {"total": 120, "sleeping": 120, "busy_total": 0, "items": []}))
    check("простой назван простоем", "все 120 соединений простаивают" in idle, True)

    broken = "\n".join(workload._fmt_active({"error": "нет прав"}))
    check("отказ объяснён, а не проглочен", "нет прав" in broken, True)


def diagnose_budget() -> None:
    """Долгий разбор отвечает раньше, чем прокси теряет терпение."""
    from agent.services import tasks

    async def scenario():
        slow_done = {"n": 0}

        async def slow():
            await asyncio.sleep(0.4)
            slow_done["n"] += 1
            return {"report": "готово"}

        data, in_time = await tasks.shared_within("долгая", slow,
                                                  budget=0.05, ttl=30)
        check("не успели — сказано честно", in_time, False)
        check("пустышка вместо результата", data is None, True)

        # Главное: работа не брошена, и следующий спросивший получит готовое
        await asyncio.sleep(0.6)
        check("работа доведена до конца", slow_done["n"], 1)
        again, ok = await tasks.shared_within("долгая", slow, budget=0.05, ttl=30)
        check("повторный запрос отдаёт готовое", ok, True)
        check("это тот же результат", again["report"], "готово")
        check("заново не считали", slow_done["n"], 1)
        await tasks.shutdown()

    asyncio.run(scenario())

    from agent.services.analysis import DIAG_PARALLEL
    check("набор идёт не по одному запросу", DIAG_PARALLEL > 1, True)
    check("но и не всем скопом", DIAG_PARALLEL <= 8, True)

    app_js = (ROOT / "web" / "app.js").read_text(encoding="utf-8")
    check("504 объясняется по-человечески",
          "proxy_read_timeout" in app_js and "504" in app_js, True)


# Слова, которые MySQL 8.0 не даст использовать псевдонимом без кавычек.
# Список неполный намеренно: здесь те, что реально просятся в псевдоним
# диагностического запроса. READS уже стоил двух пустых разделов.
MYSQL_RESERVED = {
    "read", "reads", "read_write", "write", "writes", "row", "rows", "groups",
    "system", "rank", "lead", "lag", "over", "window", "recursive", "lateral",
    "of", "except", "empty", "first_value", "last_value", "dense_rank",
    "cume_dist", "ntile", "percent_rank", "row_number", "json_table", "range",
    "interval", "key", "keys", "order", "group", "match", "status", "usage",
    "partition", "option", "level", "lines", "columns",
}


def sql_aliases() -> None:
    """Псевдоним, совпавший с зарезервированным словом, ломает весь запрос.

    Сервер отвечает 1064, агент прячет ошибку в текст блока, и раздел
    выглядит как «данных нет». Найти это по симптому почти невозможно.
    """
    import re

    bad = []
    for path in sorted((ROOT / "agent").rglob("*.py")):
        src = path.read_text(encoding="utf-8")
        for m in re.finditer(r"\bAS\s+([A-Za-z_][\w]*)", src):
            if m.group(1).lower() in MYSQL_RESERVED:
                line = src[:m.start()].count(chr(10)) + 1
                bad.append("%s:%d AS %s" % (path.name, line, m.group(1)))
    check("зарезервированных псевдонимов нет", bad, [], show=", ".join(bad) or "чисто")

    # А в кавычках — можно и нужно
    from agent.services.analysis import DIAG_QUERIES
    io_query = next(q for q in DIAG_QUERIES if q["key"] == "table_io")
    check("проблемные псевдонимы взяты в кавычки",
          "AS `reads`" in io_query["sql"], True)

    from agent.services.mysql import sql_validate
    for q in DIAG_QUERIES:
        ok, why = sql_validate(q["sql"])
        if not ok:
            check("запрос %s проходит валидатор" % q["key"], why, "")
    check("все диагностические запросы читающие", True, True)


def long_values() -> None:
    """Длинное значение печатается целиком, а не первыми шестьюдесятью."""
    from agent.services.mysql import fmt_sql_result

    innodb = {"host": "10.0.0.5", "query": "SHOW ENGINE INNODB STATUS",
              "columns": ["Type", "Name", "Status"],
              "rows": [["InnoDB", "", "BUFFER POOL AND MEMORY" + chr(10) +
                        "Buffer pool hit rate 998 / 1000" + chr(10) +
                        "---TRANSACTION 421, ACTIVE 942 sec"]]}
    out = fmt_sql_result(innodb)
    check("состояние InnoDB не обрезано",
          "Buffer pool hit rate 998 / 1000" in out, True)
    check("и его хвост тоже", "ACTIVE 942 sec" in out, True)
    check("длинная колонка вынесена отдельно", "Status:" in out, True)

    # Короткие значения по-прежнему таблицей: так их читать удобнее
    short = {"host": "10.0.0.5", "query": "SHOW GLOBAL STATUS",
             "columns": ["Variable_name", "Value"],
             "rows": [["Threads_connected", "126"]]}
    table = fmt_sql_result(short)
    check("короткие значения остались таблицей",
          "Variable_name" in table and "|" in table and "1)" not in table, True)

    # Совсем гигантское значение обрезается, но об этом сказано
    huge = {"host": "10.0.0.5", "query": "SHOW ENGINE INNODB STATUS",
            "columns": ["Status"], "rows": [["x" * 60000]]}
    cut = fmt_sql_result(huge)
    check("гигантское значение обрезано с пометкой",
          "далее ещё" in cut, True)
    check("но взято куда больше шестидесяти символов",
          cut.count("x") > 10000, True)


def version_detection() -> None:
    """Версия и сборка сервера разбираются из того, что отдаёт VERSION()."""
    from agent.services.mysql import flavour, has_sys_schema, parse_version

    cases = [
        ("5.6.51-log",       (5, 6, 51),  "mysql",   False),
        ("5.7.44-0ubuntu",   (5, 7, 44),  "mysql",   True),
        ("8.0.36",           (8, 0, 36),  "mysql",   True),
        ("8.4.0",            (8, 4, 0),   "mysql",   True),
        ("5.7.42-46-log",    (5, 7, 42),  "percona", True),
        ("10.11.6-MariaDB",  (10, 11, 6), "mariadb", True),
        ("10.3.39-MariaDB",  (10, 3, 39), "mariadb", False),
    ]
    for raw, want_ver, want_kind, want_sys in cases:
        got = parse_version(raw)
        if got != want_ver:
            check("версия %s разобрана" % raw, got, want_ver)
        kind = flavour(raw)
        # «percona» узнаём по строке version_comment, а не по номеру:
        # у голого «5.7.42-46-log» отличить нельзя, и это нормально
        if want_kind != "percona" and kind != want_kind:
            check("сборка %s опознана" % raw, kind, want_kind)
        if has_sys_schema(got, kind) != want_sys:
            check("наличие sys у %s" % raw, has_sys_schema(got, kind), want_sys)
    check("все версии разобраны верно", True, True)

    check("мусор не роняет разбор", parse_version("непонятно"), (0, 0, 0))
    check("десятка MariaDB не путается с восьмёркой Oracle",
          parse_version("10.5.0-MariaDB") > parse_version("8.0.36"), True)


def diag_by_version() -> None:
    """Набор подбирается под сервер: на 5.6 нет sys, в 8.0 нет старой
    information_schema.innodb_lock_waits — и то и другое надо учитывать."""
    from agent.services.analysis import DIAG_QUERIES, unsupported
    from agent.services.mysql import sql_validate

    def picked(version, kind):
        return [q["key"] for q in DIAG_QUERIES if not unsupported(q, version, kind)]

    old = picked((5, 6, 51), "mysql")
    new = picked((8, 0, 36), "mysql")
    maria_new = picked((10, 11, 6), "mariadb")
    maria_old = picked((10, 3, 39), "mariadb")

    check("на 5.6 проверок из sys нет", "wait_classes" in old, False)
    check("на 8.0 они есть", "wait_classes" in new, True)
    check("на MariaDB 10.6+ тоже", "wait_classes" in maria_new, True)
    check("на MariaDB 10.3 — нет", "wait_classes" in maria_old, False)

    # Блокировки должны быть видны на любой версии, просто из разных мест
    for name, keys in (("5.6", old), ("8.0", new),
                       ("MariaDB 10.11", maria_new), ("MariaDB 10.3", maria_old)):
        got = [k for k in keys if k.startswith("locks")]
        if len(got) != 1:
            check("на %s ровно один источник блокировок" % name, got, ["один"])
    check("блокировки видны на всех версиях, каждый раз из своего места",
          True, True)

    check("незнакомая версия ничего не отсекает",
          len(picked((0, 0, 0), "mysql")), len(DIAG_QUERIES))

    # Проверки без пометок должны работать везде
    always = [q["key"] for q in DIAG_QUERIES
              if not q.get("needs") and not q.get("min_version")
              and not q.get("max_version")]
    for key in always:
        if key not in old or key not in new:
            check("проверка %s работает на любой версии" % key, False, True)
    check("общие проверки есть в наборе для каждой версии", len(always) > 5, True)

    bad = [(q["key"], sql_validate(q["sql"])[1])
           for q in DIAG_QUERIES if not sql_validate(q["sql"])[0]]
    check("все запросы набора читающие", bad, [],
          show=", ".join("%s: %s" % b for b in bad) or "да")

    check("методика начинается с классов ожиданий",
          DIAG_QUERIES[[q["key"] for q in DIAG_QUERIES].index("wait_classes")]["why"]
          .startswith("отвечает на вопрос"), True)


def skipped_reported() -> None:
    """Пропущенное на этой версии названо, а не проглочено молча."""
    from agent.services.analysis import fmt_diagnostics

    text = fmt_diagnostics([
        {"key": "_skipped", "title": "Пропущено на этой версии",
         "why": "mysql 5.6.51",
         "note": "  Во что упирается сервер — нужна схема sys: она появилась в 5.7"},
    ], "Кемерово", "10.0.0.5")
    check("сказано, что пропущено", "Пропущено на этой версии" in text, True)
    check("и почему", "появилась в 5.7" in text, True)
    check("названа версия сервера", "5.6.51" in text, True)


def time_window() -> None:
    """Границы окна приводятся к разумным, а не принимаются как есть."""
    import time as _time

    from agent.services.prometheus import MAX_METRICS_HOURS, resolve_window

    now = _time.time()

    start, end, hours = resolve_window(3)
    check("«за 3 часа» — это три часа", round(hours, 2), 3.0)
    check("и заканчивается сейчас", abs(end - now) < 5, True)

    _, _, hours = resolve_window(100)
    check("слишком длинное окно обрезано", hours, float(MAX_METRICS_HOURS))

    start, end, hours = resolve_window(0, now - 26 * 3600, now - 24 * 3600)
    check("свой интервал берётся как есть", round(hours, 2), 2.0)
    check("и не подтягивается к «сейчас»", abs(end - (now - 24 * 3600)) < 5, True)

    _, _, hours = resolve_window(0, now - 3600, now - 7200)
    check("перевёрнутый интервал развернут", round(hours, 2), 1.0)

    _, end, _ = resolve_window(0, now - 3600, now + 99999)
    check("будущее обрезано по «сейчас»", abs(end - now) < 5, True)

    start, end, hours = resolve_window(0, now - 72 * 3600, now)
    check("трое суток сужены до предела", hours, float(MAX_METRICS_HOURS))
    check("сужены с сохранением свежего края", abs(end - now) < 5, True)

    _, _, hours = resolve_window(0, now - 10, now)
    check("слишком узкое окно расширено до минуты",
          round(hours * 3600), 60)


def range_request() -> None:
    """В Prometheus уходят именно те границы, которые попросили."""
    class FakeResponse:
        @staticmethod
        def json():
            return {"status": "success", "data": {"result": [
                {"metric": {}, "values": [[1789000000, "1.5"]]}]}}

    class FakeClient:
        def __init__(self):
            self.params = None

        async def get(self, url, params=None, timeout=None):
            self.params = params
            return FakeResponse()

    from agent.services.prometheus import prom_range_series

    async def scenario():
        client = FakeClient()
        since, until = 1788973200, 1788989400      # 4.5 часа
        await prom_range_series(client, "up", 0, since, until)
        check("начало окна передано", client.params["start"], "%d" % since)
        check("конец окна передан", client.params["end"], "%d" % until)
        # ~200 точек на график: шаг считается от длины окна, а не от «часов»
        check("шаг подобран под длину окна",
              int(client.params["step"]), (until - since) // 200)

        await prom_range_series(client, "up", 3)
        span = int(client.params["end"]) - int(client.params["start"])
        check("режим «за N часов» тоже работает", abs(span - 3 * 3600) < 5, True)

    asyncio.run(scenario())


def charts_range_route(client) -> None:
    """Эндпоинт графиков отвечает теми границами, которые применил."""
    import time as _time

    now = int(_time.time())
    r = client.get("/api/charts/kemerovo?since=%d&until=%d" % (now - 7200, now))
    check("график за свой интервал отдан", r.status_code, 200)
    data = r.json()
    check("границы возвращены", data["until"] - data["since"], 7200)
    check("длина окна посчитана", round(data["hours"], 2), 2.0)

    # Слишком широкий интервал сужается, и это видно в ответе
    wide = client.get("/api/charts/kemerovo?since=%d&until=%d"
                      % (now - 72 * 3600, now)).json()
    check("широкий интервал сужен", wide["hours"] <= 24.001, True)

    plain = client.get("/api/charts/kemerovo?hours=3").json()
    check("прежний способ не сломан", round(plain["hours"], 2), 3.0)


def range_ui() -> None:
    """Выбор интервала в интерфейсе: подстановка и проверки."""
    app = (ROOT / "web" / "app.js").read_text(encoding="utf-8")
    html = (ROOT / "web" / "index.html").read_text(encoding="utf-8")

    check("в списке периодов есть свой интервал",
          'value="custom"' in html, True)
    check("поля даты есть", html.count('type="datetime-local"'), 2)
    check("предел суток задан в одном месте",
          "RANGE_MAX_HOURS = 24" in app, True)
    for message in ("Конец интервала раньше начала",
                    "Интервал больше суток",
                    "Начало в будущем"):
        if message not in app:
            check("есть объяснение «%s»" % message, False, True)
    check("неверный интервал объясняется словами", True, True)
    check("наружу уходит Unix-время, а не местное",
          "'since=' + state.range.since" in app, True)
    check("печатный отчёт получает тот же интервал",
          "report?cluster=' + encodeURIComponent(name) + '&' + period" in app, True)

    report = (ROOT / "web" / "report.html").read_text(encoding="utf-8")
    check("отчёт умеет подписать интервал",
          "since && until" in report, True)


def websocket(client) -> None:
    """Разговор по WebSocket от начала до конца.

    Модель и сбор метрик подменяются: проверяем протокол и то, что обработчик
    доходит до конца. Именно здесь ломается перенос кода — забытый импорт
    роняет соединение, а внешне это выглядит как «связь прервана».
    """
    from agent.api.routes import chat as chat_routes

    async def fake_context(text, progress=None):
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
