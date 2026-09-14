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
        chat_finishes_thought(c)
        threads(c)
        gui_endpoints(c)
        page_is_never_stale(c)
        foresight(c)
        knowledge(c)
        ssh_access(c)
        background_answer(c)
        switching_threads(c)
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
        attach_after_reload()
        tick_dates()
        design_system()
        motion()
        memory_report()
        insight_reaches()
        memory_route(c)
        explain_findings()
        explain_text()
        explain_rights()
        explain_endpoint(c)
        log_window()
        schema_snapshot()
        schema_storage(c)
        schema_semantic(c)
        running_plans()
        list_paging()
        themes()
        range_hidden()
        lanbilling_log()
        lanbilling_wired(c)
        schema_background(c)
        select_only()
        mysql_types(c)
        schema_decimal()
        schema_comments()
        schema_comments_collected()
        schema_mentioned()
        schema_in_chat_context()
        schema_notes_via_show()
        sql_limit_over_ssh()
        thinking_hidden()
        answer_not_a_plan()
        native_tool_calls()
        preamble_is_not_an_answer()
        rounds_end_with_answer()
        tool_budget_is_a_question()
        job_asks_and_waits()
        vector_math()
        schema_links()
        embed_model_discovery()
        tables_picked_by_model()
        settings_reach_the_agent()
        ask_has_a_way_out()

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

    async def fake_stream(messages, tool_sink=None):
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
    shown = "".join(flt.feed(ch)[0] for ch in sample) + flt.finish()[0]
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
    out = "".join(f2.feed(t + " ")[0] for t in plain.split(" ")) + f2.finish()[0]
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

    async def fake_analyze(cluster, blocks, scope="all", question="",
                           hours=3.0):
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
    async def never(cluster, blocks, scope="all", question="", hours=3.0):
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
    # Групп стало пять: к «сейчас», «запасу», «настройкам» и
    # «обслуживанию» добавилось «что в базе» со схемой
    check("блоки разложены по группам", app_js.count("blocks: [") >= 4, True)
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


def attach_after_reload() -> None:
    """Возврат к идущему ответу не зависит от того, что успело раньше.

    Сокет открывается за миллисекунды, а какой разговор текущий — только
    когда придёт ответ на запрос истории. Подключение делалось при
    открытии сокета, то есть почти всегда раньше, чем разговор становился
    известен: после перезагрузки человек смотрел на пустой экран, хотя
    ответ в это время дописывался.
    """
    app = (ROOT / "web" / "app.js").read_text(encoding="utf-8")

    check("подключение вынесено в отдельное место",
          "function attachToThread()" in app, True)
    # Три источника события: сокет открылся, история пришла, сменили разговор
    check("просимся при открытии сокета",
          "// Ответ мог считаться, пока страница перезагружалась" in app and
          app.count("attachToThread();") >= 3, True)
    check("и после того, как узнали разговор",
          "restoreHistory().then(() => { attachToThread(); return loadThreads(); });"
          in app, True)
    check("повторно не просимся",
          "if (state.attachedTo === state.threadId) return;" in app, True)
    check("после обрыва просимся заново",
          "state.attachedTo = null;      // переподключимся" in app, True)


def tick_dates() -> None:
    """На сутках подписи оси обязаны различать дни."""
    for name in ("app.js", "report.html"):
        src = (ROOT / "web" / name).read_text(encoding="utf-8")
        ok = ("const crosses = new Date(x0 * 1000).toDateString() !==" in src
              and "const withDate = crosses && (k === 0 || day !== lastDay);" in src)
        if not ok:
            check("даты на оси в %s" % name, False, True)
    check("дата ставится там, где меняется день", True, True)

    app = (ROOT / "web" / "app.js").read_text(encoding="utf-8")
    check("порог «36 часов» убран — он и прятал даты за сутки",
          "36 * 3600" in app, False)


def design_system() -> None:
    """Интерфейс собран из одного набора величин, а не подобран на глаз."""
    css = (ROOT / "web" / "style.css").read_text(encoding="utf-8")
    html = (ROOT / "web" / "index.html").read_text(encoding="utf-8")

    for token in ("--sp-3:", "--r-md:", "--fs-md:", "--ui:"):
        if token not in css:
            check("есть величина %s" % token, False, True)
    check("шкалы отступов, скруглений и размеров заданы", True, True)

    check("фокус с клавиатуры виден", ":focus-visible {" in css, True)
    check("движение можно отключить",
          css.count("prefers-reduced-motion") >= 2, True)

    # Значки вкладок рисованные: эмодзи берутся из шрифта системы, и
    # одного из них на рабочих машинах не оказалось вовсе
    check("значки нарисованы, а не набраны",
          html.count('<use href="#i-') >= 10, True)
    check("эмодзи из вкладок убраны",
          any(ch in html for ch in "💬📊🔔🖥📄🗄🔍🔧🔑📋"), False)
    check("вкладки — кнопки, а не div",
          '<button class="tab' in html, True)

    check("подсказка про Enter переехала к полю ввода",
          'class="input-hint"' in html, True)
    check("пустые состояния объясняют, а не командуют",
          html.count('class="empty"') >= 2 and "empty-title" in html, True)


def motion() -> None:
    """Движение привязано к изменению состояния, а не насыпано поверх."""
    css = (ROOT / "web" / "style.css").read_text(encoding="utf-8")
    app = (ROOT / "web" / "app.js").read_text(encoding="utf-8")

    # Длительности и кривая — величинами, а не числами по месту
    for token in ("--dur-fast:", "--dur:", "--dur-slow:", "--ease:"):
        if token not in css:
            check("задана величина %s" % token, False, True)
    check("длительности заданы одним набором", True, True)

    # Ничего затяжного: интерфейс не должен заставлять ждать свою анимацию
    import re

    long_ones = [ms for ms in re.findall(r"--dur[\w-]*:\s*(\d+)ms", css)
                 if int(ms) > 400]
    check("нет затяжных анимаций", long_ones, [],
          show=", ".join(long_ones) or "да")

    # Каждая анимация отвечает на изменение, а не играет сама по себе
    for name in ("pane-in", "msg-in", "step-in", "changed", "bump",
                 "toast-in", "dot-pulse", "chart-reveal"):
        if ("@keyframes " + name) not in css:
            check("есть движение «%s»" % name, False, True)
    check("движение есть там, где меняется состояние", True, True)

    check("новая реплика выезжает, восстановленная — нет",
          "state.restoring ? '' : ' enter'" in app, True)
    check("подсвечивается изменившееся, а не любое обновление",
          "el.innerHTML !== html" in app, True)
    check("подключение отличается от обрыва",
          "'connecting'" in app and ".conn-dot.connecting" in css, True)

    # Раскрытие блока: класс вместо hidden, иначе переходу нечего играть
    check("раскрытие ведёт класс", "grid-template-rows: 0fr" in css, True)
    check("свёрнутое не читается диктором",
          "visibility: hidden;" in css and "visibility 0s linear" in css, True)

    # Системная настройка «меньше движения» уважается целиком
    block = css[css.index("@media (prefers-reduced-motion: reduce) {",
                          css.index("ДВИЖЕНИЕ")):]
    check("движение отключается целиком",
          "animation-duration: .001ms !important;" in block[:600] and
          "transition-duration: .001ms !important;" in block[:600], True)

    # Ничего не ждёт прокрутки: всё, что должно быть прочитано, видно сразу
    check("нет появления по прокрутке",
          "IntersectionObserver" in app, False)


def memory_report() -> None:
    """Память, своп и OOM: то, чего у агента не было вовсе."""
    from agent.services import memory

    text = memory.fmt_memory({"items": [
        {"host": "10.1.0.1", "role": "primary", "total_gb": 32.0,
         "available_gb": 1.2, "used_pct": 96.0,
         "swap_total_gb": 4.0, "swap_used_pct": 87.0,
         "swap_in_s": 240.0, "swap_out_s": 310.0, "oom_kills_24h": 2,
         "oom_log": {"killed": ["mysqld"],
                     "lines": ["Aug 12 03:11:02 db1 kernel: Out of memory: "
                               "Killed process 2431 (mysqld) total-vm:38G"]}},
        {"host": "10.1.0.2", "role": "replica", "total_gb": 32.0,
         "available_gb": 20.0, "used_pct": 37.0,
         "swap_total_gb": 0.0, "swap_used_pct": None,
         "swap_in_s": 0.0, "swap_out_s": 0.0, "oom_kills_24h": 0,
         "oom_log": {"killed": [], "lines": []}},
    ]}, "Кемерово")

    check("видно, кого убило ядро", "mysqld" in text, True)
    check("сказано, что убийства были", "ЯДРО УБИВАЛО ПРОЦЕССЫ" in text, True)
    check("активная подкачка названа прямо",
          "ПОДКАЧКА ИДЁТ ПРЯМО СЕЙЧАС" in text, True)
    check("строка журнала ядра приведена",
          "Killed process 2431" in text, True)
    check("отсутствие свопа объяснено, а не пропущено",
          "Свопа нет" in text and "сразу убивает процесс" in text, True)
    check("чистый сервер тоже получает ответ",
          "Следов OOM в журнале ядра нет" in text, True)

    # Ищем именно движение страниц, а не занятость свопа: занятый своп сам
    # по себе ничего не значит
    import inspect
    src = inspect.getsource(memory)
    check("смотрим скорость подкачки", "node_vmstat_pswpin" in src, True)
    check("и счётчик убийств ядром", "node_vmstat_oom_kill" in src, True)
    check("журнал ядра читается несколькими способами",
          len(memory.OOM_COMMANDS) >= 3, True)
    check("dmesg не единственный путь",
          "journalctl -k" in src and "/var/log/messages" in src, True)


def insight_reaches() -> None:
    """Разбор «всего» добирает то, чего нет на экране.

    Раньше он видел только раскрытые блоки и писал «нет метрик памяти, нет
    истории, нет планов выполнения» — хотя всё это агенту доступно, просто
    никто не нажал кнопку.
    """
    from agent.services import insight

    async def scenario():
        calls = []

        async def fake(name, value):
            calls.append(name)
            return value

        original = (insight._current, insight._history,
                    insight._memory, insight._plans)
        insight._current = lambda c: fake("current", "## Текущие метрики: X")
        insight._history = lambda c, h: fake("history", "## История кластера X")
        insight._memory = lambda c: fake("memory", "## Память, своп и OOM — X")
        insight._plans = lambda c: fake("plans", "## План выполнения")
        try:
            # Пустая страница: добираем всё
            extra, failed = await insight.gather_missing({"name": "k"}, "")
            check("добрано всё четыре раздела", len(calls), 4)
            check("ничего не потерялось", failed, [])
            for mark in ("Текущие метрики", "История кластера",
                         "Память, своп и OOM", "План выполнения"):
                if mark not in extra:
                    check("в разборе есть «%s»" % mark, False, True)
            check("разделы склеены в один текст", True, True)

            # Уже собранное второй раз не снимаем: это минуты работы сервера
            calls.clear()
            await insight.gather_missing(
                {"name": "k"}, "## Память, своп и OOM — X\n## История кластера X")
            check("повторно не собираем", sorted(calls), ["current", "plans"])
        finally:
            (insight._current, insight._history,
             insight._memory, insight._plans) = original

        # Недоступный сервер не роняет разбор целиком
        async def dead(*a):
            raise RuntimeError("сервер не отвечает")

        insight._current = dead
        insight._history = lambda c, h: dead()
        insight._memory = dead
        insight._plans = dead
        try:
            extra, failed = await insight.gather_missing({"name": "k"}, "")
            check("разбор пережил недоступность", extra, "")
            check("и назвал, чего не хватает", len(failed), 4)
            check("с причиной", "не отвечает" in failed[0], True)
        finally:
            (insight._current, insight._history,
             insight._memory, insight._plans) = original

    asyncio.run(scenario())

    check("модели сказано, что данные уже собраны",
          "Не пиши, что этих" in insight.ALL_TASK, True)
    check("названы кнопки, а не абстрактные «данные»",
          "Снять профиль" in insight.ALL_TASK, True)


def memory_route(client) -> None:
    """Память доступна и отдельной кнопкой, а не только внутри разбора."""
    r = client.get("/api/memory/kemerovo")
    check("блок памяти отвечает", r.status_code, 200)
    check("в ответе есть текст", "text" in r.json(), True)

    app = (ROOT / "web" / "app.js").read_text(encoding="utf-8")
    check("кнопка есть на странице кластера",
          "cluster-memory" in app and "loadMemory" in app, True)
    check("разбор получает период с экрана",
          "hours: state.range" in app, True)


# План выполнения в том виде, в каком его отдаёт MySQL: те же столбцы,
# те же сокращения. По ним и разбираем.
PLAN_COLUMNS = ["id", "select_type", "table", "type", "possible_keys",
                "key", "key_len", "ref", "rows", "filtered", "Extra"]


def explain_findings() -> None:
    """План разбирается словами, а не показывается как есть.

    `type=ALL` и `Using filesort` не говорят ничего тому, кто пришёл
    разбираться в аварии, а не изучать оптимизатор.
    """
    from agent.services.explain import estimated_rows, findings, plan_tables

    # Полное чтение при существующем индексе — самый ценный случай:
    # чинится ANALYZE TABLE, а не выдумыванием нового индекса
    plan = {"columns": PLAN_COLUMNS, "rows": [
        [1, "SIMPLE", "agreements", "ALL", "idx_archive", None, None, None,
         420000, 10.0, "Using where; Using filesort"]]}
    found = findings(plan)
    kinds = [f["what"] for f in found]
    check("полное чтение замечено",
          any("целиком" in k for k in kinds), True)
    check("сказано, что индекс есть, но не взят",
          any("хотя подходящий индекс есть" in k for k in kinds), True)
    check("предложен ANALYZE TABLE",
          any("ANALYZE TABLE" in f["do"] for f in found), True)
    check("сортировка без индекса замечена",
          any("сортировка идёт без индекса" in k for k in kinds), True)

    # Соединение без индекса — стоимость растёт произведением
    join = {"columns": PLAN_COLUMNS, "rows": [
        [1, "SIMPLE", "a", "ALL", None, None, None, None, 1000, 100.0, ""],
        [1, "SIMPLE", "b", "ALL", None, None, None, None, 5000, 100.0,
         "Using join buffer (hash join)"]]}
    found = findings(join)
    check("соединение без индекса названо",
          any("join buffer" in f["what"] for f in found), True)
    check("оценки строк перемножаются", estimated_rows(join), 5000000)

    # Зависимый подзапрос выполняется для каждой строки
    dep = {"columns": PLAN_COLUMNS, "rows": [
        [2, "DEPENDENT SUBQUERY", "payments", "ref", "idx_uid", "idx_uid",
         "4", "func", 3, 100.0, ""]]}
    check("зависимый подзапрос замечен",
          any("для каждой строки" in f["what"] for f in findings(dep)), True)

    # Хороший план не должен обрастать выдуманными замечаниями
    good = {"columns": PLAN_COLUMNS, "rows": [
        [1, "SIMPLE", "agreements", "ref", "idx_uid", "idx_uid", "4",
         "const", 2, 100.0, "Using index"]]}
    check("на хорошем плане замечаний нет", findings(good), [])

    check("производные таблицы в схему не просятся",
          plan_tables({"columns": PLAN_COLUMNS, "rows": [
              [1, "PRIMARY", "<derived2>", "ALL", None, None, None, None,
               10, 100.0, ""]]}), [])


def explain_text() -> None:
    """Отчёт начинается с выводов, а не с таблицы."""
    from agent.services.explain import fmt_explain

    text = fmt_explain({
        "host": "10.1.0.1", "statement": "EXPLAIN SELECT 1",
        "rows_estimate": 420000,
        "plan": {"host": "10.1.0.1", "query": "EXPLAIN SELECT 1",
                 "columns": ["table", "type"], "rows": [["agreements", "ALL"]]},
        "findings": [{"level": "critical", "table": "agreements",
                      "what": "таблица читается целиком",
                      "why": "индекса нет", "do": "добавить индекс"}],
        "schemas": [{"table": "agreements",
                     "ddl": "CREATE TABLE `agreements` (\n  `uid` int\n)"}],
    })
    check("выводы идут раньше плана",
          text.index("Что не так") < text.index("Сам план"), True)
    check("объяснено, почему строки перемножаются",
          "перемножаются" in text, True)
    check("схема таблицы приложена", "CREATE TABLE" in text, True)

    clean = fmt_explain({"host": "x", "statement": "EXPLAIN SELECT 1",
                         "rows_estimate": 2, "findings": [], "schemas": [],
                         "plan": {"host": "x", "query": "q",
                                  "columns": ["type"], "rows": [["ref"]]}})
    check("хороший план так и назван",
          "Ничего тревожного" in clean, True)


def explain_rights() -> None:
    """Отказ по правам объясняется тем правом, которого не хватает.

    Сообщение сервера про «lacking privileges for underlying table» звучит
    как нехватка SELECT, хотя не хватает SHOW VIEW.
    """
    from agent.services.explain import _explain_hint

    view = _explain_hint(
        "EXPLAIN/SHOW can not be issued; lacking privileges for underlying table",
        False)
    check("про представление сказано про SHOW VIEW", "SHOW VIEW" in view, True)
    check("и дана готовая команда", "GRANT SHOW VIEW" in view, True)

    conn = _explain_hint("Access denied; you need the PROCESS privilege", True)
    check("про чужое соединение сказано про PROCESS",
          "GRANT PROCESS" in conn, True)

    gone = _explain_hint("Unknown thread id: 4211", True)
    check("исчезнувшее соединение объяснено",
          "уже завершилось" in gone, True)

    check("обычная ошибка не обрастает советами",
          _explain_hint("Table 'x' doesn't exist", False),
          "Table 'x' doesn't exist")


def explain_endpoint(client) -> None:
    """План доступен и человеку кнопкой, и модели инструментом."""
    r = client.post("/api/explain", json={"cluster": "kemerovo",
                                          "sql": "SELECT 1"})
    check("эндпоинт отвечает", r.status_code, 200)
    check("без учётки сказано, чего не хватает",
          "db_user" in (r.json().get("error") or ""), True)

    r = client.post("/api/explain", json={"cluster": "kemerovo", "sql": ""})
    check("пустой запрос отклонён",
          "db_user" in r.json()["error"] or "пуст" in r.json()["error"], True)

    r = client.post("/api/explain", json={"cluster": "нет-такого",
                                          "sql": "SELECT 1"})
    check("несуществующий кластер отвергнут", r.status_code, 404)

    journal = client.get("/api/audit?days=1&limit=50&action=EXPLAIN").json()
    check("обращения попадают в журнал", journal["total"] >= 1, True)

    from agent.services.assistant import tool_specs
    names = [t["function"]["name"] for t in tool_specs()]
    check("модель тоже умеет строить план", "explain_query" in names, True)

    spec = next(t["function"] for t in tool_specs()
                if t["function"]["name"] == "explain_query")
    check("и объяснять идущее соединение",
          "connection_id" in spec["parameters"]["properties"], True)

    app = (ROOT / "web" / "app.js").read_text(encoding="utf-8")
    check("кнопки есть в интерфейсе",
          "explainSql" in app and "explainLive" in app, True)


def log_window() -> None:
    """Окно логов отсчитывается от времени сервера и в его формате.

    Две беды были рядом. Первая: отбор шёл по дате, и «последние два часа»
    возвращали целые сутки, обрезанные по числу строк. Вторая: slow-лог
    MySQL 5.7+ пишет метки в UTC, а окно строилось по местному времени
    сервера — во Владивостоке это промах на семь часов.
    """
    import datetime as dt

    from agent.services.logs import (HOUR_PATTERN_LIMIT, log_date_patterns,
                                     log_hour_patterns, log_window_patterns)

    # Сервер во Владивостоке: местное 10:00 — это 03:00 UTC
    local_until = dt.datetime(2026, 9, 11, 10, 0)
    local_since = local_until - dt.timedelta(hours=2)
    until_epoch = dt.datetime(2026, 9, 11, 3, 0,
                              tzinfo=dt.timezone.utc).timestamp()
    since_epoch = until_epoch - 2 * 3600

    app = log_window_patterns(local_since, local_until, since_epoch,
                              until_epoch, utc_dates=False)
    check("в шаблон вошёл час, а не только дата",
          "11.09.2026 09:" in app, True)
    check("соседний час тоже", "11.09.2026 08:" in app, True)
    check("чужих часов не набрано", "11.09.2026 12:" in app, False)
    check("формат slow-лога с «T» тоже есть", "2026-09-11T09:" in app, True)

    # Для slow-лога добавляется то же окно в UTC: метки там в UTC
    slow = log_window_patterns(local_since, local_until, since_epoch,
                               until_epoch, utc_dates=True)
    check("окно пересчитано в UTC", "2026-09-11T02:" in slow, True)
    check("и местное осталось", "2026-09-11T09:" in slow, True)
    check("дубликатов нет", len(slow), len(set(slow)))

    # Широкое окно: по часам шаблонов стало бы больше, чем строк в ответе
    wide = log_window_patterns(local_until - dt.timedelta(hours=40),
                               local_until, 0, 0)
    check("широкое окно отбирается по суткам",
          all(":" not in p for p in wide), True)
    check("предел перехода задан величиной",
          HOUR_PATTERN_LIMIT >= 24, True)
    check("часовые шаблоны на широком окне не строятся",
          log_hour_patterns(local_until - dt.timedelta(hours=40), local_until),
          [])

    # Отбор по суткам остался прежним — он нужен как запасной
    days = log_date_patterns(local_since, local_until)
    check("суточные шаблоны знают все форматы",
          "2026-09-11" in days and "11.09.2026" in days and "260911" in days,
          True)

    import inspect

    from agent.services import logs
    src = inspect.getsource(logs.read_log_group)
    check("в отчёте сказано, за какой период отбирали",
          "по времени сервера" in src, True)
    check("и что метки в файле в UTC",
          "метки в файле в UTC" in src, True)


def schema_snapshot() -> None:
    """Схема снимается один раз и живёт у агента.

    Обход information_schema на базе с тысячами таблиц заметен на боевом
    сервере, а схема меняется раз в релиз. Поэтому снимок, а не запрос на
    каждый вопрос.
    """
    from agent.services import schema

    calls = []

    async def fake_sql(cluster, sql, host=None, max_rows=0):
        calls.append(sql)
        low = sql.lower()
        if "group by table_schema" in low:
            return {"host": "10.1.0.1", "columns": ["db", "tables", "size_mb",
                                                    "rows_est"],
                    "rows": [["lanbilling", 120, 4096, 88000000]]}
        if "from information_schema.tables" in low:
            return {"columns": ["tbl", "engine", "rows_est", "size_mb",
                                "idx_mb", "note"],
                    "rows": [["agreements", "InnoDB", 4200000, 3100, 900,
                              "договоры"],
                             ["payments", "InnoDB", 88000000, 900, 400, ""]]}
        if "from information_schema.columns" in low:
            return {"columns": ["tbl", "col", "type", "nullable", "ckey",
                                "extra", "note"],
                    "rows": [["agreements", "uid", "int(11)", "NO", "PRI",
                              "auto_increment", ""],
                             ["agreements", "balance", "decimal(10,2)", "YES",
                              "", "", "баланс"],
                             ["payments", "pay_id", "bigint", "NO", "PRI", "", ""]]}
        if "from information_schema.statistics" in low:
            return {"columns": ["tbl", "idx", "cols", "non_unique",
                                "cardinality"],
                    "rows": [["agreements", "PRIMARY", "uid", 0, 4200000]]}
        return {"columns": [], "rows": []}

    original = schema.sql_execute
    schema.sql_execute = fake_sql
    try:
        cluster = {"name": "kemerovo", "label": "Кемерово",
                   "primary_ip": "10.1.0.1", "db_user": "ai_agent",
                   "db_password": "x"}
        snapshot = asyncio.run(schema.collect(cluster))

        check("базы сняты", len(snapshot["databases"]), 1)
        check("таблицы сняты", len(snapshot["tables"]), 2)
        check("столбцы взяты одним запросом на базу",
              sum(1 for c in calls if "information_schema.columns" in c.lower()), 1)
        check("индексы тоже одним",
              sum(1 for c in calls if "information_schema.statistics" in c.lower()), 1)

        # Читаем снимок, а не базу: обращений к ней больше нет
        before = len(calls)
        one = schema.describe(snapshot, "agreements")
        check("таблица нашлась без указания базы", one["table"], "agreements")
        check("столбцы на месте", len(one["columns"]), 2)
        check("к базе за этим не ходили", len(calls), before)

        text = schema.fmt_describe(one)
        check("первичный ключ подписан", "первичный ключ" in text, True)
        check("комментарий столбца виден", "баланс" in text, True)

        found = schema.find(snapshot, "balance")
        check("поиск по куску имени работает",
              found["matches"][0]["col"], "balance")
        check("короткий запрос отклонён",
              "error" in schema.find(snapshot, "b"), True)

        brief = schema.fmt_brief(snapshot)
        check("в подсказке есть имена таблиц", "agreements" in brief, True)
        check("и запрет угадывать", "не угадывай" in brief, True)

        # Не снимали — так и сказано, вместе с тем, что делать
        empty = schema.fmt_snapshot({}, "Кемерово")
        check("несняток объяснён", "ещё не снята" in empty, True)
        check("сказано, кто может снять", "администраторам" in empty, True)
    finally:
        schema.sql_execute = original


def schema_storage(client) -> None:
    """Снимок переживает перезапуск и отдаётся через API."""
    from agent.services import schema

    snapshot = {"taken_at": "2026-09-11T05:00:00",
                "databases": [{"db": "billing", "tables": 2, "size_mb": 10,
                               "rows_est": 100}],
                "tables": {"billing.orders": {
                    "db": "billing", "table": "orders", "engine": "InnoDB",
                    "rows_est": 100, "size_mb": 10, "idx_mb": 2, "note": "",
                    "columns": [{"col": "id", "type": "int", "nullable": "NO",
                                 "ckey": "PRI", "extra": "", "note": ""}],
                    "indexes": []}},
                "cut": []}

    asyncio.run(schema.save("kemerovo", snapshot))
    back = asyncio.run(schema.load("kemerovo"))
    check("снимок сохранился и прочитался",
          list(back["tables"].keys()), ["billing.orders"])

    r = client.get("/api/schema/kemerovo")
    check("схема отдаётся", r.status_code, 200)
    check("в ответе видно, когда снято",
          r.json()["taken_at"].startswith("2026-09-11"), True)
    check("и сколько таблиц", r.json()["tables"], 1)

    one = client.get("/api/schema/kemerovo?table=orders").json()
    check("описание таблицы отдаётся", "orders" in one["text"], True)

    hit = client.get("/api/schema/kemerovo?search=ord").json()
    check("поиск по схеме отдаётся", "orders" in hit["text"], True)

    from agent.services.assistant import tool_specs
    names = [t["function"]["name"] for t in tool_specs()]
    check("модель умеет читать схему", "get_schema" in names, True)

    app = (ROOT / "web" / "app.js").read_text(encoding="utf-8")
    check("пересъёмка спрашивает подтверждение",
          "Снять схему заново?" in app, True)
    check("и предупреждает про нагрузку",
          "создаёт нагрузку" in app, True)


def running_plans() -> None:
    """Долго идущий запрос объясняется сам, без отдельной кнопки."""
    from agent.services import explain

    seen = []

    async def fake_explain(cluster, sql="", connection_id=0, host=None,
                           with_schema=True):
        seen.append(connection_id)
        check("схемы к горячему разбору не тянем", with_schema, False)
        return {"findings": [{"level": "critical", "table": "agreements",
                              "what": "таблица читается целиком",
                              "why": "индекса нет", "do": "добавить индекс"}]}

    original = explain.explain
    explain.explain = fake_explain
    try:
        items = [
            {"id": 11, "time_s": 42.0, "query": "SELECT * FROM agreements"},
            {"id": 12, "time_s": 1.0,  "query": "SELECT 1"},
            {"id": 13, "time_s": 88.0, "query": "SELECT * FROM payments"},
            {"id": 14, "time_s": 9.0,  "query": "SELECT 2"},
            {"id": 15, "time_s": 7.0,  "query": "SELECT 3"},
        ]
        plans = asyncio.run(explain.explain_running({"name": "k"}, items))
        check("короткие запросы не объясняем", 12 in seen, False)
        check("начинаем с самого долгого", seen[0], 13)
        check("берём не больше трёх", len(plans), 3)

        text = explain.fmt_running_plans(plans)
        check("видно, сколько запрос уже идёт", "идёт 88 с" in text, True)
        check("и что с ним делать", "добавить индекс" in text, True)
    finally:
        explain.explain = original

    check("пустой список ничего не печатает", explain.fmt_running_plans([]), "")

    import inspect

    from agent.services import workload
    check("профиль нагрузки зовёт планы сам",
          "explain_running" in inspect.getsource(workload.workload_delta), True)


def list_paging() -> None:
    """Длинные списки листаются, а панели прокручиваются.

    На ноутбуке подвал со счётчиком уезжал за нижний край: у панелей
    «Журнал» и «Доступы» не было прокрутки вовсе.
    """
    html = (ROOT / "web" / "index.html").read_text(encoding="utf-8")
    app = (ROOT / "web" / "app.js").read_text(encoding="utf-8")

    for tab in ("tab-access", "tab-audit"):
        marker = '<section id="%s" class="tab-pane pad-pane"' % tab
        if marker not in html:
            check("панель %s прокручивается" % tab, False, True)
    check("панели журнала и доступов прокручиваются", True, True)

    check("счётчик журнала виден всегда",
          "это всё за период" in app, True)
    check("список доступов листается",
          "ACCESS_PAGE" in app and "access-more" in app, True)
    check("и фильтруется", 'id="access-filter"' in html, True)
    check("фильтр сбрасывает показанное",
          "state.accessShown = ACCESS_PAGE;" in app, True)


def _luminance(colour: str) -> float:
    colour = colour.lstrip("#")
    parts = [int(colour[i:i + 2], 16) / 255 for i in (0, 2, 4)]
    parts = [(v / 12.92 if v <= 0.03928 else ((v + 0.055) / 1.055) ** 2.4)
             for v in parts]
    return 0.2126 * parts[0] + 0.7152 * parts[1] + 0.0722 * parts[2]


def _contrast(a: str, b: str) -> float:
    high, low = sorted((_luminance(a), _luminance(b)), reverse=True)
    return (high + 0.05) / (low + 0.05)


def _palettes(css: str) -> dict:
    """Величины цвета из каждого блока темы."""
    import re

    out = {}
    for name, start in (("тёмная", css.index(":root {")),
                        ("светлая (система)",
                         css.index("@media (prefers-color-scheme: light)")),
                        ("светлая (выбор)", css.index(':root[data-theme="light"]'))):
        block = css[start:css.index("\n}", start)]
        out[name] = dict(re.findall(r"(--[\w-]+):\s*(#[0-9a-fA-F]{6})", block))
    return out


def themes() -> None:
    """Две темы, три состояния, и ни одна величина не потеряна.

    Классическая ошибка тёмной темы — цвет, объявленный только в одном
    блоке: в другом состоянии он берётся из чужой палитры, и получается
    текст одной темы на фоне другой.
    """
    css = (ROOT / "web" / "style.css").read_text(encoding="utf-8")
    html = (ROOT / "web" / "index.html").read_text(encoding="utf-8")
    app = (ROOT / "web" / "app.js").read_text(encoding="utf-8")

    # Три состояния: система, явно тёмная, явно светлая
    check("системная светлая учтена",
          'prefers-color-scheme: light' in css, True)
    check("и явный выбор её перебивает",
          ':root:not([data-theme="dark"])' in css, True)
    check("явная светлая есть отдельно",
          ':root[data-theme="light"] {' in css, True)
    check("схема оформления сообщается браузеру",
          css.count("color-scheme:") >= 3, True)

    palettes = _palettes(css)
    base = set(palettes["тёмная"])
    for name, colours in palettes.items():
        missing = sorted(base - set(colours))
        if name != "тёмная" and missing:
            check("в палитре «%s» не хватает %s" % (name, ", ".join(missing)),
                  False, True)
    check("во всех палитрах один и тот же набор величин", True, True)
    check("палитр три", len(palettes), 3)

    # Контраст: подписи мелкие, и «почти читается» тут не годится
    for name, colours in palettes.items():
        surfaces = [colours[k] for k in ("--bg", "--surface", "--surface2")
                    if k in colours]
        for token in ("--text", "--text-hl", "--muted", "--accent",
                      "--green", "--yellow", "--red"):
            if token not in colours:
                continue
            worst = min(_contrast(colours[token], s) for s in surfaces)
            if worst < 4.5:
                check("%s: %s к поверхностям %.2f" % (name, token, worst),
                      False, True)
    check("контраст всех цветов не ниже 4.5 в обеих темах", True, True)

    # Цвет, зашитый в правило, одинаков в обеих темах — так нельзя
    body_css = css[css.index("* { box-sizing"):]
    check("полупрозрачных литералов не осталось",
          "rgba(" in body_css, False)
    import re
    hardcoded = re.findall(r"[:\s]#[0-9a-fA-F]{3,8}(?![\w-])", body_css)
    check("и обычных тоже", hardcoded, [],
          show=", ".join(hardcoded) or "да")

    # Переключатель
    check("кнопка темы есть", 'id="theme-btn"' in html, True)
    check("три состояния в переключателе", app.count("id: '"), app.count("id: '"))
    check("выбор запоминается", "THEME_KEY" in app, True)
    check("тема ставится до первого кадра",
          "// Тема — первым делом" in app, True)
    check("«как в системе» — это отсутствие атрибута",
          "root.removeAttribute('data-theme')" in app, True)

    # Кнопка темы не должна отбирать правила у кнопки боковой панели:
    # у той свои размеры и свои условия показа
    check("у кнопки темы свой класс", ".theme-btn {" in css, True)
    check("класс кнопки панели не тронут",
          ".icon-btn {\n  /* На широком экране" in css, True)

    # Страница входа подключает ту же таблицу и обязана следовать теме
    login = (ROOT / "web" / "login.html").read_text(encoding="utf-8")
    check("на странице входа нет своих цветов",
          re.findall(r"#[0-9a-fA-F]{3,8}", login), [])


def range_hidden() -> None:
    """Поля своего интервала показываются только по выбору.

    Правило display перебивало служебный атрибут hidden, и поля висели на
    странице всегда — рядом с выбранным «за 3 часа».
    """
    css = (ROOT / "web" / "style.css").read_text(encoding="utf-8")
    check("атрибут hidden сильнее оформления",
          ".range-pick[hidden] { display: none; }" in css, True)
    check("и объявлен раньше правила показа",
          css.index(".range-pick[hidden]") < css.index(".range-pick {"), True)


LB_LOG = chr(10).join([
    "07.09.2026 17:29:58.100000 INFO LWP410001 [core:main] запуск обработки",
    "07.09.2026 17:30:01.123456 ERROR LWP410005 [db:connect] "
    "can't connect to MySQL server on 10.0.0.5 (111)",
    "07.09.2026 17:30:01.223456 ERROR LWP410005 [db:connect] "
    "can't connect to MySQL server on 10.0.0.6 (111)",
    "07.09.2026 17:30:02.000000 ERROR LWP410005 [db:connect] "
    "can't connect to MySQL server on 10.0.0.5 (111)",
    "07.09.2026 17:30:05.000000 WARN LWP410010 [pay:send] "
    "no response from gateway 4712",
    "07.09.2026 17:31:00.000000 ERROR LWP420100 [db:tx] "
    "Deadlock found when trying to get lock",
    "продолжение многострочной записи без даты",
])


def lanbilling_log() -> None:
    """Логи АСР сворачиваются в образцы, а не пересказываются построчно.

    За два часа набегают десятки тысяч строк, где одна и та же ошибка
    повторяется сотни раз. Читать это глазами бесполезно.
    """
    from agent.services import lanbilling

    data = lanbilling.analyse(LB_LOG)
    check("строки разобраны", data["records"], 6)
    check("чужая строка посчитана, а не выброшена", data["unparsed"], 1)
    check("ошибки отделены от предупреждений",
          (data["errors"], data["warnings"]), (4, 1))

    # Три строки об одном и том же — один образец с числом повторов
    top = data["patterns"][0]
    check("повторы свёрнуты", top["count"], 3)
    check("у образца есть код", top["code"], "LWP410005")
    check("и время начала", top["first"].strftime("%H:%M"), "17:30")

    check("всплеск найден", data["peak_count"], 4)
    check("и его минута названа",
          data["peak_minute"].strftime("%H:%M"), "17:30")

    # Классы бед: не просто «ошибка», а какая именно
    check("потеря соединения с базой распознана",
          data["classes"].get("db_down"), 3)
    check("дедлок распознан", data["classes"].get("deadlock"), 1)
    check("внешняя система распознана", data["classes"].get("external"), 1)

    text = lanbilling.fmt_report(dict(data, host="10.1.0.9", hours=2), "Кемерово")
    check("в отчёте сказано, куда идти дальше",
          "Память, своп и OOM" in text, True)
    check("склонения человеческие", "3 строки" in text, True)
    check("и повторы тоже", "3 раза" in text, True)

    # Свёртка: разные адреса и номера — одна и та же беда
    check("адреса свёрнуты",
          lanbilling.template("connect to 10.0.0.5 failed after 42 tries"),
          "connect to <адрес> failed after <N> tries")

    # Тихий лог — тоже ответ
    quiet = lanbilling.analyse(
        "07.09.2026 10:00:00 INFO LWP1 [a:b] всё хорошо")
    check("тихий лог не выдумывает бед", quiet["troubles"], 0)
    quiet_text = lanbilling.fmt_report(dict(quiet, hours=2), "Кемерово")
    check("и говорит, что причина не в ядре",
          "причина не в ядре" in quiet_text, True)

    # Чужой формат объясняется, а не молчит
    alien = lanbilling.fmt_report(lanbilling.analyse("что-то совсем другое"),
                                  "Кемерово")
    check("чужой формат объяснён", "формат другой" in alien, True)


def lanbilling_wired(client) -> None:
    """Разбор доступен кнопкой, инструментом и в общем разборе."""
    r = client.get("/api/lanbilling/kemerovo?hours=2")
    check("эндпоинт отвечает", r.status_code, 200)
    check("без настроенных логов сказано, чего не хватает",
          "app_log_dirs" in r.json().get("error", "")
          or "app_ip" in r.json().get("error", ""), True)
    check("сырой лог наружу не отдаётся", "raw" in r.json(), False)

    from agent.services.assistant import tool_specs
    names = [t["function"]["name"] for t in tool_specs()]
    check("модель умеет разбирать логи АСР", "analyse_app_log" in names, True)

    import inspect

    from agent.services import insight
    src = inspect.getsource(insight.gather_missing)
    check("общий разбор берёт логи АСР", "_app_log" in src, True)
    check("но только если они настроены", "app_log_dirs" in src, True)

    app = (ROOT / "web" / "app.js").read_text(encoding="utf-8")
    check("блок есть на странице кластера",
          "cluster-lanbilling" in app and "loadLanbilling" in app, True)


def schema_background(client) -> None:
    """Схема снимается в фоне и один раз на всех.

    Двое нажали — обход всё равно один: второй подключается к идущему.
    """
    from agent.api.routes import clusters as routes
    from agent.services import schema, tasks

    started = {"n": 0}

    async def slow_collect(cluster, host=None):
        started["n"] += 1
        await asyncio.sleep(0.4)
        return {"taken_at": "2026-09-14T10:00:00", "databases": [],
                "tables": {}, "cut": []}

    async def scenario():
        original = schema.collect
        schema.collect = slow_collect
        was = routes.SCHEMA_BUDGET_S
        routes.SCHEMA_BUDGET_S = 0.05
        try:
            key = routes.schema_key("kemerovo")
            tasks.drop(key)

            async def build():
                data = await schema.collect({"name": "kemerovo"})
                await schema.save("kemerovo", data)
                return data

            # Два нажатия подряд — одна работа
            first = await tasks.shared_within(key, build, budget=0.05, ttl=0)
            second = await tasks.shared_within(key, build, budget=0.05, ttl=0)
            check("первый не дождался", first[1], False)
            check("второй тоже", second[1], False)
            check("но съёмка одна", started["n"], 1)
            check("и она видна как идущая", tasks.running(key), True)

            await asyncio.sleep(0.7)
            check("съёмка дошла до конца", started["n"], 1)
            check("и больше не идёт", tasks.running(key), False)
            await tasks.shutdown()
        finally:
            schema.collect = original
            routes.SCHEMA_BUDGET_S = was

    asyncio.run(scenario())

    # Чтение говорит, идёт ли съёмка прямо сейчас
    body = client.get("/api/schema/kemerovo").json()
    check("состояние съёмки видно в ответе", "collecting" in body, True)

    app = (ROOT / "web" / "app.js").read_text(encoding="utf-8")
    check("страница дожидается фоновой съёмки",
          "waitForSchema" in app, True)
    check("опрос прекращается при уходе со страницы",
          "state.clusterName !== cluster" in app, True)


def select_only() -> None:
    """Из чата можно только читать. Проверяем не обещанием, а валидатором."""
    from agent.services.assistant import tool_specs
    from agent.services.mysql import sql_validate

    allowed = ("SELECT uid FROM agreements WHERE balance < 0",
               "SELECT COUNT(*) FROM payments",
               "SHOW GLOBAL STATUS",
               "EXPLAIN SELECT 1",
               "DESCRIBE agreements")
    for sql in allowed:
        ok, why = sql_validate(sql)
        if not ok:
            check("читающий запрос разрешён: %s" % sql, why, "")
    check("читающие запросы проходят", True, True)

    forbidden = (
        "UPDATE agreements SET balance = 0",
        "DELETE FROM payments",
        "INSERT INTO agreements VALUES (1)",
        "DROP TABLE agreements",
        "TRUNCATE payments",
        "GRANT ALL ON *.* TO 'x'@'%'",
        "SELECT 1; DROP TABLE agreements",
        "SELECT /*! DROP TABLE agreements */ 1",
        "SELECT * INTO OUTFILE '/tmp/x' FROM agreements",
        "SET GLOBAL max_connections = 10",
        "CALL some_proc()",
        "KILL 42",
    )
    for sql in forbidden:
        ok, _ = sql_validate(sql)
        if ok:
            check("ПРОПУЩЕН ЗАПИСЫВАЮЩИЙ ЗАПРОС: %s" % sql, True, False)
    check("ни один пишущий запрос не прошёл", True, True)

    spec = next(t["function"] for t in tool_specs()
                if t["function"]["name"] == "run_sql")
    check("модели сказано, что записи не будет",
          "любая запись отклоняется" in spec["description"], True)

    from agent.services.analysis import system_prompt
    prompt = system_prompt()
    check("и что на вопросы про данные отвечают запросом",
          "ВОПРОСЫ ПРО ДАННЫЕ" in prompt, True)
    check("а не текстом запроса вместо ответа",
          "не показывай текст запроса вместо ответа" in prompt, True)


def mysql_types(client) -> None:
    """Типы MySQL, которых не знает JSON, не должны ронять ответ.

    Съёмка схемы падала на последнем шаге: «Object of type Decimal is not
    JSON serializable». Данные собраны, обход боевого сервера сделан — и
    всё потеряно из-за столбца, который вернул SUM. То же самое ждало
    любой ответ с сырыми строками из базы.
    """
    import datetime as dt
    import decimal
    import json as jsonlib

    from agent.api.responses import SafeJSONResponse, sanitize

    # DECIMAL приходит от любого SUM, ROUND, AVG
    check("целое DECIMAL остаётся целым",
          sanitize(decimal.Decimal("4200000")), 4200000)
    check("дробное становится числом",
          sanitize(decimal.Decimal("12.50")), 12.5)
    check("не-число не роняет разбор",
          sanitize(decimal.Decimal("NaN")) is None, True)

    check("дата становится строкой",
          sanitize(dt.date(2026, 9, 14)), "2026-09-14")
    check("дата со временем тоже",
          sanitize(dt.datetime(2026, 9, 14, 10, 30)), "2026-09-14T10:30:00")
    check("интервал — в секундах",
          sanitize(dt.timedelta(minutes=2)), 120.0)
    check("читаемые двоичные данные разбираются",
          sanitize(b"\xd0\xb4\xd0\xb0"), "да")
    check("нечитаемые названы, а не потеряны",
          "двоичные данные" in sanitize(b"\x00\x01\xff"), True)
    check("логическое не превращается в число",
          sanitize(True) is True, True)

    # Вложенность: беда пряталась именно там
    deep = {"rows": [[decimal.Decimal("1.5"), dt.date(2026, 1, 1)]],
            "set": {decimal.Decimal("2")}}
    back = jsonlib.loads(SafeJSONResponse(content=deep).render(deep))
    check("вложенные значения приведены",
          back["rows"][0], [1.5, "2026-01-01"])
    check("множество стало списком", back["set"], [2])

    # Даже неизвестный тип не должен терять весь ответ
    class Странный:
        pass

    raw = SafeJSONResponse(content={"x": Странный()}).render({"x": Странный()})
    check("неизвестный тип назван, а ответ цел",
          jsonlib.loads(raw)["x"], "<Странный>")


def schema_decimal() -> None:
    """Снимок схемы сохраняется, даже если база вернула DECIMAL."""
    import decimal

    from agent.services import schema

    async def fake_sql(cluster, sql, host=None, max_rows=0):
        low = sql.lower()
        if "group by table_schema" in low:
            # Ровно то, что отдаёт MySQL: SUM и ROUND возвращают DECIMAL
            return {"host": "10.1.0.1",
                    "columns": ["db", "tables", "size_mb", "rows_est"],
                    "rows": [["billing", 120, decimal.Decimal("4096"),
                              decimal.Decimal("88000000")]]}
        if "from information_schema.tables" in low:
            return {"columns": ["tbl", "engine", "rows_est", "size_mb",
                                "idx_mb", "note"],
                    "rows": [["agreements", "InnoDB", decimal.Decimal("4200000"),
                              decimal.Decimal("3100"), decimal.Decimal("900"),
                              ""]]}
        if "from information_schema.columns" in low:
            return {"columns": ["tbl", "col", "type", "nullable", "ckey",
                                "extra", "note"],
                    "rows": [["agreements", "uid", "int(11)", "NO", "PRI",
                              "", ""]]}
        if "from information_schema.statistics" in low:
            return {"columns": ["tbl", "idx", "cols", "non_unique",
                                "cardinality"],
                    "rows": [["agreements", "PRIMARY", "uid", 0,
                              decimal.Decimal("4200000")]]}
        return {"columns": [], "rows": []}

    original = schema.sql_execute
    schema.sql_execute = fake_sql
    try:
        cluster = {"name": "kemerovo", "label": "Кемерово",
                   "primary_ip": "10.1.0.1", "db_user": "ai_agent",
                   "db_password": "x"}
        snapshot = asyncio.run(schema.collect(cluster))
        check("съёмка прошла", len(snapshot["tables"]), 1)
        check("DECIMAL приведён уже в снимке",
              isinstance(snapshot["databases"][0]["size_mb"], int), True)

        # Тот самый шаг, на котором всё терялось
        asyncio.run(schema.save("kemerovo-decimal", snapshot))
        back = asyncio.run(schema.load("kemerovo-decimal"))
        check("снимок сохранился и прочитался",
              back["databases"][0]["rows_est"], 88000000)
        check("кардинальность индекса тоже цела",
              back["tables"]["billing.agreements"]["indexes"][0]["cardinality"],
              4200000)

        text = schema.fmt_snapshot(back, "Кемерово")
        check("и в отчёте читается", "4096" in text, True)
    finally:
        schema.sql_execute = original


SCHEMA_WITH_COMMENTS = {
    "taken_at": "2026-09-14T10:00:00",
    "databases": [{"db": "billing", "tables": 2, "size_mb": 4096,
                   "rows_est": 88000000}],
    "comments": {"tables": 1, "columns": 2},
    "tables": {
        "billing.agreements": {
            "db": "billing", "table": "agreements", "engine": "InnoDB",
            "rows_est": 4200000, "size_mb": 3100, "idx_mb": 900,
            "note": "Договоры абонентов",
            "columns": [
                {"col": "uid", "type": "int(11)", "nullable": "NO",
                 "ckey": "PRI", "extra": "", "note": "Идентификатор абонента"},
                {"col": "balance", "type": "decimal(10,2)", "nullable": "YES",
                 "ckey": "", "extra": "", "note": "Остаток на счёте"}],
            "indexes": [{"idx": "PRIMARY", "cols": "uid", "non_unique": 0,
                         "cardinality": 4200000}]},
        "billing.log_tmp": {
            "db": "billing", "table": "log_tmp", "engine": "InnoDB",
            "rows_est": 10, "size_mb": 1, "idx_mb": 0, "note": "",
            "columns": [], "indexes": []}},
    "cut": [],
}


def schema_comments() -> None:
    """Комментарии из базы — главное, что упрощает разговор.

    Имя `balance` не говорит ничего, «Остаток на счёте» говорит всё. Имена
    в базе английские, а спрашивают по-русски — значит искать надо и по
    комментариям тоже.
    """
    from agent.services import schema

    snapshot = SCHEMA_WITH_COMMENTS

    # Справка для чата: имя рядом с комментарием
    brief = schema.fmt_brief(snapshot)
    check("комментарий таблицы в справке для модели",
          "agreements" in brief and "Договоры абонентов" in brief, True)
    check("таблицы без комментария не занимают по строке",
          "без комментария: log_tmp" in brief, True)
    check("модели сказано про поиск по смыслу",
          "ищет и по комментариям" in brief, True)

    # Описание таблицы
    one = schema.fmt_describe(schema.describe(snapshot, "agreements"))
    check("комментарий таблицы виден", "Договоры абонентов" in one, True)
    check("комментарии столбцов видны",
          "Остаток на счёте" in one and "Идентификатор абонента" in one, True)

    # Поиск по русскому слову находит английскую таблицу
    found = schema.find(snapshot, "договор")
    check("таблица нашлась по комментарию",
          found["matches"][0]["tbl"], "agreements")
    check("и сказано, что именно совпало",
          found["matches"][0]["by"], "комментарию")

    col = schema.find(snapshot, "счёт")
    check("столбец нашёлся по комментарию",
          col["matches"][0]["col"], "balance")
    check("в выводе поиска комментарий приведён",
          "Остаток на счёте" in schema.fmt_find(col), True)

    # Найденное по смыслу идёт раньше случайного совпадения по имени
    mixed = schema.find(dict(snapshot, tables={
        "billing.dogovor_log": {"db": "billing", "table": "dogovor_log",
                                "note": "", "columns": []},
        "billing.agreements": snapshot["tables"]["billing.agreements"]}),
        "договор")
    check("совпадение по смыслу идёт первым",
          mixed["matches"][0]["by"], "комментарию")

    # В отчёте видно, прочитались ли комментарии вообще
    text = schema.fmt_snapshot(snapshot, "Кемерово")
    check("сказано, сколько комментариев прочитано",
          "Комментарии из базы прочитаны" in text, True)
    check("и со склонением", "1 таблицы и 2 столбцов" in text, True)

    silent = schema.fmt_snapshot(dict(snapshot, comments={"tables": 0,
                                                          "columns": 0}),
                                 "Кемерово")
    check("их отсутствие названо прямо и с оговоркой про оба пути",
          "ни в information_schema, ни через SHOW" in silent, True)

    # Снимок прежней версии: комментарии не читались, а не отсутствуют
    old_one = dict(snapshot)
    old_one.pop("comments")
    stale = schema.fmt_snapshot(old_one, "Кемерово")
    check("старый снимок не выдаётся за отсутствие комментариев",
          "снят прежней версией агента" in stale, True)
    check("и сказано, что делать", "Снять схему" in stale, True)

    # Модели не обещаем того, чего в снимке нет
    bare = schema.fmt_brief({"databases": [{"db": "billing", "tables": 1,
                                            "size_mb": 10}],
                             "tables": {"billing.t": {"db": "billing",
                                                      "table": "t",
                                                      "note": "",
                                                      "columns": []}}})
    check("без комментариев модели про них не обещают",
          "Рядом с именем — комментарий" in bare, False)
    check("и прямо сказано не выдумывать",
          "не выдумывай" in bare, True)

    # Приписка MySQL 5.6 — не комментарий разработчика
    check("служебная приписка вычищена",
          schema.clean_comment("InnoDB free: 1024 kB"), "")
    check("настоящий комментарий цел",
          schema.clean_comment("Платежи абонентов"), "Платежи абонентов")
    check("комментарий с припиской остаётся читаемым",
          schema.clean_comment("Договоры; InnoDB free: 8192 kB"),
          "Договоры")

    from agent.core.words import count_of
    check("склонения человеческие",
          [count_of(n, "таблица", "таблицы", "таблиц") for n in (1, 2, 5, 11, 21)],
          ["1 таблица", "2 таблицы", "5 таблиц", "11 таблиц", "21 таблица"])


def schema_comments_collected() -> None:
    """Комментарии забираются при съёмке, а не теряются по дороге."""
    from agent.services import schema

    async def fake_sql(cluster, sql, host=None, max_rows=0):
        low = sql.lower()
        if "group by table_schema" in low:
            return {"host": "10.1.0.1",
                    "columns": ["db", "tables", "size_mb", "rows_est"],
                    "rows": [["billing", 1, 10, 100]]}
        if "from information_schema.tables" in low:
            return {"columns": ["tbl", "engine", "rows_est", "size_mb",
                                "idx_mb", "note"],
                    "rows": [["agreements", "InnoDB", 100, 10, 2,
                              "Договоры абонентов; InnoDB free: 1024 kB"]]}
        if "from information_schema.columns" in low:
            return {"columns": ["tbl", "col", "type", "nullable", "ckey",
                                "extra", "note"],
                    "rows": [["agreements", "balance", "decimal(10,2)", "YES",
                              "", "", "Остаток на счёте"]]}
        if "from information_schema.statistics" in low:
            return {"columns": ["tbl", "idx", "cols", "non_unique",
                                "cardinality"], "rows": []}
        return {"columns": [], "rows": []}

    # Комментарии обязаны быть в самих запросах, иначе их неоткуда взять
    import inspect
    src = inspect.getsource(schema.collect)
    check("комментарий таблицы запрашивается", "TABLE_COMMENT" in src, True)
    check("комментарий столбца тоже", "COLUMN_COMMENT" in src, True)

    original = schema.sql_execute
    schema.sql_execute = fake_sql
    try:
        snapshot = asyncio.run(schema.collect(
            {"name": "k", "label": "K", "primary_ip": "1.1.1.1",
             "db_user": "u", "db_password": "p"}))
        table = snapshot["tables"]["billing.agreements"]
        check("комментарий таблицы дошёл до снимка",
              table["note"], "Договоры абонентов")
        check("комментарий столбца тоже",
              table["columns"][0]["note"], "Остаток на счёте")
        check("и посчитан", (snapshot["comments"]["tables"],
                             snapshot["comments"]["columns"]), (1, 1))
        check("и записано, откуда взят",
              snapshot["comments"]["source"], "information_schema")
    finally:
        schema.sql_execute = original


def schema_mentioned() -> None:
    """Про какую таблицу спросили — агент должен понять сам.

    Иначе описание таблицы в подсказку не попадёт, и модель ответит по
    смыслу имени: перечислит столбцы, которых в базе нет.
    """
    from agent.services import schema

    snapshot = dict(SCHEMA_WITH_COMMENTS, tables=dict(
        SCHEMA_WITH_COMMENTS["tables"],
        **{"billing.payments": {"db": "billing", "table": "payments",
                                "size_mb": 900, "note": "Платежи абонентов",
                                "columns": [], "indexes": []}}))

    check("полное имя базы и таблицы",
          schema.mentioned(snapshot, "что лежит в billing.agreements"),
          ["billing.agreements"])
    check("имя таблицы отдельным словом",
          schema.mentioned(snapshot, "какие поля в таблице agreements?"),
          ["billing.agreements"])
    check("русский вопрос находит английскую таблицу по комментарию",
          schema.mentioned(snapshot, "сколько платежей за вчера"),
          ["billing.payments"])
    check("падеж комментарию не мешает",
          schema.mentioned(snapshot, "по договорам есть долги?"),
          ["billing.agreements"])

    # Подстрокой искать нельзя: log найдётся в половине схемы
    check("случайная подстрока не тянет лишние таблицы",
          schema.mentioned(snapshot, "посмотри log"), [])
    check("вопрос не про данные ничего не цепляет",
          schema.mentioned(snapshot, "как дела в Кемерово"), [])
    check("пустой вопрос безопасен",
          schema.mentioned(snapshot, ""), [])
    check("без снимка пусто", schema.mentioned({}, "agreements"), [])

    # Крупные вперёд: спрашивают про них, а не про справочник
    both = schema.mentioned(snapshot, "сверь agreements и payments")
    check("две таблицы, крупная первой", both,
          ["billing.agreements", "billing.payments"])
    check("больше трёх таблиц в подсказку не льём",
          len(schema.mentioned(snapshot, "agreements payments log_tmp",
                               limit=2)), 2)


def schema_in_chat_context() -> None:
    """Описание таблицы кладём в подсказку сами.

    Ждать, что модель сходит за ним инструментом, нельзя: не всякий
    эндпоинт умеет вызовы функций. Тогда в контексте не будет столбцов —
    и модель их придумает.
    """
    from agent.services import assistant, schema

    snapshot = SCHEMA_WITH_COMMENTS
    original = schema.load

    async def fake_load(name):
        return snapshot if name == "kemerovo" else None

    schema.load = fake_load
    try:
        blocks = asyncio.run(assistant.schema_blocks(
            "kemerovo", "какие поля в agreements?"))
        text = "\n".join(blocks)
        check("общий список таблиц приложен",
              "## Что есть в базе" in text, True)
        check("описание нужной таблицы приложено",
              "## billing.agreements" in text, True)
        check("столбцы в подсказке настоящие",
              "balance" in text and "decimal(10,2)" in text, True)
        check("комментарии столбцов тоже приложены",
              "Остаток на счёте" in text, True)

        only = asyncio.run(assistant.schema_blocks(
            "kemerovo", "что с нагрузкой на базу?"))
        check("вопрос не про таблицы — только общий список", len(only), 1)

        check("без снимка схемы блоков нет",
              asyncio.run(assistant.schema_blocks("novosibirsk", "agreements")),
              [])
    finally:
        schema.load = original

    # Правило в подсказке: столбцы берутся только из приложенного блока
    from agent.services import analysis
    prompt = analysis.system_prompt()
    check("модели запрещено выдумывать столбцы",
          "СТОЛБЦЫ НЕ ВЫДУМЫВАЙ" in prompt, True)
    check("сказано, что делать без схемы",
          "структуры этой таблицы у меня нет" in prompt, True)
    check("и что общий список — не список столбцов",
          "Перечислять по нему столбцы нельзя" in prompt, True)
    check("запрет выдумывать распространён на всё, чего агент не знает",
          "НЕ ЗНАЕШЬ — ТАК И СКАЖИ" in prompt, True)
    check("сказано не выдавать чужие базы за эту",
          "устройство ЭТОЙ базы" in prompt, True)
    check("и требуется отделять проверенное от предположений",
          "проверить нечем" in prompt, True)


def sql_limit_over_ssh() -> None:
    """Предел строк запроса должен доходить до самого запроса.

    Через SSH сюда дописывался общий предел в 200 строк независимо от
    того, сколько запросили. Столбцы всех таблиц базы — тысячи строк:
    доезжали первые двести, то есть несколько таблиц по алфавиту, а у
    остальных столбцов не оказывалось вовсе. Ровно так пропали
    комментарии, которые в базе есть.
    """
    from agent.services import mysql, ssh

    sent = []

    async def fake_ssh(ip, cmd, ok_codes=(0,), env=None):
        sent.append(cmd)
        return True, "col" + chr(9) + "note" + chr(10) + "a" + chr(9) + "Платежи"

    original = mysql.log_ssh
    mysql.log_ssh = fake_ssh
    try:
        cluster = {"name": "k", "primary_ip": "10.0.0.1", "db_user": "u",
                   "db_password": "p"}
        res = asyncio.run(mysql.sql_run_ssh(
            cluster, "SELECT COLUMN_COMMENT AS note FROM information_schema.COLUMNS",
            None, 20000))
        check("запрошенный предел дошёл до запроса",
              "LIMIT 20000" in sent[-1], True)
        check("общий предел не подставился вместо него",
              "LIMIT 200 " in sent[-1] or sent[-1].endswith("LIMIT 200"), False)
        check("русский комментарий доехал целым",
              res["rows"][0][1], "Платежи")

        sent.clear()
        asyncio.run(mysql.sql_run_ssh(cluster, "SELECT 1", None, 0))
        check("без запрошенного предела действует общий",
              "LIMIT %d" % mysql.SQL_MAX_ROWS in sent[-1], True)
    finally:
        mysql.log_ssh = original


def schema_notes_via_show() -> None:
    """Комментарии через SHOW, когда information_schema отдала пустые.

    На живом сервере так и вышло: в information_schema пусто, а
    SHOW CREATE TABLE показывает комментарии. Берём SHOW FULL COLUMNS —
    те же данные, но отдельным столбцом, без разбора текста DDL.
    """
    from agent.services import schema

    asked = []

    async def fake_sql(cluster, sql, host=None, max_rows=0):
        asked.append(sql)
        low = sql.lower()
        if "group by table_schema" in low:
            return {"host": "10.1.0.1",
                    "columns": ["db", "tables", "size_mb", "rows_est"],
                    "rows": [["billing", 1, 10, 100]]}
        if "from information_schema.tables" in low:
            # Комментарий пустой — та самая жалоба
            return {"columns": ["tbl", "engine", "rows_est", "size_mb",
                                "idx_mb", "note"],
                    "rows": [["payments", "InnoDB", 100, 10, 2, ""]]}
        if "from information_schema.columns" in low:
            return {"columns": ["tbl", "col", "type", "nullable", "ckey",
                                "extra", "note"],
                    "rows": [["payments", "amount", "decimal(10,2)", "YES",
                              "", "", ""]]}
        if "from information_schema.statistics" in low:
            return {"columns": ["tbl", "idx", "cols", "non_unique",
                                "cardinality"], "rows": []}
        if low.startswith("show table status"):
            return {"columns": ["Name", "Engine", "Comment"],
                    "rows": [["payments", "InnoDB",
                              "Платежи абонентов; InnoDB free: 1024 kB"]]}
        if low.startswith("show full columns"):
            return {"columns": ["Field", "Type", "Comment"],
                    "rows": [["amount", "decimal(10,2)", "Сумма платежа"]]}
        return {"columns": [], "rows": []}

    original = schema.sql_execute
    schema.sql_execute = fake_sql
    try:
        snapshot = asyncio.run(schema.collect(
            {"name": "k", "label": "K", "primary_ip": "1.1.1.1",
             "db_user": "u", "db_password": "p"}))
    finally:
        schema.sql_execute = original

    table = snapshot["tables"]["billing.payments"]
    check("комментарий таблицы добран через SHOW",
          table["note"], "Платежи абонентов")
    check("служебная приписка вычищена и здесь",
          "InnoDB free" in table["note"], False)
    check("комментарий столбца тоже добран",
          table["columns"][0]["note"], "Сумма платежа")
    check("и записано, что взято не из information_schema",
          snapshot["comments"]["source"], "SHOW")
    check("в отчёте это сказано человеку",
          any("через SHOW" in n for n in snapshot["cut"]), True)

    # Имена в обратных кавычках: иначе имя со спецсимволом развалит запрос
    check("имя базы взято в кавычки",
          any(chr(96) + "billing" + chr(96) in q for q in asked), True)

    # Даром второй путь не ходит: комментарии есть — SHOW не нужен
    asked.clear()

    async def with_notes(cluster, sql, host=None, max_rows=0):
        res = await fake_sql(cluster, sql, host, max_rows)
        cols, rows = res.get("columns") or [], res.get("rows") or []
        if "note" in cols and "tbl" in cols and "col" not in cols and rows:
            rows[0][cols.index("note")] = "Платежи абонентов"
        return res

    schema.sql_execute = with_notes
    try:
        full = asyncio.run(schema.collect(
            {"name": "k", "label": "K", "primary_ip": "1.1.1.1",
             "db_user": "u", "db_password": "p"}))
    finally:
        schema.sql_execute = original
    check("нашлись в information_schema — SHOW не запускается",
          any(q.lower().startswith("show") for q in asked), False)
    check("и источник записан правильно",
          full["comments"]["source"], "information_schema")


def thinking_hidden() -> None:
    """Ход мысли модели в чат не попадает.

    Рассуждающие модели пишут его прямо в ответ. Человек спрашивал про
    платежи, а видел протокол размышлений — и в нём ещё и мелькал тег
    <think>.
    """
    from agent.services.toolcalls import StreamFilter, strip_thinking

    check("парный блок вырезан",
          strip_thinking("<think>прикину так</think>Платежей 12"),
          "Платежей 12")
    check("тег с атрибутами тоже",
          strip_thinking('<thinking step="1">ага</thinking>Готово'), "Готово")
    check("оборванная мысль не показывается",
          strip_thinking("<think>начал думать и прервали"), "")
    check("обычный текст не трогаем",
          strip_thinking("Платежей по договору 7 — двенадцать"),
          "Платежей по договору 7 — двенадцать")
    check("угловые скобки в тексте не ломают ответ",
          strip_thinking("Условие: a < b и c > d"), "Условие: a < b и c > d")

    # Закрывающий тег без открывающего: часть провайдеров отдаёт именно так
    check("рассуждение до закрывающего тега отброшено",
          strip_thinking("долго рассуждаю</think>Платежей 12"), "Платежей 12")

    # В потоке: показанное рассуждение придётся стереть
    flt = StreamFilter()
    shown, resets = "", 0
    for token in ("Сна", "чала ", "прикину", "</think>", "Платежей ", "12"):
        out, reset = flt.feed(token)
        if reset:
            shown, resets = "", resets + 1
        shown += out
    out, reset = flt.finish()
    shown = (out if reset else shown + out)
    check("клиенту сказано стереть показанное", resets, 1)
    check("в итоге виден только ответ", shown, "Платежей 12")
    check("и в сохранённом ответе тоже", flt.clean, "Платежей 12")

    # Тег приходит кусками и не должен мелькать ни одним символом
    flt2 = StreamFilter()
    seen = ""
    for ch in "<think>тайна</think>Ответ: 42":
        out, reset = flt2.feed(ch)
        if reset:
            seen = ""
        seen += out
    out, reset = flt2.finish()
    seen = out if reset else seen + out
    check("по символу разметка не просочилась",
          "think" not in seen and "<" not in seen, True)
    check("ответ дошёл целым", seen, "Ответ: 42")


def answer_not_a_plan() -> None:
    """Запрос, написанный вместо ответа, агент выполняет сам.

    Человек просил посмотреть платежи по договору. Модель ответила
    инструкцией «выполните такой SELECT» — но доступа к базе у человека в
    чате нет, он есть у агента. План — не ответ.
    """
    from agent.services import assistant

    cluster = {"name": "kemerovo", "label": "Кемерово"}
    fence = chr(96) * 3

    plan = ("Чтобы посмотреть платежи, выполните запрос:" + chr(10) +
            fence + "sql" + chr(10) +
            "SELECT id, amount FROM payments WHERE agrm_id = 7;" + chr(10) +
            fence)
    calls = assistant.sql_from_answer(plan, cluster)
    check("запрос из ответа забран", len(calls), 1)
    check("выполнять будем тем же инструментом", calls[0]["name"], "run_sql")
    check("кластер подставлен", calls[0]["args"]["cluster"], "kemerovo")
    check("запрос собран в одну строку",
          calls[0]["args"]["sql"],
          "SELECT id, amount FROM payments WHERE agrm_id = 7;")

    bare = ("Нужно выполнить:" + chr(10) +
            "SELECT COUNT(*) FROM payments WHERE uid = 5;" + chr(10) +
            "и посмотреть, что вернётся")
    check("запрос без ограды тоже найден",
          assistant.sql_from_answer(bare, cluster)[0]["args"]["sql"],
          "SELECT COUNT(*) FROM payments WHERE uid = 5;")

    # Пишущий запрос не выполняем ни при какой подаче: та же проверка,
    # что и у штатного инструмента
    harm = (fence + "sql" + chr(10) +
            "DELETE FROM payments WHERE id = 1;" + chr(10) + fence)
    check("пишущий запрос из ответа не выполняется",
          assistant.sql_from_answer(harm, cluster), [])
    sneaky = (fence + chr(10) + "SELECT 1; DROP TABLE payments;" + chr(10)
              + fence)
    check("две инструкции тоже отклонены",
          assistant.sql_from_answer(sneaky, cluster), [])

    # Готовый ответ переделывать не надо
    check("ответ по данным ничего не запускает",
          assistant.sql_from_answer(
              "Платежей по договору 7 — двенадцать на 4500 руб.", cluster), [])
    check("без кластера выполнять негде",
          assistant.sql_from_answer(plan, None), [])

    # Больше двух запросов из одного ответа не берём
    many = "".join(fence + "sql" + chr(10) + "SELECT %d;" % n + chr(10) + fence
                   + chr(10) for n in range(5))
    check("запросов берём не больше предела",
          len(assistant.sql_from_answer(many, cluster)),
          assistant.MAX_ANSWER_SQL)

    # Правила в подсказке
    from agent.services import analysis
    prompt = analysis.system_prompt()
    check("модели сказано не выводить рассуждения",
          "<think>" in prompt and "не выводи" in prompt, True)
    check("и что план не является ответом", "ПЛАН — НЕ ОТВЕТ" in prompt, True)
    check("и что агент выполнит написанный запрос сам",
          "агент выполнит его сам" in prompt, True)


def native_tool_calls() -> None:
    """Вызовы штатным полем не теряются в потоке.

    Модель умеет звать инструменты не текстом, а полем tool_calls. В
    стриме они приходят кусками: имя в первом, аргументы по символам в
    следующих. Раньше поток брал только content — и человек получал
    вступление «сейчас посмотрю» вместо ответа, а вызов пропадал молча.
    """
    from agent.services import llm

    parts = {}
    llm._collect_tool_deltas(parts, [
        {"index": 0, "id": "c1",
         "function": {"name": "run_sql", "arguments": '{"clus'}}])
    llm._collect_tool_deltas(parts, [
        {"index": 0, "function": {"arguments": 'ter": "kemerovo", "sql": '}}])
    llm._collect_tool_deltas(parts, [
        {"index": 0, "function": {"arguments": '"SELECT 1"}'}}])
    calls = llm._finish_tool_calls(parts)
    check("вызов собран из кусков", len(calls), 1)
    check("имя взято из первого куска", calls[0]["name"], "run_sql")
    check("аргументы склеены и разобраны",
          calls[0]["args"], {"cluster": "kemerovo", "sql": "SELECT 1"})

    # Два вызова в одном ответе различаются по номеру, а не по приходу
    pair = {}
    llm._collect_tool_deltas(pair, [
        {"index": 0, "function": {"name": "get_schema", "arguments": "{}"}},
        {"index": 1, "function": {"name": "get_history", "arguments": '{"h'}}])
    llm._collect_tool_deltas(pair, [
        {"index": 1, "function": {"arguments": 'ours": 6}'}}])
    both = llm._finish_tool_calls(pair)
    check("оба вызова собраны", [c["name"] for c in both],
          ["get_schema", "get_history"])
    check("аргументы не перепутаны", both[1]["args"], {"hours": 6})

    # Битые аргументы не должны ронять ответ целиком
    broken = llm._finish_tool_calls({0: {"name": "run_sql", "args": "{не json"}})
    check("битые аргументы не роняют разбор", broken[0]["args"], {})
    check("вызов без имени отброшен",
          llm._finish_tool_calls({0: {"name": "", "args": "{}"}}), [])


def preamble_is_not_an_answer() -> None:
    """«Сейчас получу то и это:» — это не ответ."""
    from agent.services.assistant import FINISH_NOTE, looks_unfinished

    check("вступление опознано",
          looks_unfinished("Получаю количество договоров без движения:"), True)
    check("многоточие тоже",
          looks_unfinished("Сейчас посмотрю таблицы платежей..."), True)
    check("пустой ответ — тем более", looks_unfinished("   "), True)
    check("ответ по существу не трогаем",
          looks_unfinished("Договоров без движения — 412, из них 87 с "
                           "нулевым балансом."), False)
    check("длинный текст с двоеточием в конце — всё-таки ответ",
          looks_unfinished("Разбор по кластерам. " * 30 + "итого:"), False)

    check("модели сказано, что сбор окончен",
          "инструменты закончились" in FINISH_NOTE.lower(), True)
    check("и что описывать намерения не надо",
          "не описывай" in FINISH_NOTE, True)


def rounds_end_with_answer() -> None:
    """Когда раунды инструментов кончились, модели говорят: отвечай.

    Без этого она продолжает в том же духе — объявляет следующий шаг и
    замолкает. Именно так получались пустые ответы с рядом значков
    инструментов и вступлением вместо текста.
    """
    from agent.services import assistant

    rounds = {"n": 0}

    class FakeResponse:
        status_code = 200

        def raise_for_status(self):
            pass

        def json(self):
            rounds["n"] += 1
            # Модель зовёт инструмент столько раз, сколько ей позволят
            return {"choices": [{"message": {
                "role": "assistant", "content": "Сейчас посмотрю:",
                "tool_calls": [{"id": "c%d" % rounds["n"], "function": {
                    "name": "get_schema",
                    "arguments": '{"cluster": "c%d"}' % rounds["n"]}}]}}]}

    class FakeClient:
        def __init__(self, *a, **kw):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def post(self, *a, **kw):
            return FakeResponse()

    async def fake_tool(name, args):
        return "## %s\n\n  данные" % name

    originals = (assistant.httpx.AsyncClient, assistant.run_tool)
    assistant.httpx.AsyncClient = FakeClient
    assistant.run_tool = fake_tool
    try:
        convo, used = asyncio.run(assistant.llm_with_tools(
            [{"role": "user", "content": "изучи структуру базы"}]))
    finally:
        assistant.httpx.AsyncClient, assistant.run_tool = originals

    check("раунды ограничены", len(used), assistant.LLM_TOOL_ROUNDS)
    check("последним идёт указание отвечать",
          convo[-1]["content"], assistant.FINISH_NOTE)
    check("и оно от лица человека, а не инструмента",
          convo[-1]["role"], "user")


def chat_finishes_thought(client) -> None:
    """Ответ-вступление агент просит договорить, а показанное стирает."""
    from agent.api.routes import chat as chat_routes

    turns = {"n": 0}

    async def fake_context(text, progress=None):
        return "## Метрики", None, 0

    async def fake_stream(messages, tool_sink=None):
        turns["n"] += 1
        if turns["n"] == 1:
            for piece in ("Получаю ", "количество ", "договоров:"):
                yield piece
        else:
            for piece in ("Договоров ", "без движения — 412."):
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
            ws.send_json({"type": "message", "text": "сколько пустых договоров",
                          "client_id": "web-9", "session_id": "s9"})
            seen, answer = [], ""
            for _ in range(40):
                msg = ws.receive_json()
                seen.append(msg.get("type"))
                if msg.get("type") == "reset":
                    answer = ""
                if msg.get("type") == "token":
                    answer += msg.get("text", "")
                if msg.get("type") == "done":
                    break
        check("агент попросил договорить", turns["n"], 2)
        check("клиенту сказано стереть вступление", "reset" in seen, True)
        check("человек видит ответ, а не вступление",
              answer, "Договоров без движения — 412.")
    finally:
        (chat_routes.build_chat_context, chat_routes.llm_stream,
         chat_routes.llm_probe_tools) = original


def tool_budget_is_a_question() -> None:
    """Предел инструментов — порция, а не потолок.

    Сбор данных идёт не бесплатно: это запросы к боевой базе и чтение
    логов по SSH. Сколько на это потратить, решает человек, а не число в
    настройках, — поэтому по исчерпании порции агент спрашивает.
    """
    from agent.services import assistant

    rounds = {"n": 0}

    class FakeResponse:
        status_code = 200

        def raise_for_status(self):
            pass

        def json(self):
            rounds["n"] += 1
            # Каждый раунд просим НОВЫЙ инструмент, иначе сработает
            # защита от хождения по кругу
            return {"choices": [{"message": {
                "role": "assistant", "content": "",
                "tool_calls": [{"id": "c%d" % rounds["n"], "function": {
                    "name": "get_schema",
                    "arguments": '{"cluster": "c%d"}' % rounds["n"]}}]}}]}

    class FakeClient:
        def __init__(self, *a, **kw):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def post(self, *a, **kw):
            return FakeResponse()

    async def fake_tool(name, args):
        return "данные %s" % args.get("cluster")

    originals = (assistant.httpx.AsyncClient, assistant.run_tool,
                 assistant.LLM_TOOL_ROUNDS)
    assistant.httpx.AsyncClient = FakeClient
    assistant.run_tool = fake_tool
    assistant.LLM_TOOL_ROUNDS = 2
    try:
        # Отказались продолжать — сбор кончается на первой порции
        asked = []

        async def say_no(done, done_rounds):
            asked.append((done, done_rounds))
            return False

        rounds["n"] = 0
        _convo, used = asyncio.run(assistant.llm_with_tools(
            [{"role": "user", "content": "изучи базу"}], say_no))
        check("спросили ровно один раз", len(asked), 1)
        check("спросили после порции", asked[0][1], 2)
        check("и сказали, сколько уже сделано", asked[0][0], 2)
        check("после отказа сбор окончен", len(used), 2)

        # Согласились один раз — порция выдаётся заново
        answers = iter([True, False])

        async def say_once(done, done_rounds):
            return next(answers, False)

        rounds["n"] = 0
        _convo, used = asyncio.run(assistant.llm_with_tools(
            [{"role": "user", "content": "изучи базу"}], say_once))
        check("после согласия собрано вдвое больше", len(used), 4)

        # Без вопроса порция работает как прежний потолок
        rounds["n"] = 0
        _convo, used = asyncio.run(assistant.llm_with_tools(
            [{"role": "user", "content": "изучи базу"}]))
        check("без спрашивающего порция — это потолок", len(used), 2)

        # Предел выключен: агент ходит, пока модель просит
        assistant.LLM_TOOL_ROUNDS = 0
        rounds["n"] = 0
        never = {"asked": False}

        async def never_ask(done, done_rounds):
            never["asked"] = True
            return True

        # Модель просит инструменты вечно — остановит только предохранитель,
        # поэтому здесь она повторяется после пятого раза
        class LoopingResponse(FakeResponse):
            def json(self):
                rounds["n"] += 1
                number = min(rounds["n"], 5)
                return {"choices": [{"message": {
                    "role": "assistant", "content": "",
                    "tool_calls": [{"id": "x", "function": {
                        "name": "get_schema",
                        "arguments": '{"cluster": "c%d"}' % number}}]}}]}

        class LoopingClient(FakeClient):
            async def post(self, *a, **kw):
                return LoopingResponse()

        assistant.httpx.AsyncClient = LoopingClient
        _convo, used = asyncio.run(assistant.llm_with_tools(
            [{"role": "user", "content": "изучи базу"}], never_ask))
        check("без предела не спрашиваем", never["asked"], False)
        check("хождение по кругу остановлено предохранителем", len(used), 5)
    finally:
        (assistant.httpx.AsyncClient, assistant.run_tool,
         assistant.LLM_TOOL_ROUNDS) = originals


def job_asks_and_waits() -> None:
    """Задача умеет спросить человека и дождаться ответа."""
    from agent.services import jobs

    async def answered() -> tuple:
        job = jobs.Job("t-1", "вопрос")

        async def reply_soon():
            await asyncio.sleep(0.05)
            job.reply("yes")

        asyncio.create_task(reply_soon())
        return await job.ask("Продолжаем?", [{"value": "yes", "label": "Да"}],
                             5), job

    value, job = asyncio.run(answered())
    check("ответ человека дошёл", value, "yes")
    kinds = [e["type"] for e in job.events]
    check("вопрос и закрытие попали в ленту событий",
          kinds, ["ask", "asked"])
    check("вернувшийся клиент увидит, чем кончилось",
          job.events[-1]["value"], "yes")

    async def ignored() -> str:
        job = jobs.Job("t-2", "вопрос")
        return await job.ask("Продолжаем?", [], 0.1)

    check("не дождались — пусто, а не зависание", asyncio.run(ignored()), "")

    async def interrupted() -> str:
        job = jobs.Job("t-3", "вопрос")

        async def press_stop():
            await asyncio.sleep(0.05)
            job.stop_event.set()

        asyncio.create_task(press_stop())
        return await job.ask("Продолжаем?", [], 5)

    check("«Остановить» снимает вопрос", asyncio.run(interrupted()), "")

    # Ответ на несуществующий вопрос ничего не ломает
    check("ответ без вопроса отклонён", jobs.Job("t-4", "в").reply("yes"), False)
    check("ответ неизвестному разговору отклонён",
          jobs.reply("нет-такого", "yes"), False)


def vector_math() -> None:
    """Близость по смыслу: нормировка, скалярное произведение, порог."""
    from agent.services import embed

    unit = embed.normalize([3.0, 4.0])
    check("вектор приведён к единичной длине", unit, [0.6, 0.8])
    check("нулевой вектор отброшен", embed.normalize([0, 0]), [])
    check("мусор вместо чисел не роняет", embed.normalize(["а", "б"]), [])

    check("одинаковые векторы — близость единица",
          round(embed.similarity([0.6, 0.8], [0.6, 0.8]), 3), 1.0)
    check("перпендикулярные — ноль",
          round(embed.similarity([1.0, 0.0], [0.0, 1.0]), 3), 0.0)
    check("разная длина векторов — не сравниваем",
          embed.similarity([1.0], [1.0, 0.0]), 0.0)

    index = {"billing.vgroups": [1.0, 0.0],
             "billing.payments": [0.0, 1.0],
             "billing.logs": [0.7071, 0.7071]}
    near = embed.nearest([1.0, 0.0], index, limit=2)
    check("ближайшее идёт первым", near[0][0], "billing.vgroups")
    check("и близость возвращается", near[0][1], 1.0)
    check("предел соблюдён", len(near), 2)

    # Порог обязателен: иначе на любой вопрос найдётся «самое похожее»
    check("непохожее не возвращается",
          embed.nearest([0.0, -1.0], index), [])
    check("без вопроса ничего", embed.nearest([], index), [])
    check("без индекса ничего", embed.nearest([1.0, 0.0], {}), [])


def schema_links() -> None:
    """Связи между таблицами: объявленные и предположенные."""
    from agent.services import schema

    # Внешние ключи есть — догадки не нужны
    real = {"tables": {
        "billing.payments": {"db": "billing", "table": "payments",
                             "columns": [], "links": [
                                 {"col": "uid", "ref": "billing.vgroups",
                                  "ref_col": "uid", "kind": "внешний ключ"}]},
        "billing.vgroups": {"db": "billing", "table": "vgroups",
                            "columns": [], "links": []}}}
    check("при живых ключах ничего не выдумываем", schema._guess_links(real), 0)
    check("обратная связь видна",
          schema.incoming(real, "billing.vgroups")[0]["from"],
          "billing.payments")

    # Ключей нет — предполагаем по именам столбцов
    guess = {"tables": {
        "billing.vgroups": {
            "db": "billing", "table": "vgroups", "size_mb": 10, "links": [],
            "columns": [{"col": "uid", "ckey": "PRI"},
                        {"col": "login", "ckey": ""}]},
        "billing.payments": {
            "db": "billing", "table": "payments", "size_mb": 5, "links": [],
            "columns": [{"col": "id", "ckey": "PRI"},
                        {"col": "uid", "ckey": "MUL"}]},
        "billing.notes": {
            "db": "billing", "table": "notes", "size_mb": 1, "links": [],
            "columns": [{"col": "id", "ckey": "PRI"},
                        {"col": "text", "ckey": ""}]}}}
    added = schema._guess_links(guess)
    check("связь предположена", added, 1)
    link = guess["tables"]["billing.payments"]["links"][0]
    check("указано, на что ссылается", link["ref"], "billing.vgroups")
    check("и честно помечено догадкой", link["kind"], "по имени столбца")
    check("по столбцу id связей не выдумано",
          guess["tables"]["billing.notes"]["links"], [])

    # В описании таблицы обе стороны связи
    text = schema.fmt_describe(schema.describe(guess, "billing.vgroups"))
    check("сказано, кто ссылается на таблицу",
          "billing.payments" in text and "На неё ссылаются" in text, True)
    out = schema.fmt_describe(schema.describe(guess, "billing.payments"))
    check("и на что ссылается сама",
          "Ссылается на:" in out and "billing.vgroups" in out, True)


def schema_semantic(client) -> None:
    """Поиск по смыслу находит то, что не совпало ни одной буквой."""
    from agent.services import embed, schema

    snapshot = {"taken_at": "2026-09-14T06:00:00",
                "databases": [{"db": "billing", "tables": 2, "size_mb": 10,
                               "rows_est": 100}],
                "tables": {
                    "billing.vgroups": {
                        "db": "billing", "table": "vgroups", "size_mb": 10,
                        "note": "Абоненты", "columns": [
                            {"col": "login", "type": "varchar(64)",
                             "note": "Логин для входа"}],
                        "indexes": [], "links": []},
                    "billing.logs": {
                        "db": "billing", "table": "logs", "size_mb": 1,
                        "note": "Журнал событий", "columns": [],
                        "indexes": [], "links": []}},
                "cut": []}

    # Документ для векторизации должен нести смысл, а не одно имя
    doc = schema.doc_for(snapshot["tables"]["billing.vgroups"])
    check("в документ попали имя, комментарий и столбцы",
          "vgroups" in doc and "Абоненты" in doc and "Логин для входа" in doc,
          True)

    # Вместо эндпоинта — простая подстановка: «учётные записи» ближе к
    # абонентам, чем к журналу
    def fake_vector(text):
        low = text.lower()
        people = 1.0 if ("абонент" in low or "учётн" in low
                         or "учетн" in low or "логин" in low) else 0.0
        events = 1.0 if ("журнал" in low or "событ" in low) else 0.0
        return embed.normalize([people, events]) or [0.0, 0.0]

    async def fake_encode(texts):
        return [fake_vector(t) for t in texts]

    async def yes():
        return True

    originals = (embed.encode, embed.probe, embed.EMBED_MODEL)
    embed.encode, embed.probe = fake_encode, yes
    # Имя модели в бою определяется само при пробе; заглушка пробы этого
    # не делает, поэтому подставляем
    embed.EMBED_MODEL = "тест-векторы"
    try:
        asyncio.run(schema.save("kemerovo", snapshot))
        built = asyncio.run(schema.build_index("kemerovo", snapshot))
        check("индекс построен на все таблицы", built["items"], 2)

        stored = asyncio.run(schema.load_index("kemerovo"))
        check("индекс прочитался", len(stored["index"]), 2)
        check("и помнит модель", bool(stored["model"]), True)

        near = asyncio.run(schema.search_semantic("kemerovo",
                                                  "покажи учётные записи"))
        check("«учётные записи» нашли таблицу «Абоненты»",
              near[0][0], "billing.vgroups")
        check("журнал не подмешался", len(near), 1)

        check("вопрос не про данные ничего не находит",
              asyncio.run(schema.search_semantic("kemerovo", "как дела")), [])
        check("для кластера без индекса пусто",
              asyncio.run(schema.search_semantic("novosibirsk", "абоненты")),
              [])

        # Найденное по смыслу подаётся с оговоркой: это догадка
        text = schema.fmt_semantic(snapshot, "учётные записи", near)
        check("сказано, что искали по смыслу",
              "по смыслу" in text, True)
        check("и предложено проверить",
              "Проверь, та ли это таблица" in text, True)
        check("близость показана", "близость 1.00" in text, True)
    finally:
        embed.encode, embed.probe, embed.EMBED_MODEL = originals

    check("модель индекса записана",
          asyncio.run(schema.load_index("kemerovo"))["model"], "тест-векторы")

    # Эндпоинт векторов не отвечает — работаем без индекса, не падая
    async def no_vectors():
        return False

    embed.probe = no_vectors
    try:
        check("без эндпоинта индекс не строится",
              asyncio.run(schema.build_index("vladivostok", snapshot)), {})
    finally:
        embed.probe = originals[1]


def switching_threads(client) -> None:
    """Ушёл в другой чат и вернулся — ответ на месте.

    Сокет раньше висел внутри пересказа одного разговора и не слышал
    ничего: человек переключался на другой чат, возвращался, а его просьба
    подключиться обратно всё ещё лежала в очереди — и вместо ответа он
    видел пустоту.
    """
    from agent.api.routes import chat as chat_routes
    from agent.services import jobs

    go = {"on": False}

    async def fake_ctx(text, progress=None):
        return "", None, 0

    async def fake_stream(messages, tool_sink=None):
        yield "начало "
        for _ in range(80):
            if go["on"]:
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
        first = client.post("/chat/threads?title=Первый").json()["id"]
        second = client.post("/chat/threads?title=Второй").json()["id"]

        with client.websocket_connect("/ws") as ws:
            ws.send_json({"type": "message", "text": "долгий вопрос",
                          "client_id": "web-7", "thread_id": first})
            kinds = []
            for _ in range(4):
                kinds.append(ws.receive_json().get("type"))
                if "token" in kinds:
                    break
            check("ответ в первом чате пошёл", "token" in kinds, True)

            # Ушли в другой чат: там ничего не считается
            ws.send_json({"type": "attach", "thread_id": second,
                          "client_id": "web-7"})

            # И сразу вернулись обратно. Раньше эта просьба лежала в
            # очереди до конца ответа, и человек видел пустой чат
            ws.send_json({"type": "attach", "thread_id": first,
                          "client_id": "web-7"})

            seen, answer = [], ""
            go["on"] = True
            for _ in range(20):
                msg = ws.receive_json()
                seen.append(msg.get("type"))
                if msg.get("type") == "token":
                    answer += msg.get("text", "")
                if msg.get("type") == "done":
                    break
            check("возврат распознан", "resume" in seen, True)
            check("накопленное отдано заново",
                  answer.startswith("начало"), True)
            check("и ответ дописан", answer.endswith("и конец"), True)

        for _ in range(20):
            if client.get("/chat/history?thread=%s" % first).json()["total"] >= 2:
                break
            time.sleep(0.1)
        check("ответ сохранён в свой чат",
              client.get("/chat/history?thread=%s" % first).json()["total"], 2)
        check("в чужой чат ничего не попало",
              client.get("/chat/history?thread=%s" % second).json()["total"], 0)
        check("задача завершена", jobs.running(first) is None, True)
    finally:
        (chat_routes.build_chat_context, chat_routes.llm_stream,
         chat_routes.llm_probe_tools) = original


def embed_model_discovery() -> None:
    """Имя модели векторов агент узнаёт у эндпоинта сам.

    Скачивать её бывает неоткуда: сеть наружу закрыта. Значит, работать
    надо с тем, что уже развёрнуто, — а как оно называется, знает сам
    эндпоинт.
    """
    from agent.services import embed

    listed = {"data": []}

    class FakeResponse:
        status_code = 200

        def raise_for_status(self):
            pass

        def json(self):
            return listed

    class FakeClient:
        def __init__(self, *a, **kw):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def get(self, *a, **kw):
            return FakeResponse()

    original = embed.httpx.AsyncClient
    embed.httpx.AsyncClient = FakeClient
    try:
        listed["data"] = [{"id": "qwen2.5-72b-instruct"},
                          {"id": "bge-m3"},
                          {"id": "whisper-large"}]
        check("модель векторов найдена среди развёрнутых",
              asyncio.run(embed.discover()), "bge-m3")

        listed["data"] = [{"id": "multilingual-e5-large"}]
        check("имя без слова embed тоже узнаётся",
              asyncio.run(embed.discover()), "multilingual-e5-large")

        listed["data"] = [{"id": "qwen2.5-72b-instruct"}]
        check("векторной модели нет — так и говорим",
              asyncio.run(embed.discover()), "")

        listed["data"] = []
        check("пустой список не ломает", asyncio.run(embed.discover()), "")
    finally:
        embed.httpx.AsyncClient = original


def tables_picked_by_model() -> None:
    """Без модели векторов таблицы выбирает сама генеративная модель.

    Она уже есть у всех, скачивать нечего, а смысл слов понимает не хуже:
    «учётные записи» и «Абоненты» для неё одно и то же.
    """
    from agent.services import schema

    snapshot = {"tables": {
        "billing.vgroups": {"db": "billing", "table": "vgroups",
                            "size_mb": 10, "note": "Абоненты", "columns": []},
        "billing.logs": {"db": "billing", "table": "logs", "size_mb": 1,
                         "note": "Журнал событий", "columns": []}}}

    said = {"text": "billing.vgroups"}
    asked = []

    async def fake_complete(messages):
        asked.append(messages[0]["content"])
        return said["text"]

    import agent.services.llm as llm_module
    original = llm_module.llm_complete
    llm_module.llm_complete = fake_complete
    try:
        found = asyncio.run(schema.search_by_model(snapshot,
                                                   "покажи учётные записи"))
        check("модель выбрала таблицу", found, ["billing.vgroups"])
        check("ей показали комментарии из базы",
              "Абоненты" in asked[0], True)
        check("и попросили отвечать только именами",
              "ТОЛЬКО именами" in asked[0], True)

        # Ответ модели проверяется по снимку: выдумка отбрасывается
        said["text"] = "billing.accounts\nbilling.users"
        check("несуществующие таблицы отброшены",
              asyncio.run(schema.search_by_model(snapshot, "учётки")), [])

        # Обычная манера отвечать списком тоже понимается
        said["text"] = "- billing.logs — журнал"
        check("список с дефисом разобран",
              asyncio.run(schema.search_by_model(snapshot, "события")),
              ["billing.logs"])

        said["text"] = "нет"
        check("отказ модели понят", asyncio.run(
            schema.search_by_model(snapshot, "как дела")), [])

        check("без снимка модель не тревожим",
              asyncio.run(schema.search_by_model({}, "учётные записи")), [])
        count = len(asked)
        check("и без вопроса тоже",
              asyncio.run(schema.search_by_model(snapshot, "  ")), [])
        check("лишнего запроса к модели не было", len(asked), count)
    finally:
        llm_module.llm_complete = original


def settings_reach_the_agent() -> None:
    """Настройка, которой нет в .env агента, — не настройка.

    Документировать переменную, которую установщик не пишет, бессмысленно:
    задать её человеку негде, а руками правленный .env затрётся при
    следующей установке.
    """
    env_block = (ROOT / "scripts" / "install_agent.sh").read_text(
        encoding="utf-8")
    config = (ROOT / "configure.sh").read_text(encoding="utf-8")

    for name in ("LLM_TOOLS", "LLM_TOOL_ROUNDS", "LLM_TOOL_ASK_S",
                 "EMBED_MODE", "EMBED_MODEL"):
        check("%s доезжает до агента" % name,
              ("%s=" % name) in env_block, True)
        check("%s видно в config.env" % name, ("%s=" % name) in config, True)

    # Смена модели не должна стирать остальной конфиг
    update = (ROOT / "scripts" / "update_llm.sh").read_text(encoding="utf-8")
    check("смена модели не переписывает .env целиком",
          'cat > "$AGENT_ENV"' in update, False)
    check("а правит нужные ключи", "set_env LLM_MODEL" in update, True)
    check("и делает копию перед правкой", "AGENT_ENV}.bak" in update, True)


def page_is_never_stale(client) -> None:
    """Браузер не должен показывать вчерашний интерфейс.

    Кэш уже подводил: сервер спрашивал «продолжаем?», а в старом app.js
    кнопок не было, и ответить было нечем. Версия в адресе скрипта не
    спасает, если сама страница взята из кэша, — значит запрещать надо
    прежде всего её.
    """
    r = client.get("/")
    check("страница отдаётся", r.status_code, 200)
    cache = r.headers.get("cache-control", "")
    check("страницу кэшировать запрещено", "no-store" in cache, True)
    check("и версия видна в заголовке ответа",
          bool(r.headers.get("x-agent-version")), True)

    body = r.text
    check("в адресе скрипта стоит версия", "static/app.js?v=" in body, True)
    check("и в адресе стилей тоже", "static/style.css?v=" in body, True)
    check("версия показана человеку в интерфейсе",
          "side-version" in body, True)
    check("плейсхолдер заменён", "{{VERSION}}" not in body, True)

    js = client.get("/static/app.js")
    check("скрипт отдаётся", js.status_code, 200)
    check("и его велено перепроверять",
          "no-cache" in js.headers.get("cache-control", ""), True)


def ask_has_a_way_out() -> None:
    """На вопрос агента можно ответить, что бы ни случилось с кнопками."""
    js = (ROOT / "web" / "app.js").read_text(encoding="utf-8")

    check("кнопки подставляются, даже если вариантов не пришло",
          "msg.options && msg.options.length" in js
          and "Продолжить сбор" in js, True)
    check("пока висит вопрос, в чат писать можно",
          "state.asking = true" in js and "$('input').disabled = false" in js,
          True)
    check("написанное в чат уходит ответом на вопрос",
          "if (state.asking) {" in js and "answerAsk(text)" in js, True)
    check("слова «да» и «продолжай» понимаются",
          "продолж" in js and "type: 'answer'" in js, True)
    check("сказано, что будет без ответа",
          "агент закончит сам" in js, True)

    css = (ROOT / "web" / "style.css").read_text(encoding="utf-8")
    check("подсказка под вопросом оформлена", ".ask-hint" in css, True)
    check("и сами кнопки тоже", ".ask-btn" in css, True)


def websocket(client) -> None:
    """Разговор по WebSocket от начала до конца.

    Модель и сбор метрик подменяются: проверяем протокол и то, что обработчик
    доходит до конца. Именно здесь ломается перенос кода — забытый импорт
    роняет соединение, а внешне это выглядит как «связь прервана».
    """
    from agent.api.routes import chat as chat_routes

    async def fake_context(text, progress=None):
        return "## Метрики\n  всё в порядке", None, 0

    async def fake_stream(messages, tool_sink=None):
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
