"""
Схема базы: снимается по кнопке, хранится у агента.

Без схемы агент отвечает на вопросы про нагрузку, но не может ответить на
вопрос про данные. «Сколько договоров с отрицательным балансом» — вопрос к
базе, а не к метрикам, и чтобы написать такую выборку, надо знать имена
таблиц и столбцов. Не зная их, модель либо отказывается, либо выдумывает.

Почему снимок, а не запрос каждый раз. Обход `information_schema` на базе с
тысячами таблиц — это не бесплатно: на боевом сервере такой запрос заметен,
а схема меняется раз в релиз, а не раз в минуту. Поэтому она снимается
однажды, хранится у агента и читается из его собственной базы — мгновенно и
не трогая продуктив. Пересъёмка — действие администратора: это нагрузка на
боевой сервер, и запускать её походя не стоит.

Снимок ограничен по объёму сознательно. В базе бывают тысячи таблиц, и
полный список бесполезен и человеку, и модели. Берём крупные — они же
интересные, — а о том, что осталось за кадром, пишем прямо.
"""
from __future__ import annotations

import json
import logging
import re
from typing import Optional

from agent.db.base import session_scope
from agent.db.models import SchemaSnapshot, to_iso
from agent.services.mysql import cluster_db_creds, sql_execute
from sqlalchemy import select

logger = logging.getLogger("agent.schema")

SYSTEM_DBS = ("mysql", "information_schema", "performance_schema", "sys")
_SYS_LIST = ", ".join("'%s'" % d for d in SYSTEM_DBS)

# Пределы снимка. Не ради экономии места: список из тысячи таблиц нечитаем,
# а подсказка модели, забитая именами, вытесняет всё остальное.
MAX_DBS = 20
MAX_TABLES_PER_DB = 80
MAX_DETAIL_TABLES = 300
MAX_COLUMNS = 120
MAX_MATCHES = 40


def _quote(value: str) -> str:
    """Строковый литерал для SQL: имена приходят от человека и от модели."""
    return "'" + str(value).replace("\\", "\\\\").replace("'", "''") + "'"


def _safe_name(value: str) -> str:
    return re.sub(r"[^0-9A-Za-z_$\--￿]", "", str(value or ""))[:64]


def split_table(name: str) -> tuple:
    """«lanbilling.agreements» -> ('lanbilling', 'agreements')."""
    raw = str(name or "").replace("`", "").strip()
    if "." in raw:
        db, _, tbl = raw.partition(".")
        return _safe_name(db), _safe_name(tbl)
    return "", _safe_name(raw)


def _rows(result: dict) -> list:
    cols = result.get("columns") or []
    return [dict(zip(cols, row)) for row in (result.get("rows") or [])]


def _num(value):
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return None


# ── Съёмка ───────────────────────────────────────────────────────────────

async def collect(cluster: dict, host: Optional[str] = None) -> dict:
    """Обойти information_schema и собрать снимок.

    Столбцы и индексы берутся одним запросом на базу, а не по запросу на
    таблицу: на сотне таблиц это сотня обращений против одного.
    """
    if not cluster_db_creds(cluster):
        return {"error": "Для кластера не задана учётка db_user — "
                         "схему прочитать нельзя"}

    dbs = await sql_execute(cluster, """
        SELECT TABLE_SCHEMA AS db, COUNT(*) AS tables,
               ROUND(SUM(DATA_LENGTH + INDEX_LENGTH) / 1048576) AS size_mb,
               SUM(TABLE_ROWS) AS rows_est
          FROM information_schema.TABLES
         WHERE TABLE_SCHEMA NOT IN (%s) AND TABLE_TYPE = 'BASE TABLE'
         GROUP BY TABLE_SCHEMA
         ORDER BY SUM(DATA_LENGTH + INDEX_LENGTH) DESC
         LIMIT %d""" % (_SYS_LIST, MAX_DBS), host, MAX_DBS + 5)
    if dbs.get("error"):
        return {"error": "Схема не прочитана: %s" % dbs["error"]}

    databases = _rows(dbs)
    snapshot = {"taken_at": to_iso(), "databases": databases,
                "tables": {}, "cut": []}

    detailed = 0
    for db in databases:
        name = _safe_name(db.get("db"))
        if not name:
            continue

        tbls = await sql_execute(cluster, """
            SELECT TABLE_NAME AS tbl, ENGINE AS engine, TABLE_ROWS AS rows_est,
                   ROUND((DATA_LENGTH + INDEX_LENGTH) / 1048576) AS size_mb,
                   ROUND(INDEX_LENGTH / 1048576) AS idx_mb,
                   TABLE_COMMENT AS note
              FROM information_schema.TABLES
             WHERE TABLE_SCHEMA = %s AND TABLE_TYPE = 'BASE TABLE'
             ORDER BY (DATA_LENGTH + INDEX_LENGTH) DESC
             LIMIT %d""" % (_quote(name), MAX_TABLES_PER_DB),
            host, MAX_TABLES_PER_DB + 5)
        if tbls.get("error"):
            snapshot["cut"].append("%s — таблицы не прочитаны: %s"
                                   % (name, tbls["error"][:120]))
            continue

        rows = _rows(tbls)
        if _num(db.get("tables")) and _num(db.get("tables")) > len(rows):
            snapshot["cut"].append(
                "%s — в снимке %d самых крупных таблиц из %s"
                % (name, len(rows), db.get("tables")))

        # Подробности берём не для всех: столбцы всех таблиц всех баз —
        # это мегабайты, из которых пригодятся десятки строк
        take = rows[:max(0, MAX_DETAIL_TABLES - detailed)]
        detailed += len(take)
        wanted = ", ".join(_quote(t["tbl"]) for t in take if t.get("tbl"))

        columns, indexes = {}, {}
        if wanted:
            cols = await sql_execute(cluster, """
                SELECT TABLE_NAME AS tbl, COLUMN_NAME AS col,
                       COLUMN_TYPE AS type, IS_NULLABLE AS nullable,
                       COLUMN_KEY AS ckey, EXTRA AS extra,
                       COLUMN_COMMENT AS note
                  FROM information_schema.COLUMNS
                 WHERE TABLE_SCHEMA = %s AND TABLE_NAME IN (%s)
                 ORDER BY TABLE_NAME, ORDINAL_POSITION"""
                % (_quote(name), wanted), host, 20000)
            for row in _rows(cols):
                bucket = columns.setdefault(row["tbl"], [])
                if len(bucket) < MAX_COLUMNS:
                    bucket.append({k: row[k] for k in
                                   ("col", "type", "nullable", "ckey",
                                    "extra", "note") if k in row})

            idx = await sql_execute(cluster, """
                SELECT TABLE_NAME AS tbl, INDEX_NAME AS idx,
                       GROUP_CONCAT(COLUMN_NAME ORDER BY SEQ_IN_INDEX) AS cols,
                       MAX(NON_UNIQUE) AS non_unique,
                       MAX(CARDINALITY) AS cardinality
                  FROM information_schema.STATISTICS
                 WHERE TABLE_SCHEMA = %s AND TABLE_NAME IN (%s)
                 GROUP BY TABLE_NAME, INDEX_NAME
                 ORDER BY TABLE_NAME, (INDEX_NAME = 'PRIMARY') DESC, INDEX_NAME"""
                % (_quote(name), wanted), host, 20000)
            for row in _rows(idx):
                indexes.setdefault(row["tbl"], []).append(
                    {k: row[k] for k in ("idx", "cols", "non_unique",
                                         "cardinality") if k in row})

        for t in rows:
            key = "%s.%s" % (name, t.get("tbl"))
            snapshot["tables"][key] = {
                "db": name, "table": t.get("tbl"),
                "engine": t.get("engine"), "rows_est": _num(t.get("rows_est")),
                "size_mb": _num(t.get("size_mb")), "idx_mb": _num(t.get("idx_mb")),
                "note": (t.get("note") or "")[:200],
                "columns": columns.get(t.get("tbl"), []),
                "indexes": indexes.get(t.get("tbl"), []),
            }

    if detailed >= MAX_DETAIL_TABLES:
        snapshot["cut"].append(
            "столбцы и индексы сняты для %d самых крупных таблиц; "
            "для остальных известны только имена и размеры" % detailed)
    snapshot["host"] = dbs.get("host", "")
    return snapshot


# ── Хранение ─────────────────────────────────────────────────────────────

async def save(cluster_name: str, snapshot: dict) -> None:
    """Положить снимок к себе. Один снимок на кластер — прежний заменяется."""
    payload = json.dumps(snapshot, ensure_ascii=False)
    async with session_scope() as session:
        row = (await session.execute(
            select(SchemaSnapshot).where(
                SchemaSnapshot.cluster == cluster_name))).scalar_one_or_none()
        counts = (len(snapshot.get("databases") or []),
                  len(snapshot.get("tables") or {}))
        if row is None:
            session.add(SchemaSnapshot(
                cluster=cluster_name, taken_at=snapshot.get("taken_at") or to_iso(),
                databases=counts[0], tables=counts[1], payload=payload))
        else:
            row.taken_at = snapshot.get("taken_at") or to_iso()
            row.databases, row.tables = counts
            row.payload = payload
    logger.info("Схема %s снята: баз %d, таблиц %d",
                cluster_name, counts[0], counts[1])


async def load(cluster_name: str) -> dict:
    """Снимок из хранилища агента. Пусто — ещё не снимали."""
    async with session_scope() as session:
        row = (await session.execute(
            select(SchemaSnapshot).where(
                SchemaSnapshot.cluster == cluster_name))).scalar_one_or_none()
    if row is None:
        return {}
    try:
        data = json.loads(row.payload)
    except ValueError:
        logger.error("Снимок схемы %s повреждён", cluster_name)
        return {}
    data["taken_at"] = row.taken_at
    return data


# ── Чтение снимка ────────────────────────────────────────────────────────

def describe(snapshot: dict, table: str) -> dict:
    """Столбцы и индексы таблицы — всё, что нужно, чтобы написать выборку."""
    tables = snapshot.get("tables") or {}
    db, tbl = split_table(table)
    if not tbl:
        return {"error": "Не указана таблица"}

    if db:
        found = tables.get("%s.%s" % (db, tbl))
        if not found:
            return {"error": "Таблицы %s.%s нет в снимке" % (db, tbl)}
        return found

    matches = [v for k, v in tables.items() if k.split(".", 1)[1] == tbl]
    if not matches:
        return {"error": "Таблицы %s нет в снимке схемы" % tbl}
    if len(matches) > 1:
        return {"error": "Таблица %s есть в нескольких базах: %s. "
                         "Укажите как база.таблица"
                         % (tbl, ", ".join(m["db"] for m in matches))}
    return matches[0]


def find(snapshot: dict, needle: str) -> dict:
    """Поиск таблиц и столбцов по куску имени.

    Нужен чаще, чем кажется: человек помнит, что «где-то есть про
    договоры», но не помнит — agreements, contracts или dogovor.
    """
    text = str(needle or "").strip().lower()
    if len(text) < 2:
        return {"error": "Слишком короткий запрос: нужно хотя бы два символа"}

    matches = []
    for key, table in (snapshot.get("tables") or {}).items():
        if text in str(table.get("table", "")).lower():
            matches.append({"db": table["db"], "tbl": table["table"],
                            "col": "", "type": "таблица целиком"})
        for col in table.get("columns") or []:
            if text in str(col.get("col", "")).lower():
                matches.append({"db": table["db"], "tbl": table["table"],
                                "col": col.get("col"), "type": col.get("type")})
        if len(matches) >= MAX_MATCHES:
            break
    return {"needle": text, "matches": matches[:MAX_MATCHES]}


# ── Вывод ────────────────────────────────────────────────────────────────

def fmt_snapshot(snapshot: dict, label: str) -> str:
    """Что в снимке: базы, крупные таблицы, когда снято."""
    if not snapshot:
        return ("## Схема базы — %s\n\n"
                "  Схема ещё не снята. Нажмите «Снять схему» на странице "
                "кластера — агент обойдёт information_schema один раз и "
                "запомнит результат у себя.\n"
                "  Пересъёмка доступна администраторам: это обращение к "
                "боевому серверу, и делать его походя не стоит." % label)

    lines = ["## Схема базы — %s" % label, "",
             "  Снято: %s. Числа строк — оценка InnoDB, не точный счёт."
             % str(snapshot.get("taken_at", ""))[:16].replace("T", " "), ""]
    for db in snapshot.get("databases") or []:
        lines.append("  %-24s таблиц %-6s %s МБ, строк ~%s"
                     % (db.get("db"), db.get("tables"),
                        db.get("size_mb"), db.get("rows_est")))

    tables = snapshot.get("tables") or {}
    if tables:
        biggest = sorted(tables.values(),
                         key=lambda t: -(t.get("size_mb") or 0))[:20]
        lines += ["", "  Самые крупные таблицы:"]
        for t in biggest:
            note = (" — " + t["note"]) if t.get("note") else ""
            lines.append("    %-36s строк ~%-10s %s МБ%s"
                         % ("%s.%s" % (t["db"], t["table"]),
                            t.get("rows_est"), t.get("size_mb"), note))

    for note in snapshot.get("cut") or []:
        lines.append("  " + note)
    return "\n".join(lines)


def fmt_describe(data: dict) -> str:
    if data.get("error"):
        return "## Таблица\n\n  %s" % data["error"]
    lines = ["## %s.%s — строк ~%s, %s МБ"
             % (data["db"], data["table"], data.get("rows_est"),
                data.get("size_mb")), "", "  Столбцы:"]
    for c in data.get("columns") or []:
        marks = []
        key = str(c.get("ckey") or "")
        if key == "PRI":
            marks.append("первичный ключ")
        elif key == "UNI":
            marks.append("уникальный")
        elif key == "MUL":
            marks.append("в индексе")
        if str(c.get("nullable")).upper() == "NO":
            marks.append("NOT NULL")
        if c.get("extra"):
            marks.append(str(c["extra"]))
        if c.get("note"):
            marks.append(str(c["note"])[:60])
        lines.append("    %-28s %-22s %s"
                     % (c.get("col"), c.get("type"), ", ".join(marks)))
    if not data.get("columns"):
        lines.append("    Столбцы в снимок не попали: таблица не вошла в число "
                     "тех, для которых снимались подробности.")

    if data.get("indexes"):
        lines += ["", "  Индексы:"]
        for i in data["indexes"]:
            kind = "уникальный" if str(i.get("non_unique")) == "0" else "обычный"
            lines.append("    %-26s (%s) — %s, различных значений ~%s"
                         % (i.get("idx"), i.get("cols"), kind,
                            i.get("cardinality")))
    return "\n".join(lines)


def fmt_find(data: dict) -> str:
    if data.get("error"):
        return "## Поиск по схеме\n\n  %s" % data["error"]
    matches = data.get("matches") or []
    lines = ["## Что нашлось по «%s»" % data.get("needle", ""), ""]
    if not matches:
        lines.append("  Ни таблиц, ни столбцов с таким именем в снимке нет.")
        return "\n".join(lines)
    for m in matches:
        where = "%s.%s" % (m.get("db"), m.get("tbl"))
        lines.append("  %s%s — %s" % (where,
                                      ("." + m["col"]) if m.get("col") else "",
                                      m.get("type")))
    if len(matches) >= MAX_MATCHES:
        lines.append("  (показаны первые %d)" % MAX_MATCHES)
    return "\n".join(lines)


def fmt_brief(snapshot: dict) -> str:
    """Короткая справка для подсказки модели: что вообще есть в базе.

    Именно короткая. Подробности модель дозапросит инструментом; а вот без
    этого верхнего слоя она не знает даже, о каких базах речь, и либо
    отказывается писать выборку, либо выдумывает имена.
    """
    if not snapshot or not snapshot.get("databases"):
        return ""
    lines = ["## Что есть в базе", "",
             "  Имена ниже — настоящие, из снимка схемы. Подробности по "
             "столбцам и индексам запрашивай инструментом get_schema, "
             "не угадывай."]
    tables = snapshot.get("tables") or {}
    for db in (snapshot["databases"])[:6]:
        name = db.get("db")
        names = [t["table"] for t in sorted(
            (t for t in tables.values() if t.get("db") == name),
            key=lambda t: -(t.get("size_mb") or 0))][:25]
        lines.append("")
        lines.append("  %s (%s таблиц, %s МБ):"
                     % (name, db.get("tables"), db.get("size_mb")))
        if names:
            lines.append("    " + ", ".join(names))
    return "\n".join(lines)
