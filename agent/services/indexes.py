"""
Лишние индексы: дублирующие и избыточные.

Неиспользуемые индексы диагностика показывает давно. Избыточные она не видит,
а они есть почти в каждой схеме: индекс по `(a)` не нужен, когда рядом есть
`(a, b)` — префикс составного работает и для запросов по одному полю. Такой
индекс занимает место, замедляет каждую вставку и обновление и участвует в
выборе плана, сбивая оптимизатор.

Глазами это в схеме на триста таблиц не найти, а считается одним проходом по
information_schema — без обращения к самим данным.
"""
from __future__ import annotations

import logging
from typing import Optional

from agent.services.mysql import cluster_db_creds, sql_execute

logger = logging.getLogger("agent.indexes")

INDEXES_SQL = """
SELECT s.TABLE_SCHEMA AS db, s.TABLE_NAME AS tbl, s.INDEX_NAME AS idx,
       s.SEQ_IN_INDEX AS pos, s.COLUMN_NAME AS col, s.NON_UNIQUE AS non_unique,
       s.CARDINALITY AS cardinality
  FROM information_schema.STATISTICS s
 WHERE s.TABLE_SCHEMA NOT IN ('mysql', 'sys', 'performance_schema',
                              'information_schema')
 ORDER BY s.TABLE_SCHEMA, s.TABLE_NAME, s.INDEX_NAME, s.SEQ_IN_INDEX"""


def build(rows: list[dict]) -> dict:
    """Собрать индексы по таблицам: {(db, tbl): {idx: {cols, unique}}}."""
    tables: dict = {}
    for row in rows:
        key = (row.get("db"), row.get("tbl"))
        name = row.get("idx")
        entry = tables.setdefault(key, {}).setdefault(
            name, {"cols": [], "unique": str(row.get("non_unique")) == "0",
                   "cardinality": row.get("cardinality")})
        entry["cols"].append(row.get("col"))
    return tables


def find_redundant(tables: dict) -> list[dict]:
    """Индексы, чьи колонки — начало другого индекса той же таблицы.

    Уникальный индекс избыточным не считаем, даже если он префикс другого:
    он держит ограничение целостности, и его удаление меняет поведение базы,
    а не только скорость.
    """
    found = []
    for (db, tbl), indexes in tables.items():
        names = list(indexes)
        for name in names:
            info = indexes[name]
            if info["unique"] or name == "PRIMARY":
                continue
            for other in names:
                if other == name:
                    continue
                cols, wider = info["cols"], indexes[other]["cols"]
                if len(cols) >= len(wider):
                    continue
                if wider[:len(cols)] != cols:
                    continue
                found.append({
                    "table": "%s.%s" % (db, tbl),
                    "index": name, "columns": list(cols),
                    "covered_by": other, "covered_columns": list(wider),
                    "kind": "prefix",
                    "why": "колонки (%s) — начало индекса %s (%s), запросы "
                           "по ним пойдут и через него"
                           % (", ".join(cols), other, ", ".join(wider)),
                })
                break
    return found


def find_duplicates(tables: dict) -> list[dict]:
    """Индексы с одинаковым набором колонок в одном порядке."""
    found = []
    for (db, tbl), indexes in tables.items():
        by_cols: dict = {}
        for name, info in indexes.items():
            by_cols.setdefault(tuple(info["cols"]), []).append((name, info))
        for cols, group in by_cols.items():
            if len(group) < 2:
                continue
            # Оставлять логичнее уникальный или PRIMARY: они несут ограничение
            group.sort(key=lambda g: (not (g[0] == "PRIMARY" or g[1]["unique"]),
                                      g[0]))
            keep = group[0][0]
            for name, _info in group[1:]:
                found.append({
                    "table": "%s.%s" % (db, tbl),
                    "index": name, "columns": list(cols),
                    "covered_by": keep, "covered_columns": list(cols),
                    "kind": "duplicate",
                    "why": "полностью совпадает с индексом %s по тем же "
                           "колонкам (%s)" % (keep, ", ".join(cols)),
                })
    return found


async def analyse(cluster: dict, host: Optional[str] = None) -> dict:
    if not cluster_db_creds(cluster):
        return {"error": "Для кластера не задана учётка db_user — схему "
                         "прочитать нельзя"}
    result = await sql_execute(cluster, INDEXES_SQL, host)
    if result.get("error"):
        return {"error": "Индексы не прочитаны: %s" % result["error"]}

    cols = result.get("columns") or []
    rows = [dict(zip(cols, r)) for r in (result.get("rows") or [])]
    tables = build(rows)
    items = find_duplicates(tables) + find_redundant(tables)
    items.sort(key=lambda i: (i["table"], i["index"]))
    return {
        "cluster": cluster["name"],
        "host": host or cluster["primary_ip"],
        "tables": len(tables),
        "indexes": sum(len(v) for v in tables.values()),
        "items": items,
        "truncated": len(rows) >= 100000,
    }


def fmt_indexes(data: dict) -> str:
    if data.get("error"):
        return "## Лишние индексы\n\n  %s" % data["error"]
    if not data["items"]:
        return ("## Лишние индексы — %s\n\n"
                "  Проверено таблиц: %d, индексов: %d. Дублирующих и "
                "избыточных не найдено."
                % (data["host"], data["tables"], data["indexes"]))

    lines = ["## Лишние индексы — %s" % data["host"], "",
             "  Проверено таблиц: %d, индексов: %d. Найдено лишних: %d."
             % (data["tables"], data["indexes"], len(data["items"])), ""]
    for item in data["items"][:40]:
        lines.append("  %s.%s — %s"
                     % (item["table"], item["index"],
                        "дубликат" if item["kind"] == "duplicate" else "избыточен"))
        lines.append("      " + item["why"])
        lines.append("      DROP INDEX `%s` ON %s;" % (item["index"], item["table"]))
    lines.append("")
    lines.append("  Каждый лишний индекс занимает место и обновляется при "
                 "каждой вставке. Перед удалением стоит убедиться, что он не "
                 "нужен как подсказка оптимизатору: посмотрите "
                 "sys.schema_unused_indexes на боевом сервере, а не на реплике "
                 "— статистика использования у них разная.")
    return "\n".join(lines)
