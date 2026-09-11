"""
EXPLAIN как инструмент, а не как приложение к отчёту.

План выполнения отвечает на вопрос, на который нельзя ответить по метрикам:
почему именно этот запрос медленный. «Запрос выполняется 4 секунды» — это
наблюдение; «читает таблицу целиком, потому что индекс по (created, status)
не подходит под порядок условий» — это уже причина и действие.

Сам по себе вывод EXPLAIN читается не всеми: шесть столбцов сокращений, где
значение `type=ALL` важнее всего остального, а `Using filesort` в поле Extra
значит не «использует сортировку», а «сортирует без индекса, в памяти или на
диске». Поэтому план не просто показывается, а разбирается: находки словами,
с указанием, что именно делать.

Две формы. Первая — план для написанного запроса. Вторая — план для запроса,
который выполняется прямо сейчас: `EXPLAIN FOR CONNECTION`. Вторая ценнее в
аварии, когда запрос виден в списке процессов, но воспроизвести его негде.
"""
from __future__ import annotations

import json
import logging
import re
from typing import Optional

from agent.services.mysql import (cluster_db_creds, fmt_sql_result,
                                  server_version, sql_execute, sql_validate)

logger = logging.getLogger("agent.explain")

# Сколько схем таблиц прикладывать. Без схемы рекомендация по индексам —
# гадание: неизвестно, какие индексы уже есть и какого типа столбцы.
MAX_SCHEMAS = 4

# Строк оценки, выше которой полное чтение таблицы перестаёт быть мелочью
BIG_SCAN_ROWS = 10000


def _cell(row: list, cols: list, name: str):
    for col, value in zip(cols, row):
        if col.lower() == name:
            return value
    return None


def findings(plan: dict) -> list:
    """Что в плане заслуживает внимания. Словами, а не сокращениями."""
    cols = plan.get("columns") or []
    out = []

    for row in plan.get("rows") or []:
        table = _cell(row, cols, "table") or "?"
        access = str(_cell(row, cols, "type") or "").lower()
        key = _cell(row, cols, "key")
        possible = _cell(row, cols, "possible_keys")
        extra = str(_cell(row, cols, "extra") or "")
        select_type = str(_cell(row, cols, "select_type") or "")
        try:
            rows_est = int(float(_cell(row, cols, "rows") or 0))
        except (TypeError, ValueError):
            rows_est = 0

        if access == "all":
            if possible and not key:
                out.append({
                    "level": "critical", "table": table,
                    "what": "таблица читается целиком, хотя подходящий индекс есть",
                    "why": "оптимизатор не взял %s — обычно это устаревшая "
                           "статистика или условие, под которое индекс не "
                           "подходит по порядку столбцов" % possible,
                    "do": "ANALYZE TABLE %s, затем посмотреть план снова; если "
                          "не помогло — проверить порядок столбцов в индексе"
                          % table})
            else:
                level = "critical" if rows_est >= BIG_SCAN_ROWS else "warning"
                out.append({
                    "level": level, "table": table,
                    "what": "таблица читается целиком (%s строк по оценке)" % rows_est,
                    "why": "подходящего индекса нет вовсе",
                    "do": "добавить индекс под условия WHERE и JOIN этого запроса"})
        elif access == "index":
            out.append({
                "level": "warning", "table": table,
                "what": "читается весь индекс, а не его часть",
                "why": "условие не сужает диапазон — индекс используется как "
                       "замена таблице, но читается целиком",
                "do": "проверить, стоит ли первый столбец индекса в WHERE"})

        if "using filesort" in extra.lower():
            out.append({
                "level": "warning", "table": table,
                "what": "сортировка идёт без индекса",
                "why": "порядок в ORDER BY не совпадает с порядком индекса; "
                       "при большом объёме сортировка уходит на диск",
                "do": "индекс, где столбцы ORDER BY идут следом за столбцами "
                      "равенства из WHERE"})

        if "using temporary" in extra.lower():
            out.append({
                "level": "warning", "table": table,
                "what": "создаётся временная таблица",
                "why": "GROUP BY или DISTINCT нельзя выполнить по индексу",
                "do": "индекс под GROUP BY либо переписать запрос так, чтобы "
                      "группировка шла по индексированному столбцу"})

        if "using join buffer" in extra.lower():
            out.append({
                "level": "critical", "table": table,
                "what": "соединение без индекса (join buffer)",
                "why": "для каждой строки одной таблицы перебирается пачка "
                       "строк другой — стоимость растёт как произведение",
                "do": "индекс на столбце соединения таблицы %s" % table})

        if select_type.upper() in ("DEPENDENT SUBQUERY", "UNCACHEABLE SUBQUERY"):
            out.append({
                "level": "critical", "table": table,
                "what": "подзапрос выполняется для каждой строки",
                "why": "он зависит от внешнего запроса, поэтому результат не "
                       "переиспользуется",
                "do": "переписать через JOIN или вынести в отдельный запрос"})

    return out


def estimated_rows(plan: dict) -> int:
    """Во сколько строк обойдётся запрос по оценке оптимизатора.

    Оценки строк перемножаются: вложенные циклы — это произведение, а не
    сумма. Тысяча на тысячу — это миллион, и в плане это видно только так.
    """
    cols = plan.get("columns") or []
    total = 1
    seen = False
    for row in plan.get("rows") or []:
        try:
            value = int(float(_cell(row, cols, "rows") or 0))
        except (TypeError, ValueError):
            continue
        if value > 0:
            total *= value
            seen = True
    return total if seen else 0


def plan_tables(plan: dict) -> list:
    """Таблицы из плана, в порядке появления, без производных."""
    cols = plan.get("columns") or []
    out = []
    for row in plan.get("rows") or []:
        name = str(_cell(row, cols, "table") or "").strip()
        # <derived2>, <union1,2> — не таблицы, схему у них не спросить
        if name and not name.startswith("<") and name not in out:
            out.append(name)
    return out


async def explain(cluster: dict, sql: str = "", connection_id: int = 0,
                  host: Optional[str] = None, with_schema: bool = True) -> dict:
    """План выполнения: для написанного запроса или для идущего соединения."""
    if not cluster_db_creds(cluster):
        return {"error": "Для кластера не задана учётка db_user — "
                         "план выполнения получить нельзя"}

    if connection_id:
        version, _ = await server_version(cluster, host)
        if version != (0, 0, 0) and version[:2] < (5, 7):
            return {"error": "EXPLAIN FOR CONNECTION появился в MySQL 5.7; "
                             "здесь %s" % ".".join(str(n) for n in version)}
        statement = "EXPLAIN FOR CONNECTION %d" % int(connection_id)
    else:
        sql = (sql or "").strip().rstrip(";")
        if not sql:
            return {"error": "Нечего объяснять: запрос пуст"}
        # Второй EXPLAIN поверх уже написанного не нужен и не работает
        if re.match(r"^\s*explain\b", sql, re.I):
            statement = sql
        else:
            ok, why = sql_validate(sql)
            if not ok:
                return {"error": "Запрос отклонён: %s" % why}
            statement = "EXPLAIN " + sql

    plan = await sql_execute(cluster, statement, host)
    if plan.get("error"):
        return {"error": _explain_hint(plan["error"], bool(connection_id))}

    data = {
        "host": plan.get("host", ""),
        "statement": statement,
        "plan": plan,
        "findings": findings(plan),
        "rows_estimate": estimated_rows(plan),
        "schemas": [],
    }

    if with_schema:
        for table in plan_tables(plan)[:MAX_SCHEMAS]:
            ddl = await sql_execute(cluster, "SHOW CREATE TABLE " + table, host)
            if not ddl.get("error") and ddl.get("rows"):
                data["schemas"].append({"table": table,
                                        "ddl": str(ddl["rows"][0][-1])})
    return data


# С какой длительности запрос стоит объяснять сам собой. Секунда — это
# шум, пять секунд на боевой базе — уже повод посмотреть план.
SLOW_NOW_SECONDS = 5
MAX_RUNNING_PLANS = 3


async def explain_running(cluster: dict, items: list,
                          host: Optional[str] = None,
                          min_seconds: float = SLOW_NOW_SECONDS,
                          limit: int = MAX_RUNNING_PLANS) -> list:
    """Планы для запросов, которые выполняются прямо сейчас и долго.

    Это тот случай, ради которого EXPLAIN FOR CONNECTION и существует:
    запрос висит, его видно в списке процессов, но воспроизвести его
    негде — параметры неизвестны, а данные за время разбирательства
    изменятся. План при этом можно взять прямо с работающего соединения.

    Схемы таблиц к таким планам не прикладываем: разбор идёт по горячим
    следам, и лишние обращения к базе, которой и так плохо, тут ни к чему.
    """
    slow = [q for q in (items or [])
            if (q.get("time_s") or 0) >= min_seconds and q.get("id")]
    slow.sort(key=lambda q: -(q.get("time_s") or 0))

    out = []
    for q in slow[:limit]:
        data = await explain(cluster, connection_id=int(q["id"]), host=host,
                             with_schema=False)
        # Запрос мог закончиться, пока мы до него шли — это нормально и
        # ничего не значит
        if data.get("error") and "уже завершилось" in data["error"]:
            continue
        out.append({"id": q["id"], "time_s": q.get("time_s"),
                    "query": q.get("query", ""), "plan": data})
    return out


def fmt_running_plans(plans: list) -> str:
    """Планы висящих запросов с выводами, без пересказа самого плана."""
    if not plans:
        return ""
    lines = ["  Планы выполнения для запросов, которые идут прямо сейчас:"]
    for item in plans:
        lines.append("")
        lines.append("  Соединение %s, идёт %.0f с:"
                     % (item["id"], item.get("time_s") or 0))
        lines.append("    " + " ".join(str(item.get("query", "")).split())[:300])
        data = item.get("plan") or {}
        if data.get("error"):
            lines.append("    План не получен: " + str(data["error"])[:200])
            continue
        found = data.get("findings") or []
        if not found:
            lines.append("    План без замечаний: запрос идёт по индексам, "
                         "долго — не из-за плана.")
            continue
        for f in found:
            lines.append("    [%s] %s — %s"
                         % ("ВАЖНО" if f["level"] == "critical" else "стоит",
                            f["table"], f["what"]))
            lines.append("         " + f["do"])
    return "\n".join(lines)


def _explain_hint(error: str, for_connection: bool) -> str:
    """Отказ EXPLAIN почти всегда упирается в права, и в разные.

    Сообщение сервера про «lacking privileges for underlying table» звучит
    так, будто не хватает SELECT, хотя не хватает SHOW VIEW. Подсказываем
    то, чего действительно недостаёт.
    """
    low = error.lower()
    if "lacking privileges" in low or "show view" in low:
        return (error + "\n  Запрос идёт через представление (VIEW): для него "
                        "EXPLAIN требует право SHOW VIEW сверх SELECT.\n"
                        "  GRANT SHOW VIEW ON *.* TO 'ai_agent'@'...';")
    if for_connection and ("access denied" in low or "process" in low):
        return (error + "\n  EXPLAIN FOR CONNECTION для чужого соединения "
                        "требует право PROCESS.\n"
                        "  GRANT PROCESS ON *.* TO 'ai_agent'@'...';")
    if for_connection and "unknown thread id" in low:
        return (error + "\n  Соединение уже завершилось — запрос успел "
                        "закончиться или его прервали.")
    return error


def fmt_explain(data: dict) -> str:
    """Отчёт: сначала выводы, потом сам план, потом схемы."""
    if data.get("error"):
        return "## План выполнения\n\n  %s" % data["error"]

    lines = ["## План выполнения (%s)" % data.get("host", ""), "",
             "  " + data["statement"][:400], ""]

    rows_est = data.get("rows_estimate") or 0
    if rows_est:
        lines.append("  Оценка просмотренных строк: %d — произведение оценок "
                     "по шагам плана," % rows_est)
        lines.append("  потому что вложенные циклы перемножаются, а не "
                     "складываются.")
        lines.append("")

    found = data.get("findings") or []
    if not found:
        lines.append("  Ничего тревожного в плане нет: таблицы читаются по "
                     "индексам, сортировка и группировка не требуют временных "
                     "таблиц.")
    else:
        mark = {"critical": "ВАЖНО ", "warning": "стоит "}
        lines.append("  Что не так:")
        for item in found:
            lines.append("    [%s] %s — %s"
                         % (mark.get(item["level"], ""), item["table"],
                            item["what"]))
            lines.append("        причина: " + item["why"])
            lines.append("        что делать: " + item["do"])
        lines.append("")

    lines.append("  Сам план:")
    plan_text = fmt_sql_result(data["plan"]).split("\n", 1)[1].lstrip("\n")
    lines.append(plan_text)

    for schema in data.get("schemas") or []:
        lines.append("")
        lines.append("  Схема %s:" % schema["table"])
        for line in str(schema["ddl"]).split("\n")[:40]:
            lines.append("    " + line)
    return "\n".join(lines)
