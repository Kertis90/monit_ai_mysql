"""
Что нагружает базу ПРЯМО СЕЙЧАС.

`events_statements_summary_by_digest` копит суммы с момента запуска сервера.
На базе с аптаймом полгода топ по `SUM_TIMER_WAIT` показывает, что грузило её
в среднем за полгода, — а запрос, который положил всё минуту назад, может
оказаться на двадцатой строке или вовсе не попасть в выборку.

Поэтому снимаем два среза с интервалом и вычитаем. То же со счётчиками
состояния: `Innodb_rows_read` за всё время бесполезен, прирост за минуту —
нет.
"""
from __future__ import annotations

import asyncio
import logging
import os
from typing import Optional

from agent.services.mysql import cluster_db_creds, sql_execute

logger = logging.getLogger("agent.workload")

# Интервал между срезами. Меньше пяти секунд — в дельту попадает шум и
# случайные единичные запросы; больше минуты — человек не дождётся ответа.
# На это время ответ в чате задерживается, поэтому значение настраиваемое.
DEFAULT_WINDOW_S = max(5.0, min(60.0,
                       float(os.environ.get("WORKLOAD_WINDOW_S", "10"))))
MIN_WINDOW_S = 5
MAX_WINDOW_S = 60

# Текст дайджеста режется на сервере: там значения уже заменены на «?»,
# и сверхдлинный нормализованный запрос читать всё равно невозможно. Полный
# текст с настоящими значениями берётся из processlist — см. ACTIVE_SQL.
DIGEST_SQL = """
SELECT DIGEST                         AS digest,
       LEFT(DIGEST_TEXT, 900)         AS query,
       SCHEMA_NAME                    AS db,
       COUNT_STAR                     AS calls,
       SUM_TIMER_WAIT                 AS time_ps,
       SUM_ROWS_EXAMINED              AS examined,
       SUM_ROWS_SENT                  AS sent,
       SUM_NO_INDEX_USED              AS no_index,
       SUM_LOCK_TIME                  AS lock_ps
  FROM performance_schema.events_statements_summary_by_digest
 WHERE SCHEMA_NAME IS NOT NULL AND DIGEST IS NOT NULL
 LIMIT 2000"""

# Счётчики, прирост которых говорит о характере нагрузки. Прирост, не сумма:
# по сумме нельзя отличить «всегда так» от «началось десять минут назад».
STATUS_VARS = (
    "Questions", "Com_select", "Com_insert", "Com_update", "Com_delete",
    "Slow_queries", "Innodb_rows_read", "Innodb_rows_inserted",
    "Innodb_rows_updated", "Innodb_rows_deleted", "Created_tmp_disk_tables",
    "Select_full_join", "Select_scan", "Table_locks_waited",
    "Threads_running", "Threads_connected", "Aborted_clients",
    "Innodb_buffer_pool_reads", "Innodb_buffer_pool_read_requests",
)

STATUS_SQL = ("SHOW GLOBAL STATUS WHERE Variable_name IN (%s)"
              % ", ".join("'%s'" % v for v in STATUS_VARS))

# Что выполняется прямо сейчас — целиком, с настоящими значениями.
#
# Дайджест performance_schema отвечает на вопрос «что грузило базу за окно»,
# но текст в нём нормализован: литералы заменены на «?», а сама строка
# обрезана по performance_schema_max_digest_length. Для «покажи мне этот
# запрос» это не годится: по нему нельзя ни повторить, ни объяснить, почему
# он читает миллион строк именно сегодня.
#
# SHOW FULL PROCESSLIST даёт полный текст того, что исполняется в эту
# секунду. Одно без другого неполно, поэтому показываем оба.
ACTIVE_SQL = "SHOW FULL PROCESSLIST"

# Сколько строк processlist забирать. На занятой базе соединений бывают
# тысячи, но подавляющее большинство спит.
ACTIVE_MAX_ROWS = 500

# Длина запроса в отчёте. Обрезаем только совсем гигантские — многотысячный
# IN (...) не несёт информации сверх первых строк, а отчёт делает нечитаемым.
QUERY_MAX_CHARS = 4000


def _rows_as_dicts(result: dict) -> list[dict]:
    cols = result.get("columns") or []
    return [dict(zip(cols, row)) for row in (result.get("rows") or [])]


def _num(value) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


async def active_queries(cluster: dict, host: Optional[str] = None,
                         limit: int = 12) -> dict:
    """Незаснувшие соединения: что выполняется и сколько уже длится.

    Спящие отбрасываем: их обычно девять из десяти, и они ничего не говорят
    о нагрузке. Число их всё же считаем — «соединений 400, из них 398 спят»
    само по себе диагноз.
    """
    res = await sql_execute(cluster, ACTIVE_SQL, host, ACTIVE_MAX_ROWS)
    if res.get("error"):
        return {"error": res["error"]}

    rows = _rows_as_dicts(res)
    # Регистр имён колонок различается между сборками и режимами доступа
    def field(row: dict, *names):
        for name in names:
            for key in row:
                if key.lower() == name:
                    return row[key]
        return None

    sleeping, busy = 0, []
    for row in rows:
        command = str(field(row, "command") or "")
        query = (field(row, "info") or "")
        if command.lower() == "sleep" or not str(query).strip():
            sleeping += 1
            continue
        text = " ".join(str(query).split())
        cut = len(text) > QUERY_MAX_CHARS
        busy.append({
            "id":      field(row, "id"),
            "user":    str(field(row, "user") or ""),
            "from":    str(field(row, "host") or ""),
            "db":      str(field(row, "db") or ""),
            "command": command,
            "time_s":  _num(field(row, "time")),
            "state":   str(field(row, "state") or ""),
            "query":   text[:QUERY_MAX_CHARS] + ("…" if cut else ""),
            "cut":     cut,
        })

    busy.sort(key=lambda r: -r["time_s"])
    return {"total": len(rows), "sleeping": sleeping,
            "items": busy[:limit], "busy_total": len(busy)}


async def _snapshot(cluster: dict, host: Optional[str]) -> tuple:
    """Срез: профиль запросов и счётчики состояния одним заходом."""
    digest, status = await asyncio.gather(
        sql_execute(cluster, DIGEST_SQL, host),
        sql_execute(cluster, STATUS_SQL, host))
    return digest, status


def _digest_delta(before: dict, after: dict, limit: int) -> list[dict]:
    """Разница между срезами по каждому запросу.

    Пропавшие между срезами digest'ы игнорируем: таблица могла быть очищена
    или вытеснена по размеру, и отрицательная дельта означала бы не спад
    нагрузки, а потерю базы для сравнения.
    """
    was = {r["digest"]: r for r in _rows_as_dicts(before)}
    out = []
    for row in _rows_as_dicts(after):
        old = was.get(row["digest"])
        calls = _num(row["calls"]) - (_num(old["calls"]) if old else 0)
        time_ps = _num(row["time_ps"]) - (_num(old["time_ps"]) if old else 0)
        if calls <= 0 or time_ps <= 0:
            continue
        examined = _num(row["examined"]) - (_num(old["examined"]) if old else 0)
        sent     = _num(row["sent"])     - (_num(old["sent"])     if old else 0)
        lock_ps  = _num(row["lock_ps"])  - (_num(old["lock_ps"])  if old else 0)
        no_index = _num(row["no_index"]) - (_num(old["no_index"]) if old else 0)
        out.append({
            "query":     (row.get("query") or "").strip(),
            "db":        row.get("db") or "",
            "calls":     int(calls),
            "total_s":   round(time_ps / 1e12, 3),
            "avg_ms":    round(time_ps / 1e9 / calls, 2),
            "lock_s":    round(lock_ps / 1e12, 3),
            "examined":  int(examined),
            "sent":      int(sent),
            # Отношение просмотренных строк к отданным: 1 — идеально,
            # тысячи — запрос перелопачивает таблицу ради нескольких строк
            "ratio":     round(examined / sent, 1) if sent else None,
            "no_index":  int(no_index),
            "new":       old is None,
        })
    out.sort(key=lambda r: -r["total_s"])
    return out[:limit]


def _status_delta(before: dict, after: dict, seconds: float) -> dict:
    was = {r[0]: r[1] for r in (before.get("rows") or [])}
    out = {}
    for name, value in (after.get("rows") or []):
        old = was.get(name)
        if old is None:
            continue
        diff = _num(value) - _num(old)
        # Threads_* — мгновенные значения, а не счётчики: их прирост
        # бессмыслен, показываем как есть
        if name.startswith("Threads_"):
            out[name] = {"value": int(_num(value))}
        elif diff >= 0:
            out[name] = {"delta": int(diff),
                         "per_sec": round(diff / seconds, 1) if seconds else 0}
    return out


async def workload_delta(cluster: dict, seconds: float = DEFAULT_WINDOW_S,
                         host: Optional[str] = None,
                         limit: int = 10) -> dict:
    """Профиль нагрузки за окно: что реально исполнялось в эти секунды."""
    if not cluster_db_creds(cluster):
        return {"error": "Для кластера не задана учётка db_user — "
                         "профиль нагрузки недоступен"}
    window = max(MIN_WINDOW_S, min(MAX_WINDOW_S, float(seconds)))

    first_digest, first_status = await _snapshot(cluster, host)
    if first_digest.get("error"):
        return {"error": "Профиль нагрузки не собран: %s"
                         % first_digest["error"]}

    await asyncio.sleep(window)
    # Второй срез и живой processlist — одним заходом: они должны описывать
    # один и тот же момент, иначе «сейчас выполняется» окажется про другое
    (second_digest, second_status), active = await asyncio.gather(
        _snapshot(cluster, host), active_queries(cluster, host))
    if second_digest.get("error"):
        return {"error": "Второй срез не снят: %s" % second_digest["error"]}

    queries = _digest_delta(first_digest, second_digest, limit)
    status  = _status_delta(first_status, second_status, window)

    # Долго висящий запрос — первый кандидат на разбор, и план для него
    # можно взять прямо с работающего соединения. Спрашивать об этом
    # отдельной кнопкой значит терять время там, где его и так нет.
    plans = []
    try:
        from agent.services import explain as explain_service
        plans = await explain_service.explain_running(
            cluster, (active or {}).get("items") or [], host)
    except Exception as exc:
        logger.info("Планы для идущих запросов не получены: %s", exc)
    return {
        "host":    second_digest.get("host", ""),
        "window":  window,
        "queries": queries,
        "status":  status,
        "active":  active,
        "plans":   plans,
        # Пустой список — не ошибка: база могла просто простаивать
        "idle":    not queries,
    }


def fmt_workload(data: dict, label: str) -> str:
    """Блок для подсказки модели и для человека."""
    if data.get("error"):
        return "## Профиль нагрузки %s\n\n  %s" % (label, data["error"])

    window = data["window"]
    lines = ["## Профиль нагрузки %s за последние %g с" % (label, window), "",
             "  Это ПРИРОСТ за окно, а не сумма с момента запуска сервера:",
             "  показано то, что исполнялось именно сейчас.", ""]

    status = data.get("status") or {}
    if status:
        def rate(name):
            item = status.get(name) or {}
            return item.get("per_sec", item.get("value", "—"))
        lines.append("  Запросов/с: %s, из них медленных/с: %s"
                     % (rate("Questions"), rate("Slow_queries")))
        lines.append("  Активных потоков: %s, соединений: %s"
                     % (rate("Threads_running"), rate("Threads_connected")))
        reads = (status.get("Innodb_buffer_pool_reads") or {}).get("delta", 0)
        req   = (status.get("Innodb_buffer_pool_read_requests") or {}).get("delta", 0)
        if req:
            # Промахи буферного пула за окно: устойчиво высокий процент
            # означает, что рабочий набор перестал помещаться в память
            lines.append("  Промахи буферного пула: %.2f%% (%d из %d)"
                         % (reads * 100.0 / req, reads, req))
        for name in ("Created_tmp_disk_tables", "Select_full_join",
                     "Select_scan", "Table_locks_waited"):
            item = status.get(name)
            if item and item.get("delta"):
                lines.append("  %s: +%d за окно" % (name, item["delta"]))
        lines.append("")

    lines += _fmt_active(data.get("active") or {})

    if data.get("plans"):
        from agent.services.explain import fmt_running_plans
        lines.append(fmt_running_plans(data["plans"]))
        lines.append("")

    if data.get("idle"):
        lines.append("  За это окно ни один запрос не завершился — база "
                     "простаивала. Если жалуются на медленную работу, "
                     "проблема не в нагрузке на SQL.")
        return "\n".join(lines)

    lines.append("  Топ запросов по времени за окно:")
    for i, q in enumerate(data["queries"], 1):
        mark = " (новый)" if q["new"] else ""
        lines.append("  %d. %s c всего, %s вызовов, %s мс в среднем%s"
                     % (i, q["total_s"], q["calls"], q["avg_ms"], mark))
        detail = ["просмотрено %d строк" % q["examined"],
                  "отдано %d" % q["sent"]]
        if q["ratio"] is not None and q["ratio"] >= 100:
            detail.append("на строку результата просмотрено %.0f — вероятно, "
                          "не хватает индекса" % q["ratio"])
        if q["no_index"]:
            detail.append("%d раз без индекса" % q["no_index"])
        if q["lock_s"] >= 0.01:
            detail.append("в блокировках %s c" % q["lock_s"])
        lines.append("       " + ", ".join(detail))
        lines.append("       %s" % " ".join(q["query"].split())[:900])
    lines.append("")
    lines.append("  Текст выше нормализован: значения заменены на «?», и это "
                 "суммы по одинаковым запросам.")
    lines.append("  Целиком, с настоящими значениями — в списке выполняемых "
                 "сейчас.")
    return "\n".join(lines)


def _fmt_active(active: dict) -> list:
    """Список того, что выполняется прямо сейчас, полными запросами."""
    if not active:
        return []
    if active.get("error"):
        return ["  Список выполняемых запросов не прочитан: %s"
                % active["error"], ""]

    total, sleeping = active.get("total", 0), active.get("sleeping", 0)
    items = active.get("items") or []
    out = ["  Выполняется прямо сейчас (SHOW FULL PROCESSLIST):"]
    if not items:
        out.append("    Ничего: все %d соединений простаивают." % total)
        out.append("")
        return out

    out.append("    Соединений %d, из них спящих %d, работают %d."
               % (total, sleeping, active.get("busy_total", len(items))))
    out.append("")
    for i, q in enumerate(items, 1):
        where = q["user"] + ("@" + q["from"].split(":")[0] if q["from"] else "")
        head = "  %d. %.0f с · %s" % (i, q["time_s"], where)
        if q["db"]:
            head += " · база " + q["db"]
        if q["state"]:
            head += " · " + q["state"]
        out.append(head)
        out.append("       " + q["query"])
    out.append("")
    return out
