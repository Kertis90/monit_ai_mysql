"""
Разбор настроек MySQL: что выставлено неудачно и чем это грозит.

То, что DBA делает руками раз в год и обычно откладывает. Проверки написаны
не как «должно быть столько-то», а как «вот значение, вот последствие»: у
каждой настройки есть законные причины отличаться от рекомендации, и решение
всё равно принимает человек.

Отдельно отмечается, что можно поменять на ходу, а что требует перезапуска, —
иначе рекомендация бесполезна для дежурного ночью.
"""
from __future__ import annotations

import logging
from typing import Optional

from agent.services.mysql import cluster_db_creds, sql_execute

logger = logging.getLogger("agent.config_audit")

VARIABLES_SQL = "SHOW GLOBAL VARIABLES"
STATUS_SQL    = "SHOW GLOBAL STATUS"

# Переменных в MySQL 8 больше шестисот, счётчиков состояния — около пятисот.
# Общий предел вкладки SQL (200 строк) обрывал ответ посреди алфавита: version,
# sql_mode, sync_binlog и slow_query_log просто не доезжали, и разбор считал
# их незаданными. Здесь нужен полный список.
ALL_ROWS = 5000

# Ключи, которые читаем из вывода. Разбирать всё подряд незачем: в 8.0
# переменных больше шестисот, и отчёт стал бы нечитаемым.
WATCHED = (
    "version", "innodb_buffer_pool_size", "innodb_buffer_pool_instances",
    "innodb_log_file_size", "innodb_redo_log_capacity",
    "innodb_flush_log_at_trx_commit", "innodb_flush_method",
    "innodb_file_per_table", "innodb_io_capacity",
    "sync_binlog", "log_bin", "binlog_format", "binlog_expire_logs_seconds",
    "expire_logs_days", "max_connections", "thread_cache_size",
    "table_open_cache", "open_files_limit", "tmp_table_size",
    "max_heap_table_size", "query_cache_type", "query_cache_size",
    "slow_query_log", "long_query_time", "log_queries_not_using_indexes",
    "performance_schema", "character_set_server", "collation_server",
    "sql_mode", "read_only", "super_read_only", "gtid_mode",
    "innodb_print_all_deadlocks", "max_allowed_packet",
)


def _num(value) -> Optional[float]:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _gb(value) -> str:
    n = _num(value)
    return "%.1f ГБ" % (n / 1073741824) if n else "?"


def _rows_to_dict(result: dict) -> dict:
    return {str(r[0]).lower(): r[1] for r in (result.get("rows") or [])
            if len(r) >= 2}


def _check(items: list, level: str, name: str, value, message: str,
           restart: bool = False) -> None:
    items.append({"level": level, "name": name, "value": value,
                  "message": message, "restart": restart})


def analyse(variables: dict, status: dict, ram_bytes: Optional[int]) -> list:
    """Список замечаний. Пустой — настройки разумны."""
    found: list = []
    version = str(variables.get("version", ""))
    major = version.split(".")[0] if version else ""

    # ── Долговечность транзакций ────────────────────────────────────────────
    flush = variables.get("innodb_flush_log_at_trx_commit")
    sync  = variables.get("sync_binlog")
    if str(flush) != "1" or str(sync) != "1":
        _check(found, "warning",
               "innodb_flush_log_at_trx_commit / sync_binlog",
               "%s / %s" % (flush, sync),
               "Подтверждённые транзакции могут потеряться при внезапном "
               "отключении питания. Обе единицы дают полную долговечность, "
               "но стоят производительности записи — если так сделано "
               "осознанно ради скорости, это нормально, главное чтобы это "
               "было решением, а не случайностью.")

    # ── Буферный пул ────────────────────────────────────────────────────────
    pool = _num(variables.get("innodb_buffer_pool_size"))
    if pool and ram_bytes:
        share = pool / ram_bytes * 100
        if share < 40:
            _check(found, "warning", "innodb_buffer_pool_size", _gb(pool),
                   "Это %.0f%% оперативной памяти сервера (%s). На выделенном "
                   "сервере БД обычно отдают 60-75%%: чем больше рабочий набор "
                   "помещается в память, тем меньше чтений с диска."
                   % (share, _gb(ram_bytes)), restart=False)
        elif share > 85:
            _check(found, "critical", "innodb_buffer_pool_size", _gb(pool),
                   "Это %.0f%% оперативной памяти (%s). Помимо пула память "
                   "нужна соединениям и временным таблицам — при пике сервер "
                   "рискует уйти в своп или быть убитым OOM."
                   % (share, _gb(ram_bytes)))

    # ── Журнал повторов ─────────────────────────────────────────────────────
    redo = (_num(variables.get("innodb_redo_log_capacity"))
            or (_num(variables.get("innodb_log_file_size")) or 0) * 2)
    if pool and redo and redo < pool * 0.15:
        _check(found, "warning", "innodb_log_file_size", _gb(redo),
               "Журнал повторов мал относительно буферного пула (%s). При "
               "интенсивной записи InnoDB начинает принудительно сбрасывать "
               "страницы, и запись упирается не в диск, а в размер журнала."
               % _gb(pool), restart=True)

    # ── Устаревшее ──────────────────────────────────────────────────────────
    if str(variables.get("query_cache_type", "0")) not in ("0", "OFF"):
        _check(found, "warning", "query_cache_type",
               variables.get("query_cache_type"),
               "Кэш запросов включён. На нагруженной базе он чаще вредит: "
               "любая запись в таблицу сбрасывает все связанные записи кэша, "
               "и это делается под общей блокировкой. В 8.0 его убрали совсем.",
               restart=True)

    if str(variables.get("innodb_file_per_table", "ON")).upper() in ("OFF", "0"):
        _check(found, "warning", "innodb_file_per_table", "OFF",
               "Все таблицы лежат в общем ibdata1. Освободить место после "
               "удаления данных без полной пересборки не получится.",
               restart=True)

    # ── Диагностика ─────────────────────────────────────────────────────────
    if str(variables.get("slow_query_log", "OFF")).upper() in ("OFF", "0"):
        _check(found, "warning", "slow_query_log", "OFF",
               "Медленные запросы не записываются — разбирать «тормозит» "
               "будет не по чему. Включается на ходу.")
    else:
        lqt = _num(variables.get("long_query_time"))
        if lqt is not None and lqt >= 5:
            _check(found, "info", "long_query_time", lqt,
                   "Порог в %g с пропускает почти всё: запрос на 2 секунды, "
                   "выполняемый тысячу раз в минуту, в лог не попадёт. "
                   "Обычно ставят 1 с или ниже." % lqt)

    if str(variables.get("performance_schema", "ON")).upper() in ("OFF", "0"):
        _check(found, "critical", "performance_schema", "OFF",
               "Выключена. Без неё недоступны профиль нагрузки, ожидания "
               "блокировок и статистика запросов — то есть почти вся "
               "диагностика агента.", restart=True)

    if str(variables.get("innodb_print_all_deadlocks", "OFF")).upper() in ("OFF", "0"):
        _check(found, "info", "innodb_print_all_deadlocks", "OFF",
               "Взаимные блокировки не пишутся в журнал ошибок — останется "
               "только последняя, а разбирать надо все. Включается на ходу.")

    # ── Соединения и кэши ───────────────────────────────────────────────────
    max_conn = _num(variables.get("max_connections"))
    peak = _num(status.get("max_used_connections"))
    if max_conn and peak:
        share = peak / max_conn * 100
        if share > 80:
            _check(found, "critical", "max_connections", int(max_conn),
                   "Пик соединений достигал %d — это %.0f%% предела. При "
                   "следующем всплеске приложение получит отказ в подключении."
                   % (int(peak), share))
        elif share < 5 and max_conn > 500:
            _check(found, "info", "max_connections", int(max_conn),
                   "Пик за всё время работы — %d. Запас в сто раз означает "
                   "лишнюю память, зарезервированную под соединения."
                   % int(peak))

    opened = _num(status.get("opened_tables"))
    cache  = _num(variables.get("table_open_cache"))
    uptime = _num(status.get("uptime")) or 1
    if opened and cache and opened / uptime > 1:
        _check(found, "warning", "table_open_cache", int(cache),
               "Таблицы открываются заново %.1f раза в секунду — кэш "
               "дескрипторов мал. Увеличивается на ходу."
               % (opened / uptime))

    tmp_disk = _num(status.get("created_tmp_disk_tables"))
    tmp_all  = _num(status.get("created_tmp_tables"))
    if tmp_disk and tmp_all and tmp_all > 1000:
        share = tmp_disk / tmp_all * 100
        if share > 25:
            _check(found, "warning", "tmp_table_size",
                   variables.get("tmp_table_size"),
                   "%.0f%% временных таблиц уходит на диск. Причина — либо "
                   "малый размер (tmp_table_size и max_heap_table_size "
                   "работают в паре, меньший побеждает), либо запросы с BLOB "
                   "и TEXT, которые в память не помещаются в принципе."
                   % share)

    # ── Репликация и журнал ─────────────────────────────────────────────────
    if str(variables.get("log_bin", "OFF")).upper() in ("OFF", "0"):
        _check(found, "critical", "log_bin", "OFF",
               "Двоичный журнал выключен: восстановление на точку во времени "
               "невозможно, реплику не поднять. Требует перезапуска.",
               restart=True)
    else:
        fmt = str(variables.get("binlog_format", "")).upper()
        if fmt and fmt != "ROW":
            _check(found, "warning", "binlog_format", fmt,
                   "Формат %s допускает расхождение данных между источником и "
                   "репликой на недетерминированных запросах. ROW — то, что "
                   "по умолчанию с 5.7." % fmt)
        keep = (_num(variables.get("binlog_expire_logs_seconds"))
                or (_num(variables.get("expire_logs_days")) or 0) * 86400)
        if not keep:
            _check(found, "warning", "binlog_expire_logs_seconds", "0",
                   "Срок хранения двоичных журналов не задан — они будут "
                   "копиться, пока не кончится место на диске.")

    if major == "8" and str(variables.get("gtid_mode", "OFF")).upper() == "OFF":
        _check(found, "info", "gtid_mode", "OFF",
               "Позиционная репликация без GTID: смена источника и разбор "
               "расхождений делаются вручную по координатам журнала.")

    return found


async def audit(cluster: dict, host: Optional[str] = None) -> dict:
    """Разобрать настройки сервера кластера."""
    if not cluster_db_creds(cluster):
        return {"error": "Для кластера не задана учётка db_user — настройки "
                         "прочитать нельзя"}

    variables = await sql_execute(cluster, VARIABLES_SQL, host, ALL_ROWS)
    if variables.get("error"):
        return {"error": "Настройки не прочитаны: %s" % variables["error"]}
    status = await sql_execute(cluster, STATUS_SQL, host, ALL_ROWS)

    values = _rows_to_dict(variables)
    counts = _rows_to_dict(status)
    if "version" not in values:
        # Версия — опора для половины проверок: у 5.7 и 8.0 разные значения по
        # умолчанию. Если её нет, спрашиваем отдельно, а не подставляем «?».
        res = await sql_execute(cluster, "SELECT VERSION() AS v", host)
        if not res.get("error") and res.get("rows"):
            values["version"] = str(res["rows"][0][0])

    ram = None
    try:
        from agent.services.prometheus import http_client, prom_query
        node = "%s:9100" % (host or cluster["primary_ip"])
        async with http_client() as client:
            total = await prom_query(
                client, 'node_memory_MemTotal_bytes{instance="%s"}' % node)
        if total is not None:
            ram = int(float(total))
    except Exception as exc:
        logger.info("Объём памяти не получен: %s", exc)

    findings = analyse(values, counts, ram)
    return {
        "cluster": cluster["name"],
        "host": host or cluster["primary_ip"],
        "version": values.get("version", "?"),
        "ram_bytes": ram,
        "findings": findings,
        "counts": {"critical": sum(1 for f in findings if f["level"] == "critical"),
                   "warning":  sum(1 for f in findings if f["level"] == "warning"),
                   "info":     sum(1 for f in findings if f["level"] == "info")},
        "watched": {k: values.get(k) for k in WATCHED if k in values},
    }


def fmt_audit(data: dict) -> str:
    if data.get("error"):
        return "## Настройки MySQL\n\n  %s" % data["error"]
    if not data["findings"]:
        return ("## Настройки MySQL — %s (версия %s)\n\n"
                "  Замечаний нет: проверенные параметры выставлены разумно."
                % (data["host"], data["version"]))

    mark = {"critical": "ВАЖНО ", "warning": "стоит ", "info": "заметка "}
    lines = ["## Настройки MySQL — %s (версия %s)" % (data["host"], data["version"]),
             "",
             "  Замечаний: %d важных, %d стоит посмотреть, %d к сведению."
             % (data["counts"]["critical"], data["counts"]["warning"],
                data["counts"]["info"]), ""]
    for item in data["findings"]:
        lines.append("  [%s] %s = %s%s"
                     % (mark.get(item["level"], ""), item["name"], item["value"],
                        " (нужен перезапуск)" if item["restart"] else ""))
        lines.append("      " + item["message"])
    return "\n".join(lines)
