"""
Сбор материала для ответа: база сравнения, диффы, лента событий,
диагностический набор и форматирование блоков контекста.

Всё, что попадает в подсказку модели, собирается здесь — так видно, из чего
складывается ответ, и любой блок можно проверить отдельно.
"""
from __future__ import annotations

import asyncio
import datetime
import logging
import os
import re
from typing import Optional

import httpx

from agent.core.config import settings
from agent.services.intents import parse_step_seconds
from agent.services.mysql import (cluster_db_creds, db_versions_text,
                                  fmt_sql_result, sql_execute)
from agent.services.prometheus import (collect_current, collect_history,
                                       http_client, prom_query,
                                       prom_range_series, prom_range_summary)
from agent.services.registry import (cluster_hosts, clusters_index_text,
                                     enabled_clusters)

logger = logging.getLogger("agent.analysis")

# Сколько диагностических запросов выполняем одновременно. Больше — быстрее,
# но в режиме туннеля каждый запрос поднимает свой ssh.
DIAG_PARALLEL = max(1, int(os.environ.get("DIAG_PARALLEL", "4")))

BASELINE_OFFSET_DAYS = settings.prometheus.baseline_offset_days
BASELINE_WEEKS       = settings.prometheus.baseline_weeks
SERIES_MAX_ROWS      = settings.prometheus.series_max_rows
MAX_METRICS_HOURS    = settings.prometheus.max_metrics_hours
ALERTS_RETENTION_DAYS = settings.db.alerts_retention_days
PROMETHEUS_URL        = settings.prometheus.url

CONFIG_DIFF_SQL = """SELECT VARIABLE_NAME, VARIABLE_VALUE
  FROM performance_schema.global_variables
 WHERE VARIABLE_NAME IN (
   'max_connections','innodb_buffer_pool_size','innodb_log_file_size',
   'innodb_flush_log_at_trx_commit','sync_binlog','read_only','super_read_only',
   'slow_query_log','long_query_time','log_timestamps','sql_mode',
   'transaction_isolation','character_set_server','collation_server',
   'innodb_io_capacity','innodb_flush_method','table_open_cache',
   'tmp_table_size','max_heap_table_size','binlog_format','gtid_mode')"""

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

DIAG_QUERIES = [
    {
        "key": "top_queries", "title": "Самые тяжёлые запросы (по суммарному времени)",
        "why": "показывает, куда реально уходит время сервера",
        "sql": """SELECT DIGEST_TEXT AS query, COUNT_STAR AS calls,
       ROUND(SUM_TIMER_WAIT/1e12, 2) AS total_sec,
       ROUND(AVG_TIMER_WAIT/1e9, 2)  AS avg_ms,
       SUM_ROWS_EXAMINED AS rows_examined, SUM_ROWS_SENT AS rows_sent
  FROM performance_schema.events_statements_summary_by_digest
 WHERE SCHEMA_NAME IS NOT NULL
 ORDER BY SUM_TIMER_WAIT DESC LIMIT 10""",
    },
    {
        "key": "full_scans", "title": "Запросы с полным сканированием таблиц",
        "why": "нехватка индексов — самая частая причина роста нагрузки",
        "sql": """SELECT DIGEST_TEXT AS query, COUNT_STAR AS calls,
       SUM_ROWS_EXAMINED AS rows_examined,
       ROUND(SUM_TIMER_WAIT/1e12, 2) AS total_sec
  FROM performance_schema.events_statements_summary_by_digest
 WHERE SUM_NO_INDEX_USED > 0 AND SCHEMA_NAME IS NOT NULL
 ORDER BY SUM_TIMER_WAIT DESC LIMIT 10""",
    },
    {
        "key": "active", "title": "Активные сессии прямо сейчас",
        "why": "видно долгие и подвисшие запросы",
        "sql": """SELECT ID, USER, HOST, DB, COMMAND, TIME, STATE,
       LEFT(INFO, 200) AS query
  FROM information_schema.PROCESSLIST
 WHERE COMMAND <> 'Sleep'
 ORDER BY TIME DESC LIMIT 20""",
    },
    {
        "key": "waits", "title": "Ожидания по типам событий",
        "why": "различает упор в диск, в блокировки и в сеть",
        "sql": """SELECT EVENT_NAME, COUNT_STAR AS waits,
       ROUND(SUM_TIMER_WAIT/1e12, 2) AS total_sec
  FROM performance_schema.events_waits_summary_global_by_event_name
 WHERE COUNT_STAR > 0 AND EVENT_NAME <> 'idle'
 ORDER BY SUM_TIMER_WAIT DESC LIMIT 15""",
    },
    {
        "key": "table_io", "title": "Таблицы с наибольшим вводом-выводом",
        "why": "указывает, какие таблицы греют диск",
        "sql": """SELECT OBJECT_SCHEMA AS db, OBJECT_NAME AS tbl,
       COUNT_READ AS reads, COUNT_WRITE AS writes,
       ROUND(SUM_TIMER_WAIT/1e12, 2) AS total_sec
  FROM performance_schema.table_io_waits_summary_by_table
 WHERE OBJECT_SCHEMA NOT IN ('mysql','performance_schema','sys')
 ORDER BY SUM_TIMER_WAIT DESC LIMIT 10""",
    },
    {
        "key": "file_io", "title": "Файлы с наибольшим вводом-выводом",
        "why": "подтверждает или опровергает упор в диск",
        "sql": """SELECT FILE_NAME AS file, COUNT_READ AS reads, COUNT_WRITE AS writes,
       ROUND(SUM_NUMBER_OF_BYTES_READ/1048576, 1)  AS read_mb,
       ROUND(SUM_NUMBER_OF_BYTES_WRITE/1048576, 1) AS write_mb
  FROM performance_schema.file_summary_by_instance
 ORDER BY SUM_TIMER_WAIT DESC LIMIT 10""",
    },
    {
        "key": "locks", "title": "Ожидания блокировок",
        "why": "кто кого блокирует прямо сейчас",
        "sql": """SELECT waiting_pid, waiting_query, blocking_pid, blocking_query,
       wait_age
  FROM sys.innodb_lock_waits LIMIT 10""",
        "optional": True,
    },
    {
        "key": "unused_idx", "title": "Неиспользуемые индексы",
        "why": "лишние индексы замедляют запись и занимают память",
        "sql": """SELECT object_schema AS db, object_name AS tbl, index_name
  FROM sys.schema_unused_indexes LIMIT 20""",
        "optional": True,
    },
    {
        "key": "conn", "title": "Подключения и потоки",
        "why": "показывает упор в max_connections и отказы",
        "sql": """SHOW GLOBAL STATUS WHERE Variable_name IN
       ('Threads_connected','Threads_running','Max_used_connections',
        'Aborted_connects','Connection_errors_max_connections')""",
    },
    {
        "key": "innodb", "title": "Состояние InnoDB",
        "why": "буферный пул, ожидания строк, дедлоки",
        "sql": "SHOW ENGINE INNODB STATUS",
        "optional": True,
    },
]


def _median(values: list) -> Optional[float]:
    vals = sorted(v for v in values if isinstance(v, (int, float)))
    if not vals:
        return None
    mid = len(vals) // 2
    return vals[mid] if len(vals) % 2 else (vals[mid - 1] + vals[mid]) / 2


async def collect_baseline(cluster: dict, hours: float) -> dict:
    """Те же метрики в обычный такой же день — чтобы было с чем сравнивать.

    Без базы «QPS 1200» ничего не значит: модель не знает, много это или мало,
    и вынуждена гадать.

    Берём не одну точку неделю назад, а медиану по нескольким неделям на тот
    же день недели и час. Одна точка ненадёжна: если ровно неделю назад был
    сбой, праздник или разовая выгрузка, база оказывается кривой, и агент
    объявит аномалией нормальную нагрузку — или наоборот. Медиана выбросы
    отбрасывает, а суточный и недельный профиль сохраняет: ночной бэкап
    сравнивается с ночным бэкапом, а не со средним по суткам.
    """
    # Недели опрашиваем параллельно: последовательно это вчетверо дольше,
    # а ответ в чате ждёт именно этого блока
    weeks = await asyncio.gather(
        *[_baseline_at(cluster, hours, BASELINE_OFFSET_DAYS * w)
          for w in range(1, BASELINE_WEEKS + 1)])
    known = [w for w in weeks if w]

    out = {"offset_days": BASELINE_OFFSET_DAYS,
           "weeks": len(known), "weeks_asked": BASELINE_WEEKS}
    if not known:
        return out
    for key in known[0]:
        for stat in ("avg", "min", "max"):
            value = _median([w.get(key, {}).get(stat) for w in known])
            if value is not None:
                out.setdefault(key, {})[stat] = round(value, 2)
    return out


async def _baseline_at(cluster: dict, hours: float, days_ago: int) -> dict:
    """Срез метрик со смещением на указанное число суток назад."""
    prim = cluster["primary_ip"]
    inst = f"{prim}:9104"
    off  = f"{days_ago * 24}h"

    queries = {
        "qps":             f'rate(mysql_global_status_queries{{instance="{inst}"}}[5m] offset {off})',
        "slow_qps":        f'rate(mysql_global_status_slow_queries{{instance="{inst}"}}[5m] offset {off})',
        "connections_pct": (f'mysql_global_status_threads_connected{{instance="{inst}"}} offset {off}'
                            f'/mysql_global_variables_max_connections{{instance="{inst}"}} offset {off}*100'),
        "cpu_pct":         (f'100-(avg by(instance)(rate(node_cpu_seconds_total'
                            f'{{mode="idle",instance="{prim}:9100"}}[5m] offset {off}))*100)'),
        "iowait_pct":      (f'avg by(instance)(rate(node_cpu_seconds_total'
                            f'{{mode="iowait",instance="{prim}:9100"}}[5m] offset {off}))*100'),
    }
    async with http_client() as client:
        keys = list(queries.keys())
        res  = await asyncio.gather(
            *[prom_range_summary(client, queries[k], hours) for k in keys])
    # Пустой срез — эта неделя за пределами хранения Prometheus либо сервер
    # тогда не опрашивался. В медиану её просто не берём.
    return {k: v for k, v in zip(keys, res) if v}


def fmt_baseline(now: dict, base: dict, label: str) -> str:
    """Сравнение «сейчас против недели назад» с относительным изменением."""
    rows = []
    for k, cur in now.items():
        if k in ("period_hours", "offset_days") or not isinstance(cur, dict):
            continue
        old = base.get(k)
        if not isinstance(old, dict) or not old.get("avg"):
            continue
        try:
            delta = (cur["avg"] - old["avg"]) / abs(old["avg"]) * 100
        except (TypeError, ZeroDivisionError):
            continue
        mark = "выше" if delta > 0 else "ниже"
        rows.append(f"  {k}: сейчас {cur['avg']}, обычно {old['avg']} "
                    f"({abs(delta):.0f}% {mark})")
    if not rows:
        return ""
    weeks = base.get("weeks", 0)
    if weeks > 1:
        source = (f"  Медиана за {weeks} недель на тот же день недели и час — "
                  f"разовый сбой или праздник в одной из них базу не искажает.")
    else:
        source = (f"  Те же метрики {base['offset_days']} дн. назад, тот же "
                  f"день недели и час. Данных всего за одну неделю, поэтому "
                  f"разовый выброс в ней мог попасть в базу — учитывай это.")
    return (f"## Сравнение с обычным днём — {label}\n\n" + source + "\n"
            f"  Отклонение в пределах 20-30% обычно норма.\n\n"
            + "\n".join(rows))


async def collect_config_diff(cluster: dict) -> str:
    """Сравнить параметры primary и replica.

    Расхождения между серверами одного кластера — частая причина странного
    поведения: реплика с другим buffer pool или flush-политикой ведёт себя
    иначе при той же нагрузке.
    """
    hosts = cluster_hosts(cluster)
    if len(hosts) < 2 or not cluster_db_creds(cluster):
        return ""

    results = {}
    for ip, role in hosts:
        res = await sql_execute(cluster, CONFIG_DIFF_SQL, ip)
        if res.get("error"):
            return (f"## Конфигурация {cluster['label']}\n\n"
                    f"  Не удалось сравнить: {res['error'][:160]}")
        results[role] = {r[0]: r[1] for r in res["rows"]}

    roles = list(results.keys())
    a, b = results[roles[0]], results[roles[1]]
    diff = [(k, a.get(k), b.get(k)) for k in sorted(set(a) | set(b))
            if a.get(k) != b.get(k)]
    if not diff:
        return (f"## Конфигурация {cluster['label']}\n\n"
                f"  Ключевые параметры primary и replica совпадают.")

    out = [f"## Расхождения конфигурации {cluster['label']}", "",
           f"  Параметр | {roles[0]} | {roles[1]}",
           "  ---------+----------+----------"]
    for k, va, vb in diff:
        out.append(f"  {k} | {va} | {vb}")
    out.append("")
    out.append("  Часть расхождений нормальна (read_only на реплике), "
               "но остальные объясни.")
    return "\n".join(out)


def build_timeline(alerts: list, extra_events: Optional[list] = None) -> str:
    """Все события одной лентой по времени.

    Метрики, логи и алерты приходят разными блоками, и модель сопоставляет их
    сама. Одна отсортированная лента показывает причинно-следственную связь
    сразу: всплеск iowait, следом таймаут в логе, следом алерт.
    """
    events = []
    for a in alerts:
        ts = (a.get("timestamp") or "")[:19].replace("T", " ")
        events.append((ts, f"АЛЕРТ  {a.get('severity','?'):8} {a.get('alert')} "
                           f"— {a.get('cluster_label') or '—'}"))
    for e in (extra_events or []):
        events.append((e.get("ts", ""), e.get("text", "")))

    events = [e for e in events if e[0]]
    if not events:
        return ""
    events.sort(key=lambda e: e[0])
    lines = ["## Лента событий (UTC, по времени)", ""]
    lines += [f"  {ts}  {txt}" for ts, txt in events[-60:]]
    return "\n".join(lines)


async def explain_top_queries(cluster: dict, host: str, limit: int = 3) -> str:
    """Планы выполнения самых тяжёлых запросов + схема их таблиц.

    Без плана ответ упирается в «запрос медленный». С планом получается
    «полное сканирование orders, нет индекса по (created, status)» —
    и конкретная команда CREATE INDEX.

    Ограничение: в performance_schema хранится DIGEST_TEXT с «?» вместо
    значений. EXPLAIN такой текст обычно принимает, но не всегда — неудачи
    пропускаем молча, они ожидаемы.
    """
    if not cluster_db_creds(cluster):
        return ""

    top = await sql_execute(cluster, """
        SELECT DIGEST_TEXT, ROUND(SUM_TIMER_WAIT/1e12, 2) AS total_sec,
               COUNT_STAR, SUM_ROWS_EXAMINED
          FROM performance_schema.events_statements_summary_by_digest
         WHERE SCHEMA_NAME IS NOT NULL AND DIGEST_TEXT LIKE 'SELECT%'
         ORDER BY SUM_TIMER_WAIT DESC LIMIT 5""", host)
    if top.get("error") or not top.get("rows"):
        return ""

    out, done = [], 0
    tables_seen = set()
    for row in top["rows"]:
        if done >= limit:
            break
        digest = (row[0] or "").strip()
        if not digest:
            continue
        # «?» — плейсхолдеры дайджеста. Подставляем 1: для плана этого хватает,
        # а разбирать типы параметров тут негде.
        query = digest.replace("?", "1")
        plan = await sql_execute(cluster, "EXPLAIN " + query, host)
        if plan.get("error"):
            logger.info("EXPLAIN пропущен: %s", plan["error"][:90])
            continue

        done += 1
        out.append(f"### Запрос {done} — {row[1]} с суммарно, "
                   f"{row[2]} вызовов, строк просмотрено {row[3]}")
        out.append("  " + digest[:400])
        out.append(fmt_sql_result(plan).split("\n", 1)[1].lstrip("\n"))

        # схемы таблиц из плана: без них рекомендации по индексам вслепую
        for prow in plan.get("rows", []):
            tbl = next((str(v) for c, v in zip(plan["columns"], prow)
                        if c.lower() == "table" and v), "")
            if tbl and tbl not in tables_seen and len(tables_seen) < 4:
                tables_seen.add(tbl)
                ddl = await sql_execute(cluster, "SHOW CREATE TABLE " + tbl, host)
                if not ddl.get("error") and ddl.get("rows"):
                    out.append(f"  Схема {tbl}:")
                    out.append("  " + str(ddl["rows"][0][-1])[:900])
        out.append("")

    if not out:
        return ""
    return (f"## Планы выполнения тяжёлых запросов ({host})\n\n"
            f"  EXPLAIN для самых дорогих SELECT и схемы их таблиц.\n"
            f"  Используй это для конкретных рекомендаций по индексам.\n\n"
            + "\n".join(out))


async def run_diagnostics(cluster: dict, host: Optional[str] = None,
                          keys: Optional[list] = None) -> list:
    """Выполнить диагностический набор. Недоступные запросы пропускаются:
    sys.innodb_lock_waits и часть представлений есть не во всех сборках."""
    if not cluster_db_creds(cluster):
        return []

    wanted = [q for q in DIAG_QUERIES if not keys or q["key"] in keys]

    # По очереди набор идёт минутами и не укладывается в терпение прокси, а
    # запросы независимы. Но и разом их пускать нельзя: в режиме туннеля
    # каждый поднимает свой ssh, и десяток одновременных — это десяток
    # процессов и соединений к базе.
    gate = asyncio.Semaphore(DIAG_PARALLEL)

    async def run(q):
        async with gate:
            return await sql_execute(cluster, q["sql"], host)

    results = await asyncio.gather(*[run(q) for q in wanted])

    out = []
    for q, res in zip(wanted, results):
        if res.get("error"):
            # необязательные молча пропускаем — иначе половина отчёта
            # состояла бы из «нет доступа к sys»
            if not q.get("optional"):
                out.append({**q, "result": res})
            else:
                logger.info(f"Диагностика: {q['key']} пропущен ({res['error'][:80]})")
            continue
        out.append({**q, "result": res})
    return out


def fmt_diagnostics(items: list, label: str, host: str) -> str:
    if not items:
        return ""
    head = [f"## Диагностика {label} ({host})", "",
            "  Данные собраны агентом по методике Performance Schema.",
            "  Опирайся на них, а не на общие рекомендации.", ""]
    for it in items:
        head.append(f"### {it['title']} — {it['why']}")
        head.append(fmt_sql_result(it["result"]).split("\n", 1)[1].lstrip("\n"))
        head.append("")
    return "\n".join(head)


def now_text() -> str:
    """Текущие дата и время для промпта.

    Без этого модель берёт дату из своих обучающих данных и уверенно пишет
    позапрошлый год — а все выводы про «вчера» и «на прошлой неделе»
    оказываются про не тот период.
    """
    MONTHS = ("января", "февраля", "марта", "апреля", "мая", "июня", "июля",
              "августа", "сентября", "октября", "ноября", "декабря")
    DAYS = ("понедельник", "вторник", "среда", "четверг",
            "пятница", "суббота", "воскресенье")
    utc   = datetime.datetime.utcnow()
    local = datetime.datetime.now()
    return (f"СЕГОДНЯ: {local.day} {MONTHS[local.month - 1]} {local.year} года, "
            f"{DAYS[local.weekday()]}, {local:%H:%M} по времени сервера "
            f"({utc:%Y-%m-%d %H:%M} UTC).\n"
            f"Дата в формате ISO: {local:%Y-%m-%d}. Текущий год: {local.year}.\n"
            f"Считай «сегодня», «вчера», «на прошлой неделе» ОТ ЭТОЙ ДАТЫ, "
            f"а не от даты из своих обучающих данных.")


def system_prompt() -> str:
    return f"""Ты — опытный DBA и SRE со специализацией на MySQL/InnoDB и репликации.
Ты обслуживаешь MySQL-кластеры (primary + replica) в разных городах.

{now_text()}

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
    предупреждением.

11. ДИАГНОСТИКА. Если приложен блок «Диагностика …» — агент уже выполнил
    набор запросов Performance Schema. Разбирай по методике:
      1) есть ли проблема вообще — по метрикам и активным сессиям;
      2) куда уходит время — самые тяжёлые запросы по суммарному времени,
         а не по числу вызовов;
      3) почему они тяжёлые — полное сканирование, ожидания блокировок,
         ввод-вывод по таблицам и файлам;
      4) упирается ли в ресурсы сервера — сопоставь с CPU, iowait, памятью;
      5) что делать — конкретные индексы, переписывание запросов, параметры.
    Называй конкретные запросы (DIGEST_TEXT), таблицы и цифры из блока.
    Общие советы уровня «включите slow query log» без опоры на эти данные
    не давай — данные уже собраны. Если часть запросов отсутствует
    (нет прав или представлений sys), скажи об этом и какие права нужны.

12. ЧЕГО НЕ ВИДЕЛ — О ТОМ НЕ СУДИ. Если приложен блок «Чего собрать не
    удалось», перечисленных данных у тебя НЕТ. Не пиши «проблем не
    обнаружено» про то, что не проверялось: отсутствие блока и отсутствие
    проблемы — разные вещи. Назови в ответе, какой проверки не хватило и что
    сделать, чтобы она заработала. Ответ, собранный по половине данных,
    должен выглядеть именно так, а не как полный.

13. НАГРУЗКА СЕЙЧАС И ЗА ВСЁ ВРЕМЯ — РАЗНОЕ. Блок «Профиль нагрузки» — это
    прирост за окно в несколько секунд, то есть что исполнялось именно
    сейчас. Блок диагностики по performance_schema — суммы с момента запуска
    сервера, то есть средние за всё время его работы. При разборе «тормозит
    прямо сейчас» опирайся на профиль; накопленное используй, только чтобы
    сказать, новая это нагрузка или всегдашняя.

14. РЕПЛИКАЦИЯ. Отставание на величину запланированной задержки
    (MASTER_DELAY) — норма, а не авария: смотри строку «сверх плана».
    Seconds_Behind_Source на простаивающем источнике показывает 0 даже при
    реальном отставании, поэтому сверяй его с позицией журнала и метриками."""


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

    async with http_client() as client:
        series = await asyncio.gather(
            *[one(client, expr.format(w=w, **ctx)) for _, expr in SERIES_SPECS])

    names  = [n for n, _ in SERIES_SPECS]
    stamps = sorted({t for s in series for t in s})
    return {"step_s": step_s, "adjusted": adjusted, "hours": hours,
            "host": ip, "role": role,
            "names": names, "stamps": stamps, "series": series}


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
