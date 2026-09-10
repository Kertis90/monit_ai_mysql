"""
Чтение метрик из Prometheus.

Сырые ряды отдаются наружу как есть: графики рисует браузер инлайновым SVG.
В закрытом контуре это единственный рабочий вариант — CDN с библиотеками
графиков недоступен, а серверный рендер тянул бы лишние зависимости.
"""
from __future__ import annotations

import asyncio
import datetime
import time
import logging
from typing import Optional

import httpx

from agent.core.config import settings
from agent.services.registry import cluster_hosts

logger = logging.getLogger("agent.prometheus")

PROMETHEUS_URL   = settings.prometheus.url
MAX_METRICS_HOURS = settings.prometheus.max_metrics_hours
SERIES_MAX_ROWS  = settings.prometheus.series_max_rows
BASELINE_OFFSET_DAYS = settings.prometheus.baseline_offset_days

# Набор показателей для графиков и отчёта. {inst} — primary, {node} — его node,
# {repl} — реплика. Панели без нужных плейсхолдеров пропускаются.
CHART_SPECS = [
    {"key": "qps", "title": "Запросы в секунду", "unit": "/с",
     "expr": 'rate(mysql_global_status_queries{{instance="{inst}"}}[5m])'},
    {"key": "slow", "title": "Медленные запросы", "unit": "/с",
     "expr": 'rate(mysql_global_status_slow_queries{{instance="{inst}"}}[5m])'},
    {"key": "conn", "title": "Подключения", "unit": "",
     "expr": 'mysql_global_status_threads_connected{{instance="{inst}"}}'},
    {"key": "conn_pct", "title": "Использование лимита подключений", "unit": "%",
     "expr": 'mysql_global_status_threads_connected{{instance="{inst}"}}'
             '/mysql_global_variables_max_connections{{instance="{inst}"}}*100'},
    {"key": "innodb_hit", "title": "InnoDB buffer pool hit rate", "unit": "%",
     "expr": '100*(1-(rate(mysql_global_status_innodb_buffer_pool_reads{{instance="{inst}"}}[5m])'
             '/clamp_min(rate(mysql_global_status_innodb_buffer_pool_read_requests'
             '{{instance="{inst}"}}[5m]),1)))'},
    {"key": "cpu", "title": "CPU сервера", "unit": "%",
     "expr": '100-(avg by(instance)(rate(node_cpu_seconds_total'
             '{{mode="idle",instance="{node}"}}[5m]))*100)'},
    {"key": "iowait", "title": "CPU iowait", "unit": "%",
     "expr": 'avg by(instance)(rate(node_cpu_seconds_total'
             '{{mode="iowait",instance="{node}"}}[5m]))*100'},
    {"key": "mem", "title": "Занято памяти", "unit": "%",
     "expr": '100*(1-(node_memory_MemAvailable_bytes{{instance="{node}"}}'
             '/node_memory_MemTotal_bytes{{instance="{node}"}}))'},
    {"key": "disk_io", "title": "Дисковый ввод-вывод", "unit": "Б/с",
     "expr": 'sum(rate(node_disk_read_bytes_total{{instance="{node}"}}[5m])'
             '+rate(node_disk_written_bytes_total{{instance="{node}"}}[5m]))'},
    {"key": "repl_lag", "title": "Отставание реплики сверх плана", "unit": "с",
     "expr": 'mysql:replica_effective_lag_seconds{{instance="{repl}"}}',
     "needs_replica": True},
]



def http_client(**kwargs) -> httpx.AsyncClient:
    """Клиент для внутренних адресов — мимо системного прокси.

    httpx по умолчанию берёт прокси из окружения, а на Windows ещё и из
    реестра. Prometheus, экспортёры и база живут внутри периметра, и
    отправлять запросы к ним через корпоративный прокси незачем: он в
    лучшем случае добавит задержку, в худшем — ответит 503 на собственный
    же адрес, и агент отрапортует «метрик нет» при исправном мониторинге.

    Диагностировать такое почти невозможно: curl с того же сервера
    работает, а агент видит пустоту.
    """
    kwargs.setdefault("trust_env", False)
    return httpx.AsyncClient(**kwargs)


async def prom_query(client: httpx.AsyncClient, query: str) -> Optional[float]:
    try:
        r = await client.get(f"{PROMETHEUS_URL}/api/v1/query",
                             params={"query": query}, timeout=10.0)
        d = r.json()
        if d.get("status") == "success" and d["data"]["result"]:
            return round(float(d["data"]["result"][0]["value"][1]), 3)
    except Exception:
        pass
    return None


def parse_series(data: dict, key_label: str = "") -> dict:
    """Ответ Prometheus -> {метка: значение} по всем рядам.

    prom_query отдаёт одно число — первое попавшееся. Этого хватает, когда
    ряд заведомо один (соединения сервера), но не когда их несколько:
    файловых систем на сервере с десяток, и «первая попавшаяся» — не ответ.

    key_label — по какой метке различать ряды. Пусто — берём первую
    подходящую: точку монтирования, устройство, цель.
    """
    out: dict = {}
    if not isinstance(data, dict) or data.get("status") != "success":
        return out
    for item in (data.get("data", {}).get("result") or []):
        metric = item.get("metric") or {}
        key = metric.get(key_label) if key_label else ""
        if not key:
            key = (metric.get("mountpoint") or metric.get("device")
                   or metric.get("instance") or str(len(out)))
        try:
            out[key] = float(item["value"][1])
        except (KeyError, IndexError, TypeError, ValueError):
            continue
    return out


async def prom_query_map(client: httpx.AsyncClient, query: str,
                         key_label: str = "") -> dict:
    """Все ряды ответа, а не только первый."""
    try:
        r = await client.get(f"{PROMETHEUS_URL}/api/v1/query",
                             params={"query": query}, timeout=10.0)
        return parse_series(r.json(), key_label)
    except Exception:
        return {}


async def prom_range_summary(client: httpx.AsyncClient, query: str,
                             hours: float) -> dict:
    """Мин/макс/среднее за период + время пиков."""
    end   = datetime.datetime.utcnow()
    start = end - datetime.timedelta(hours=hours)
    step  = "300" if hours > 6 else "60"
    try:
        r = await client.get(
            f"{PROMETHEUS_URL}/api/v1/query_range",
            params={"query": query,
                    "start": start.isoformat() + "Z",
                    "end":   end.isoformat() + "Z",
                    "step":  step},
            timeout=15.0)
        d = r.json()
        if d.get("status") == "success" and d["data"]["result"]:
            vals = [(v[0], float(v[1])) for v in d["data"]["result"][0]["values"]]
            if not vals:
                return {}
            vs      = [v[1] for v in vals]
            max_i   = vs.index(max(vs))
            min_i   = vs.index(min(vs))
            fmt     = lambda ts: datetime.datetime.utcfromtimestamp(ts).strftime("%H:%M UTC")
            return {
                "min":      round(min(vs), 2),
                "max":      round(max(vs), 2),
                "avg":      round(sum(vs) / len(vs), 2),
                "max_time": fmt(vals[max_i][0]),
                "min_time": fmt(vals[min_i][0]),
            }
    except Exception:
        pass
    return {}


# Наименьшее осмысленное окно. Уже минуты график состоит из одной точки:
# Prometheus скрейпит раз в 15 секунд.
MIN_WINDOW_S = 60


def resolve_window(hours: float = 0, since: float = 0,
                   until: float = 0) -> tuple:
    """Границы окна из «за N часов» или из явно указанных «с» и «по».

    Возвращает (начало, конец, часов) — всё в Unix-времени, чтобы не
    зависеть от часового пояса ни браузера, ни сервера: в разных городах
    кластеры живут в разных поясах, и «с 3:00» без указания, чьи это три
    часа, ничего не значит.

    Границы приводятся к разумным: перевёрнутый интервал разворачивается,
    будущее обрезается по «сейчас», а слишком широкое окно сужается до
    предела с сохранением конца — интересен обычно свежий край.
    """
    now = time.time()
    if since and until:
        start, end = float(min(since, until)), float(max(since, until))
        end = min(end, now)
        if end - start < MIN_WINDOW_S:
            start = end - MIN_WINDOW_S
        limit = MAX_METRICS_HOURS * 3600
        if end - start > limit:
            start = end - limit
        return start, end, (end - start) / 3600.0

    span = max(min(float(hours or 3), MAX_METRICS_HOURS), MIN_WINDOW_S / 3600.0)
    return now - span * 3600, now, span


async def prom_range_series(client: httpx.AsyncClient, query: str,
                            hours: float = 0, since: float = 0,
                            until: float = 0) -> list[list]:
    """Сырой ряд [[unix_ts, значение], ...] — для отрисовки графика."""
    start_ts, end_ts, span = resolve_window(hours, since, until)
    # ~200 точек на график: больше браузеру не нужно, меньше — теряется форма
    step  = max(int(span * 3600 / 200), 15)
    try:
        r = await client.get(
            f"{PROMETHEUS_URL}/api/v1/query_range",
            params={"query": query,
                    "start": "%.0f" % start_ts,
                    "end":   "%.0f" % end_ts,
                    "step":  str(step)},
            timeout=20.0)
        d = r.json()
        if d.get("status") != "success" or not d["data"]["result"]:
            return []
        return [[int(float(v[0])), round(float(v[1]), 3)]
                for v in d["data"]["result"][0]["values"]]
    except Exception as e:
        logger.error(f"Не удалось получить ряд для графика: {e}")
        return []


async def build_charts(cluster: dict, hours: float = 0,
                       keys: Optional[list[str]] = None,
                       since: float = 0, until: float = 0) -> list[dict]:
    """Собрать данные графиков по кластеру за период.

    Период задаётся либо длиной («за 3 часа»), либо границами («с … по …»).
    Второе нужно, когда разбирают конкретный случай: «вчера в 17:40 всё
    встало» — и смотреть надо ровно вокруг этого времени, а не последние
    сутки, внутри которых всплеск теряется.
    """
    prim = cluster["primary_ip"]
    repl = cluster.get("replica_ip", "")
    ctx  = {"inst": f"{prim}:9104", "node": f"{prim}:9100",
            "repl": f"{repl}:9104" if repl else ""}

    specs = [s for s in CHART_SPECS
             if (not s.get("needs_replica") or repl)
             and (not keys or s["key"] in keys)]

    async with http_client() as client:
        series = await asyncio.gather(
            *[prom_range_series(client, s["expr"].format(**ctx), hours,
                                since, until)
              for s in specs])

    charts = []
    for spec, points in zip(specs, series):
        if not points:
            continue
        vals = [p[1] for p in points]
        charts.append({
            "key":    spec["key"],
            "title":  spec["title"],
            "unit":   spec["unit"],
            "points": points,
            "min":    round(min(vals), 2),
            "max":    round(max(vals), 2),
            "avg":    round(sum(vals) / len(vals), 2),
            "last":   vals[-1],
        })
    return charts


async def collect_current(cluster: dict) -> dict:
    """Текущие метрики кластера (async, параллельно)."""
    async with http_client() as client:
        async def metrics_for(ip: str) -> dict:
            inst  = f"{ip}:9104"
            node  = f"{ip}:9100"
            queries = {
                "mysql_up":            f'mysql_up{{instance="{inst}"}}',
                "qps":                 f'rate(mysql_global_status_queries{{instance="{inst}"}}[5m])',
                "slow_qps":            f'rate(mysql_global_status_slow_queries{{instance="{inst}"}}[5m])',
                "connections_pct":     f'mysql_global_status_threads_connected{{instance="{inst}"}}/mysql_global_variables_max_connections{{instance="{inst}"}}*100',
                "connections_now":     f'mysql_global_status_threads_connected{{instance="{inst}"}}',
                "innodb_hit_pct":      f'(1-rate(mysql_global_status_innodb_buffer_pool_reads{{instance="{inst}"}}[5m])/rate(mysql_global_status_innodb_buffer_pool_read_requests{{instance="{inst}"}}[5m]))*100',
                "row_lock_waits":      f'rate(mysql_global_status_innodb_row_lock_waits{{instance="{inst}"}}[5m])',
                "aborted_connects":    f'rate(mysql_global_status_aborted_connects{{instance="{inst}"}}[5m])',
                "cpu_pct":             f'100-(avg by(instance)(rate(node_cpu_seconds_total{{mode="idle",instance="{node}"}}[5m]))*100)',
                "memory_pct":          f'(node_memory_MemTotal_bytes{{instance="{node}"}}-node_memory_MemAvailable_bytes{{instance="{node}"}})/node_memory_MemTotal_bytes{{instance="{node}"}}*100',
                "disk_free_pct":       f'node_filesystem_avail_bytes{{instance="{node}",mountpoint="/"}}/node_filesystem_size_bytes{{instance="{node}",mountpoint="/"}}*100',
                "iowait_pct":          f'avg by(instance)(rate(node_cpu_seconds_total{{mode="iowait",instance="{node}"}}[5m]))*100',
            }
            keys    = list(queries.keys())
            results = await asyncio.gather(*[prom_query(client, queries[k]) for k in keys])
            return {k: (str(v) if v is not None else "нет данных")
                    for k, v in zip(keys, results)}

        out = {
            "cluster_name":  cluster["name"],
            "cluster_label": cluster["label"],
            "primary":       await metrics_for(cluster["primary_ip"]),
        }
        repl_ip = cluster.get("replica_ip")
        if repl_ip:
            rep  = await metrics_for(repl_ip)
            inst = f"{repl_ip}:9104"
            lag, io, sql, planned = await asyncio.gather(
                prom_query(client, f'mysql_slave_status_seconds_behind_master{{instance="{inst}"}}'),
                prom_query(client, f'mysql_slave_status_slave_io_running{{instance="{inst}"}}'),
                prom_query(client, f'mysql_slave_status_slave_sql_running{{instance="{inst}"}}'),
                # Плановая задержка — из SQL_Delay самой реплики (recording rule
                # его вычисляет и подставляет запасное значение из реестра)
                prom_query(client, f'mysql:replica_configured_delay_seconds{{instance="{inst}"}}'),
            )
            # Отставание СВЕРХ плана считает Prometheus тем же правилом, что
            # питает дашборд и алерты. Не дублируем расчёт здесь: разъехавшиеся
            # цифры в чате и на графике — худшее, что может быть при разборе.
            over = await prom_query(
                client, f'mysql:replica_effective_lag_seconds{{instance="{inst}"}}')

            plan_s = float(planned) if planned is not None else 0.0
            if over is None and lag is not None:
                # правило ещё не подгрузилось — считаем сами, чтобы не молчать
                over = max(float(lag) - plan_s, 0)

            rep["replication_planned_delay_s"]  = (
                str(plan_s) if planned is not None else "нет данных")
            rep["replication_lag_over_plan_s"]  = (
                str(over) if over is not None else "нет данных")
            rep["replication_lag_raw_s"] = str(lag) if lag is not None else "нет данных"
            rep["replication_io_up"]  = str(io)  if io  is not None else "нет данных"
            rep["replication_sql_up"] = str(sql) if sql is not None else "нет данных"
            out["replica"] = rep
        return out


async def collect_history(cluster: dict, hours: float) -> dict:
    """История: min/avg/max + время пиков по ключевым метрикам."""
    prim = cluster["primary_ip"]
    repl = cluster.get("replica_ip", "")
    inst = f"{prim}:9104"

    async with http_client() as client:
        queries = {
            "qps":             f'rate(mysql_global_status_queries{{instance="{inst}"}}[5m])',
            "slow_qps":        f'rate(mysql_global_status_slow_queries{{instance="{inst}"}}[5m])',
            "connections_pct": f'mysql_global_status_threads_connected{{instance="{inst}"}}/mysql_global_variables_max_connections{{instance="{inst}"}}*100',
            "cpu_pct":         f'100-(avg by(instance)(rate(node_cpu_seconds_total{{mode="idle",instance="{prim}:9100"}}[5m]))*100)',
            "iowait_pct":      f'avg by(instance)(rate(node_cpu_seconds_total{{mode="iowait",instance="{prim}:9100"}}[5m]))*100',
            "row_lock_waits":  f'rate(mysql_global_status_innodb_row_lock_waits{{instance="{inst}"}}[5m])',
        }
        if repl:
            # Тот же recording rule, что у дашборда и алертов
            queries["replication_lag_over_plan_s"] = (
                f'mysql:replica_effective_lag_seconds{{instance="{repl}:9104"}}')

        keys    = list(queries.keys())
        results = await asyncio.gather(
            *[prom_range_summary(client, queries[k], hours) for k in keys])

        return {"period_hours": hours,
                **{k: v for k, v in zip(keys, results)}}
