"""
Когда кончится: место, соединения, автоинкременты.

Алерт «занято 85%» сообщает о состоянии, но не о запасе времени. «При нынешнем
росте место кончится через трое суток» — это то, с чем можно что-то сделать
заранее.

Отдельная история — автоинкременты. Переполнение `int` в большой таблице
случается внезапно и кладёт запись на часы, хотя предсказуемо за месяцы. В
мониторинге эта проверка почти никогда не настроена, потому что метрики для
неё нет: считается запросом к information_schema.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Optional

import httpx

from agent.core.config import settings
from agent.services.mysql import cluster_db_creds, sql_execute
from agent.services.prometheus import prom_query
from agent.services.registry import cluster_hosts

logger = logging.getLogger("agent.forecast")

# Тревожные пороги в сутках. Меньше недели — уже надо шевелиться, меньше
# месяца — планировать.
CRITICAL_DAYS = 7
WARNING_DAYS  = 30

# Наблюдаем рост по неделе: за сутки в оценку попадает суточная волна,
# за месяц — уже устаревшие темпы после чистки
TREND_WINDOW = "7d"

# Предельные значения целочисленных типов MySQL
INT_LIMITS = {
    "tinyint":   (127, 255),
    "smallint":  (32767, 65535),
    "mediumint": (8388607, 16777215),
    "int":       (2147483647, 4294967295),
    "integer":   (2147483647, 4294967295),
    "bigint":    (9223372036854775807, 18446744073709551615),
}

AUTO_INCREMENT_SQL = """
SELECT t.TABLE_SCHEMA AS db, t.TABLE_NAME AS tbl, c.COLUMN_NAME AS col,
       c.DATA_TYPE AS dtype, c.COLUMN_TYPE AS ctype,
       t.AUTO_INCREMENT AS cur, t.TABLE_ROWS AS rows_est
  FROM information_schema.TABLES t
  JOIN information_schema.COLUMNS c
    ON c.TABLE_SCHEMA = t.TABLE_SCHEMA
   AND c.TABLE_NAME   = t.TABLE_NAME
   AND c.EXTRA        = 'auto_increment'
 WHERE t.AUTO_INCREMENT IS NOT NULL
   AND t.TABLE_SCHEMA NOT IN ('mysql', 'sys', 'performance_schema',
                              'information_schema')
 ORDER BY t.AUTO_INCREMENT DESC
 LIMIT 50"""


def _level(days: Optional[float]) -> str:
    if days is None:
        return "unknown"
    if days <= CRITICAL_DAYS:
        return "critical"
    if days <= WARNING_DAYS:
        return "warning"
    return "ok"


def _days_left(remaining: float, per_day: float) -> Optional[float]:
    """Сколько суток до нуля при нынешнем темпе. None — не растёт или убывает."""
    if per_day <= 0 or remaining < 0:
        return None
    return round(remaining / per_day, 1)


async def disk_forecast(cluster: dict) -> list[dict]:
    """Когда кончится место на дисках серверов кластера.

    Берём остаток и производную по неделе: линейная экстраполяция здесь
    честнее сложных моделей — база растёт равномерно, а рывки всё равно
    непредсказуемы.
    """
    out = []
    async with httpx.AsyncClient() as client:
        for ip, role in cluster_hosts(cluster):
            node = f'{ip}:9100'
            # Только реальные файловые системы: tmpfs и overlay не интересны
            base = (f'node_filesystem_avail_bytes{{instance="{node}",'
                    f'fstype!~"tmpfs|overlay|squashfs|ramfs"}}')
            avail, slope, size = await asyncio.gather(
                prom_query(client, base),
                prom_query(client, f'deriv({base}[{TREND_WINDOW}])'),
                prom_query(client, base.replace("avail", "size")))
            if not isinstance(avail, dict):
                continue
            for key, free in avail.items():
                # Убыль в байтах в секунду -> прирост занятого за сутки
                per_day = -float(slope.get(key, 0) or 0) * 86400
                total = float(size.get(key, 0) or 0)
                days = _days_left(float(free), per_day)
                out.append({
                    "host": ip, "role": role, "mount": key,
                    "free_gb": round(float(free) / 1073741824, 1),
                    "total_gb": round(total / 1073741824, 1) if total else None,
                    "used_pct": (round((1 - float(free) / total) * 100, 1)
                                 if total else None),
                    "growth_gb_day": round(per_day / 1073741824, 2),
                    "days_left": days,
                    "level": _level(days),
                })
    out.sort(key=lambda r: (r["days_left"] is None, r["days_left"] or 0))
    return out


async def connections_forecast(cluster: dict) -> dict:
    """Когда упрёмся в max_connections при нынешнем росте.

    Считаем по threads_connected, а не по max_used_connections. Причин две.
    Первая: max_used_connections отдают не все сборки экспортёра, и раздел
    молча оставался пустым. Вторая: это отметка «самого высокого уровня» с
    момента запуска сервера, она почти никогда не убывает — темп роста по
    ней получался ложный.

    Пик берём как max_over_time за окно: это настоящий максимум за неделю,
    а не средняя занятость, — упираемся мы именно в пики. Рост — разница
    пика с таким же окном неделю назад: сравнение сопоставимых величин
    устойчивее производной по шумному ряду.
    """
    inst = f'{cluster["primary_ip"]}:9104'
    conn_metric = f'mysql_global_status_threads_connected{{instance="{inst}"}}'
    async with httpx.AsyncClient() as client:
        peak_now, peak_before, cap_raw, now_raw = await asyncio.gather(
            prom_query(client, f'max_over_time({conn_metric}[{TREND_WINDOW}])'),
            prom_query(client,
                       f'max_over_time({conn_metric}[{TREND_WINDOW}] '
                       f'offset {TREND_WINDOW})'),
            prom_query(client,
                       f'mysql_global_variables_max_connections{{instance="{inst}"}}'),
            prom_query(client, conn_metric))

    def one(value):
        if isinstance(value, dict) and value:
            try:
                return float(next(iter(value.values())))
            except (TypeError, ValueError):
                return None
        return None

    peak, cap = one(peak_now), one(cap_raw)
    now = one(now_raw)

    # Предел соединений экспортёр отдаёт только со сборщиком global_variables.
    # Если его выключили, значение всё равно доступно — запросом к самой базе.
    if not cap and cluster_db_creds(cluster):
        res = await sql_execute(cluster, "SELECT @@max_connections AS lim")
        if not res.get("error") and res.get("rows"):
            try:
                cap = float(res["rows"][0][0])
            except (TypeError, ValueError, IndexError):
                cap = None

    if peak is None:
        peak = now          # окна ещё нет — только что подняли мониторинг

    if peak is None or not cap:
        missing = []
        if peak is None:
            missing.append("mysql_global_status_threads_connected")
        if not cap:
            missing.append("mysql_global_variables_max_connections")
        return {
            "level": "unknown",
            "note": ("нет метрик %s по цели %s. Проверьте, что mysqld_exporter "
                     "на этом сервере опрашивается Prometheus: "
                     "curl -s %s/api/v1/query?query=%s"
                     % (" и ".join(missing), inst, settings.prometheus.url,
                        "mysql_up")),
        }

    before = one(peak_before)
    # Неделя назад данных может не быть — тогда роста просто не знаем
    per_day = ((peak - before) / 7.0) if before is not None else 0.0
    days = _days_left(cap - peak, per_day)
    return {"peak": int(peak), "limit": int(cap),
            "now": int(now) if now is not None else None,
            "used_pct": round(peak / cap * 100, 1),
            "growth_per_day": round(per_day, 2),
            "measured": before is not None,
            "days_left": days, "level": _level(days)}


async def auto_increment_forecast(cluster: dict) -> list[dict]:
    """Сколько осталось до переполнения счётчиков.

    Смотрим долю израсходованного диапазона. Скорость расхода по одной точке
    не оценить, поэтому здесь важен сам факт: 60% у int означает, что запас
    конечен и его надо считать.
    """
    if not cluster_db_creds(cluster):
        return []
    result = await sql_execute(cluster, AUTO_INCREMENT_SQL)
    if result.get("error"):
        logger.info("Автоинкременты не прочитаны: %s", result["error"])
        return []

    cols = result.get("columns") or []
    out = []
    for row in result.get("rows") or []:
        item = dict(zip(cols, row))
        dtype = str(item.get("dtype") or "").lower()
        ctype = str(item.get("ctype") or "").lower()
        limits = INT_LIMITS.get(dtype)
        if not limits:
            continue
        top = limits[1] if "unsigned" in ctype else limits[0]
        try:
            current = int(item.get("cur") or 0)
        except (TypeError, ValueError):
            continue
        share = current / top * 100
        # Ниже половины запаса беспокоиться не о чем, и список не засоряем
        if share < 50:
            continue
        out.append({
            "table": "%s.%s" % (item.get("db"), item.get("tbl")),
            "column": item.get("col"), "type": ctype,
            "current": current, "limit": top,
            "used_pct": round(share, 1),
            "rows": item.get("rows_est"),
            "level": "critical" if share >= 80 else "warning",
        })
    out.sort(key=lambda r: -r["used_pct"])
    return out


async def collect(cluster: dict) -> dict:
    """Полный прогноз по кластеру."""
    disks, conns, autos = await asyncio.gather(
        disk_forecast(cluster),
        connections_forecast(cluster),
        auto_increment_forecast(cluster))
    worst = "ok"
    for level in ([d["level"] for d in disks] + [conns.get("level", "ok")]
                  + [a["level"] for a in autos]):
        if level == "critical":
            worst = "critical"
        elif level == "warning" and worst != "critical":
            worst = "warning"
    return {"cluster": cluster["name"], "label": cluster["label"],
            "disks": disks, "connections": conns,
            "auto_increment": autos, "level": worst}


def fmt_forecast(data: dict) -> str:
    """Текстом — для подсказки модели, сводки и вкладки интерфейса."""
    lines = ["## Запас по ресурсам — %s" % data["label"], ""]

    disks = [d for d in data["disks"] if d["days_left"] is not None]
    if disks:
        lines.append("  Место на дисках:")
        for d in disks[:6]:
            lines.append("    %s %s: свободно %.1f ГБ (%s%% занято), "
                         "растёт на %.2f ГБ в сутки — хватит на %.1f дн."
                         % (d["host"], d["mount"], d["free_gb"],
                            d["used_pct"], d["growth_gb_day"], d["days_left"]))
    else:
        lines.append("  Место на дисках: заметного роста нет, оценивать нечего.")

    conn = data["connections"]
    if conn.get("level") == "unknown":
        lines.append("  Соединения: %s" % conn.get("note", "нет данных"))
    else:
        if conn.get("days_left") is not None:
            tail = "хватит на %.1f дн." % conn["days_left"]
        elif not conn.get("measured"):
            tail = "истории за прошлую неделю нет, темп роста пока не известен"
        else:
            tail = "роста нет"
        now_part = ("сейчас %d, " % conn["now"]) if conn.get("now") is not None else ""
        lines.append("  Соединения: %sпик за неделю %d из %d (%.1f%%), %s"
                     % (now_part, conn["peak"], conn["limit"],
                        conn["used_pct"], tail))

    if data["auto_increment"]:
        lines.append("")
        lines.append("  Автоинкременты близко к пределу типа:")
        for a in data["auto_increment"][:10]:
            lines.append("    %s.%s (%s): израсходовано %.1f%% диапазона "
                         "(%d из %d)" % (a["table"], a["column"], a["type"],
                                         a["used_pct"], a["current"], a["limit"]))
        lines.append("    Переполнение счётчика останавливает запись в таблицу. "
                     "Менять тип надо заранее: на большой таблице это часы.")
    return "\n".join(lines)
