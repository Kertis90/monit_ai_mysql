"""
Что менялось в настройках и когда.

Самый частый вопрос при внезапной деградации — «что вчера поменяли». До сих
пор настройки сравнивались между узлами и разбирались на разумность, но во
времени не отслеживались, и ответ приходилось искать в чужой памяти.

Снимок раз в сутки, диф между снимками. Изменение попадает в ленту событий
рядом с алертами — там, где его и ищут, разбирая аварию.
"""
from __future__ import annotations

import datetime
import logging
from typing import Optional

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from agent.db.base import session_scope
from agent.db.models import ConfigSnapshot, cutoff_iso, from_iso, to_iso
from agent.services.mysql import cluster_db_creds, sql_execute
from agent.services.registry import cluster_hosts, enabled_clusters

logger = logging.getLogger("agent.config_history")

RETENTION_DAYS = 180

# Переменные, изменение которых что-то значит. Всё подряд писать незачем:
# в 8.0 их больше шестисот, и половина меняется сама (счётчики, идентификаторы
# сессии), а диф превратился бы в шум.
TRACKED = (
    "innodb_buffer_pool_size", "innodb_log_file_size", "innodb_redo_log_capacity",
    "innodb_flush_log_at_trx_commit", "innodb_flush_method", "innodb_io_capacity",
    "innodb_io_capacity_max", "innodb_file_per_table", "innodb_lock_wait_timeout",
    "sync_binlog", "log_bin", "binlog_format", "binlog_expire_logs_seconds",
    "expire_logs_days", "max_connections", "max_user_connections",
    "thread_cache_size", "table_open_cache", "table_definition_cache",
    "open_files_limit", "tmp_table_size", "max_heap_table_size",
    "max_allowed_packet", "wait_timeout", "interactive_timeout",
    "slow_query_log", "long_query_time", "log_queries_not_using_indexes",
    "performance_schema", "read_only", "super_read_only", "gtid_mode",
    "enforce_gtid_consistency", "sql_mode", "character_set_server",
    "collation_server", "default_storage_engine", "version",
    "slave_parallel_workers", "replica_parallel_workers",
    "innodb_thread_concurrency", "query_cache_type", "query_cache_size",
)

VARIABLES_SQL = ("SHOW GLOBAL VARIABLES WHERE Variable_name IN (%s)"
                 % ", ".join("'%s'" % v for v in TRACKED))


async def snapshot(cluster: dict) -> int:
    """Снять значения отслеживаемых переменных со всех серверов кластера."""
    if not cluster_db_creds(cluster):
        return 0
    stamp = to_iso()
    rows = []
    for ip, _role in cluster_hosts(cluster):
        result = await sql_execute(cluster, VARIABLES_SQL, ip)
        if result.get("error"):
            logger.info("Настройки %s не сняты: %s", ip, result["error"])
            continue
        for raw in result.get("rows") or []:
            if len(raw) < 2:
                continue
            rows.append(ConfigSnapshot(ts=stamp, cluster=cluster["name"],
                                       host=ip, name=str(raw[0])[:190],
                                       value=str(raw[1] if raw[1] is not None else "")))
    if rows:
        async with session_scope() as session:
            session.add_all(rows)
    return len(rows)


async def snapshot_all() -> int:
    total = 0
    for cluster in enabled_clusters():
        try:
            total += await snapshot(cluster)
        except Exception as exc:
            logger.error("Снимок настроек %s не удался: %s", cluster["name"], exc)
    return total


async def changes(cluster_name: str, days: int = 30) -> list[dict]:
    """Изменения за период: что, где, когда, с чего на что.

    Сравниваем соседние снимки, а не первый с последним: иначе значение,
    изменённое и возвращённое обратно, потерялось бы — а это как раз самый
    интересный случай.
    """
    since = cutoff_iso(days)
    async with session_scope() as session:
        stmt = (select(ConfigSnapshot)
                .where(ConfigSnapshot.cluster == cluster_name,
                       ConfigSnapshot.ts >= since)
                .order_by(ConfigSnapshot.ts))
        rows = (await session.execute(stmt)).scalars().all()

    # (хост, переменная) -> последнее известное значение
    seen: dict[tuple, tuple] = {}
    out = []
    for row in rows:
        key = (row.host, row.name)
        previous = seen.get(key)
        if previous is not None and previous[0] != row.value:
            out.append({"ts": row.ts, "host": row.host, "name": row.name,
                        "was": previous[0], "now": row.value,
                        "since": previous[1]})
        seen[key] = (row.value, row.ts)
    out.sort(key=lambda c: c["ts"], reverse=True)
    return out


async def purge_old() -> int:
    async with session_scope() as session:
        stmt = delete(ConfigSnapshot).where(
            ConfigSnapshot.ts < cutoff_iso(RETENTION_DAYS))
        removed = int((await session.execute(stmt)).rowcount or 0)
    if removed:
        logger.info("Удалено старых снимков настроек: %d", removed)
    return removed


async def scheduler() -> None:
    """Снимок раз в сутки, рядом со снимком размеров таблиц."""
    import asyncio
    while True:
        try:
            await snapshot_all()
            await asyncio.sleep(24 * 3600)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.error("Снимок настроек не снят: %s", exc)
            await asyncio.sleep(3600)


def fmt_changes(items: list, label: str, days: int) -> str:
    if not items:
        return ("## Изменения настроек — %s\n\n"
                "  За %d дн. отслеживаемые параметры не менялись.\n"
                "  Снимок снимается раз в сутки; если агент запущен недавно, "
                "сравнивать пока не с чем." % (label, days))

    lines = ["## Изменения настроек — %s (за %d дн.)" % (label, days), ""]
    for item in items[:40]:
        when = str(item["ts"])[:16].replace("T", " ")
        lines.append("  [%s] %s на %s: было %s, стало %s"
                     % (when, item["name"], item["host"],
                        item["was"] or "пусто", item["now"] or "пусто"))
    lines.append("")
    lines.append("  Если деградация началась после одной из этих дат — "
                 "начинайте разбор с неё.")
    return "\n".join(lines)


def as_events(items: list) -> list[dict]:
    """Изменения в виде событий для общей ленты."""
    out = []
    for item in items:
        out.append({
            "ts": str(item["ts"])[:19].replace("T", " "),
            "text": "НАСТРОЙКА %s на %s: %s -> %s"
                    % (item["name"], item["host"],
                       item["was"] or "пусто", item["now"] or "пусто"),
        })
    return out
