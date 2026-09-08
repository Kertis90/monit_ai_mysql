"""
Что растёт и куда.

Размер таблицы в моменте почти ничего не говорит. Важно другое: какая растёт
быстрее всех, у какой освободилось место после чистки, но не вернулось диску,
и где вообще нет первичного ключа — на такой таблице построчная репликация
превращает обновление сотни строк в полный проход.

Метрик для этого нет, поэтому снимаем срез запросом раз в сутки и считаем
разницу между снимками.
"""
from __future__ import annotations

import datetime
import logging
from typing import Optional, Sequence

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from agent.db.base import session_scope
from agent.db.models import TableSize, cutoff_iso, from_iso, to_iso
from agent.services.mysql import cluster_db_creds, sql_execute
from agent.services.registry import enabled_clusters

logger = logging.getLogger("agent.growth")

# Дольше держать смысла нет: за три месяца тренд виден, а строк на каждый
# снимок столько же, сколько таблиц в базе
RETENTION_DAYS = 90

SIZES_SQL = """
SELECT t.TABLE_SCHEMA AS db, t.TABLE_NAME AS tbl,
       COALESCE(t.DATA_LENGTH, 0)  AS data_bytes,
       COALESCE(t.INDEX_LENGTH, 0) AS index_bytes,
       COALESCE(t.DATA_FREE, 0)    AS free_bytes,
       COALESCE(t.TABLE_ROWS, 0)   AS rows_est,
       (SELECT COUNT(*) FROM information_schema.STATISTICS s
         WHERE s.TABLE_SCHEMA = t.TABLE_SCHEMA
           AND s.TABLE_NAME   = t.TABLE_NAME
           AND s.INDEX_NAME   = 'PRIMARY') AS pk_cols
  FROM information_schema.TABLES t
 WHERE t.TABLE_TYPE = 'BASE TABLE'
   AND t.TABLE_SCHEMA NOT IN ('mysql', 'sys', 'performance_schema',
                              'information_schema')
 ORDER BY (COALESCE(t.DATA_LENGTH, 0) + COALESCE(t.INDEX_LENGTH, 0)) DESC
 LIMIT 300"""


def _int(value) -> int:
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return 0


async def snapshot(cluster: dict) -> int:
    """Снять и сохранить срез размеров. Возвращает число таблиц."""
    if not cluster_db_creds(cluster):
        return 0
    result = await sql_execute(cluster, SIZES_SQL)
    if result.get("error"):
        logger.info("Размеры таблиц %s не сняты: %s",
                    cluster["name"], result["error"])
        return 0

    cols = result.get("columns") or []
    stamp = to_iso()
    rows = []
    for raw in result.get("rows") or []:
        item = dict(zip(cols, raw))
        rows.append(TableSize(
            ts=stamp, cluster=cluster["name"],
            db=str(item.get("db") or "")[:190],
            tbl=str(item.get("tbl") or "")[:190],
            data_bytes=_int(item.get("data_bytes")),
            index_bytes=_int(item.get("index_bytes")),
            free_bytes=_int(item.get("free_bytes")),
            rows_est=_int(item.get("rows_est")),
            has_pk=1 if _int(item.get("pk_cols")) else 0))

    if rows:
        async with session_scope() as session:
            session.add_all(rows)
    logger.info("Размеры таблиц %s: снято %d", cluster["name"], len(rows))
    return len(rows)


async def snapshot_all() -> int:
    total = 0
    for cluster in enabled_clusters():
        try:
            total += await snapshot(cluster)
        except Exception as exc:
            logger.error("Срез размеров %s не удался: %s", cluster["name"], exc)
    return total


async def _rows(session: AsyncSession, cluster: str,
                stamp: str) -> Sequence[TableSize]:
    stmt = select(TableSize).where(TableSize.cluster == cluster,
                                   TableSize.ts == stamp)
    return (await session.execute(stmt)).scalars().all()


async def report(cluster_name: str, days: int = 30) -> dict:
    """Что выросло за период и на чём стоит остановиться."""
    async with session_scope() as session:
        stamps = (await session.execute(
            select(TableSize.ts).where(TableSize.cluster == cluster_name)
            .distinct().order_by(TableSize.ts.desc()).limit(200))).scalars().all()
        if not stamps:
            return {"cluster": cluster_name, "snapshots": 0,
                    "note": "Снимков ещё нет. Первый снимается автоматически "
                            "раз в сутки; после второго появится динамика."}

        latest = stamps[0]
        # Ищем снимок примерно нужной давности, а не строго: срез могли
        # пропустить из-за перезапуска или недоступной базы
        target = from_iso(to_iso(datetime.datetime.now(datetime.timezone.utc)
                                 - datetime.timedelta(days=days)))
        earlier = min(
            (s for s in stamps if s != latest),
            key=lambda s: abs(((from_iso(s) or from_iso(latest)) - target).total_seconds()),
            default=None)

        now_rows = await _rows(session, cluster_name, latest)
        old_rows = await _rows(session, cluster_name, earlier) if earlier else []

    was = {(r.db, r.tbl): r for r in old_rows}
    span_days = 0.0
    if earlier:
        a, b = from_iso(earlier), from_iso(latest)
        if a and b:
            span_days = max((b - a).total_seconds() / 86400, 0.0)

    items = []
    for row in now_rows:
        total = row.data_bytes + row.index_bytes
        old = was.get((row.db, row.tbl))
        grew = total - (old.data_bytes + old.index_bytes) if old else None
        items.append({
            "table": "%s.%s" % (row.db, row.tbl),
            "size_mb": round(total / 1048576, 1),
            "data_mb": round(row.data_bytes / 1048576, 1),
            "index_mb": round(row.index_bytes / 1048576, 1),
            "free_mb": round(row.free_bytes / 1048576, 1),
            "rows": row.rows_est,
            "has_pk": bool(row.has_pk),
            "grew_mb": round(grew / 1048576, 1) if grew is not None else None,
            "grew_mb_day": (round(grew / 1048576 / span_days, 2)
                            if grew is not None and span_days >= 0.5 else None),
        })

    by_growth = sorted((i for i in items if i["grew_mb"] is not None),
                       key=lambda i: -i["grew_mb"])
    return {
        "cluster": cluster_name,
        "snapshots": len(stamps),
        "from": earlier, "to": latest, "span_days": round(span_days, 1),
        "biggest": sorted(items, key=lambda i: -i["size_mb"])[:15],
        "growing": by_growth[:15],
        # Освобождённое место, которое не вернулось файловой системе
        "fragmented": sorted((i for i in items if i["free_mb"] >= 100),
                             key=lambda i: -i["free_mb"])[:10],
        "no_pk": [i for i in items if not i["has_pk"]][:20],
    }


async def purge_old() -> int:
    async with session_scope() as session:
        stmt = delete(TableSize).where(TableSize.ts < cutoff_iso(RETENTION_DAYS))
        removed = int((await session.execute(stmt)).rowcount or 0)
    if removed:
        logger.info("Удалено старых снимков размеров: %d", removed)
    return removed


def fmt_growth(data: dict) -> str:
    if data.get("note"):
        return "## Рост данных — %s\n\n  %s" % (data["cluster"], data["note"])

    lines = ["## Рост данных — %s" % data["cluster"], ""]
    if data["span_days"]:
        lines.append("  Сравнение за %.1f сут. (снимков накоплено: %d)"
                     % (data["span_days"], data["snapshots"]))
    else:
        lines.append("  Снимок один — динамики пока нет, только текущие размеры.")
    lines.append("")

    if data["growing"]:
        lines.append("  Растут быстрее всех:")
        for i in data["growing"][:8]:
            speed = ("%.2f МБ/сут." % i["grew_mb_day"]
                     if i["grew_mb_day"] is not None else "за период")
            lines.append("    %-45s +%.1f МБ (%s), сейчас %.1f МБ"
                         % (i["table"], i["grew_mb"], speed, i["size_mb"]))
        lines.append("")

    lines.append("  Самые большие:")
    for i in data["biggest"][:8]:
        lines.append("    %-45s %.1f МБ (данные %.1f, индексы %.1f), строк ~%d"
                     % (i["table"], i["size_mb"], i["data_mb"], i["index_mb"],
                        i["rows"]))

    if data["fragmented"]:
        lines.append("")
        lines.append("  Освободившееся место не вернулось файловой системе:")
        for i in data["fragmented"][:5]:
            lines.append("    %-45s %.1f МБ свободно внутри файла"
                         % (i["table"], i["free_mb"]))
        lines.append("    Возвращает OPTIMIZE TABLE, но он перестраивает "
                     "таблицу целиком — на большой это долго и под нагрузкой.")

    if data["no_pk"]:
        lines.append("")
        lines.append("  Без первичного ключа: %s"
                     % ", ".join(i["table"] for i in data["no_pk"][:10]))
        lines.append("    При построчной репликации обновление в такой таблице "
                     "заставляет реплику искать строки полным проходом — "
                     "отставание растёт на ровном месте.")
    return "\n".join(lines)


async def scheduler() -> None:
    """Срез раз в сутки. Чаще незачем: на большой базе запрос к
    information_schema сам по себе не бесплатный, а данные меняются медленно."""
    import asyncio
    while True:
        try:
            await snapshot_all()
            await asyncio.sleep(24 * 3600)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.error("Срез размеров не снят: %s", exc)
            await asyncio.sleep(3600)
