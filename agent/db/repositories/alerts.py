"""
Работа с историей алертов и памятью инцидентов.

Репозиторий, а не запросы прямо в роутах: те же выборки нужны и веб-интерфейсу,
и инструментам LLM, и вебхуку Alertmanager. Один раз описанные здесь, они
одинаково ведут себя во всех трёх местах.
"""
from __future__ import annotations

import datetime
import logging
from typing import Optional, Sequence

from sqlalchemy import delete, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from agent.core.config import settings
from agent.db.models import Alert, cutoff_iso, to_iso

logger = logging.getLogger("agent.db.alerts")


class AlertRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    # ── запись ───────────────────────────────────────────────────────────────

    async def add(self, *, alert: str, cluster: str = "", cluster_label: str = "",
                  instance: str = "", severity: str = "", summary: str = "",
                  analysis: str = "", source: str = "alertmanager",
                  ts: Optional[datetime.datetime] = None) -> Alert:
        row = Alert(ts=to_iso(ts), alert=alert, cluster=cluster,
                    cluster_label=cluster_label, instance=instance,
                    severity=severity, summary=summary, analysis=analysis,
                    source=source)
        self.session.add(row)
        await self.session.flush()
        return row

    async def is_duplicate(self, *, alert: str, cluster: str, instance: str,
                           minutes: Optional[int] = None) -> bool:
        """Было ли такое же событие только что.

        Alertmanager повторяет уведомления, пока проблема не ушла. Без этой
        проверки каждый повтор уходил бы в LLM на разбор — деньги и шум
        в ленте на пустом месте.
        """
        window = minutes if minutes is not None else settings.alert_dedup_minutes
        if window <= 0:
            return False
        since = to_iso(datetime.datetime.now(datetime.timezone.utc)
                       - datetime.timedelta(minutes=window))
        stmt = (select(func.count())
                .select_from(Alert)
                .where(Alert.alert == alert,
                       Alert.cluster == cluster,
                       Alert.instance == instance,
                       Alert.ts >= since))
        return bool((await self.session.execute(stmt)).scalar() or 0)

    # ── чтение ───────────────────────────────────────────────────────────────

    async def recent(self, *, cluster: Optional[str] = None,
                     hours: float = 24, limit: int = 20,
                     name: Optional[str] = None) -> Sequence[Alert]:
        since = to_iso(datetime.datetime.now(datetime.timezone.utc)
                       - datetime.timedelta(hours=hours))
        stmt = select(Alert).where(Alert.ts >= since)
        if cluster:
            stmt = stmt.where(Alert.cluster == cluster)
        if name:
            stmt = stmt.where(Alert.alert == name)
        stmt = stmt.order_by(Alert.ts.desc()).limit(limit)
        return (await self.session.execute(stmt)).scalars().all()

    async def get(self, alert_id: int) -> Optional[Alert]:
        return await self.session.get(Alert, alert_id)

    async def similar(self, alert_name: str, cluster: Optional[str] = None,
                      limit: int = 3) -> Sequence[Alert]:
        """Прошлые случаи того же алерта, у которых записано решение.

        Смысл памяти инцидентов: не разбирать заново то, что уже разбирали,
        а показать, чем это кончилось в прошлый раз.
        """
        stmt = (select(Alert)
                .where(Alert.alert == alert_name,
                       Alert.resolution.is_not(None),
                       Alert.resolution != "")
                .order_by(Alert.ts.desc())
                .limit(limit))
        if cluster:
            stmt = stmt.where(Alert.cluster == cluster)
        return (await self.session.execute(stmt)).scalars().all()

    async def count(self, *, hours: float = 24,
                    cluster: Optional[str] = None) -> int:
        since = to_iso(datetime.datetime.now(datetime.timezone.utc)
                       - datetime.timedelta(hours=hours))
        stmt = select(func.count()).select_from(Alert).where(Alert.ts >= since)
        if cluster:
            stmt = stmt.where(Alert.cluster == cluster)
        return int((await self.session.execute(stmt)).scalar() or 0)

    # ── изменение ────────────────────────────────────────────────────────────

    async def resolve(self, alert_id: int, resolution: str,
                      resolved_by: str) -> bool:
        stmt = (update(Alert)
                .where(Alert.id == alert_id)
                .values(resolution=resolution, resolved_by=resolved_by,
                        resolved_at=to_iso()))
        return bool((await self.session.execute(stmt)).rowcount)

    async def delete(self, alert_id: int) -> bool:
        stmt = delete(Alert).where(Alert.id == alert_id)
        return bool((await self.session.execute(stmt)).rowcount)

    async def delete_by_name(self, alert_name: str,
                             cluster: Optional[str] = None) -> int:
        """Удалить ложные срабатывания пачкой — по одному это мучение."""
        stmt = delete(Alert).where(Alert.alert == alert_name)
        if cluster:
            stmt = stmt.where(Alert.cluster == cluster)
        return int((await self.session.execute(stmt)).rowcount or 0)

    async def purge_old(self) -> int:
        """Убрать всё старше срока хранения."""
        stmt = delete(Alert).where(
            Alert.ts < cutoff_iso(settings.db.alerts_retention_days))
        removed = int((await self.session.execute(stmt)).rowcount or 0)
        if removed:
            logger.info("Удалено старых алертов: %d (хранение %d дн.)",
                        removed, settings.db.alerts_retention_days)
        return removed
