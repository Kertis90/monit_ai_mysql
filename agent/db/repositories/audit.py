"""Журнал действий: запись и выборка."""
from __future__ import annotations

import logging
from typing import Optional, Sequence

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from agent.db.models import AuditEntry, cutoff_iso, to_iso

logger = logging.getLogger("agent.db.audit")

# Хранить дольше событий: доступы разбирают спустя месяцы, и запись о выдаче
# должна пережить историю алертов
RETENTION_DAYS = 365


class AuditRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def add(self, *, action: str, username: str = "", target: str = "",
                  detail: str = "", ip: str = "", ok: bool = True) -> None:
        self.session.add(AuditEntry(
            ts=to_iso(), username=username or "", action=action,
            target=target or "", detail=(detail or "")[:2000], ip=ip or "",
            ok=1 if ok else 0))
        await self.session.flush()

    async def recent(self, *, days: int = 30, limit: int = 200,
                     action: Optional[str] = None,
                     username: Optional[str] = None) -> Sequence[AuditEntry]:
        stmt = select(AuditEntry).where(AuditEntry.ts >= cutoff_iso(days))
        if action:
            stmt = stmt.where(AuditEntry.action == action)
        if username:
            stmt = stmt.where(AuditEntry.username == username)
        stmt = stmt.order_by(AuditEntry.ts.desc(), AuditEntry.id.desc()).limit(limit)
        return (await self.session.execute(stmt)).scalars().all()

    async def purge_old(self) -> int:
        stmt = delete(AuditEntry).where(AuditEntry.ts < cutoff_iso(RETENTION_DAYS))
        removed = int((await self.session.execute(stmt)).rowcount or 0)
        if removed:
            logger.info("Удалено записей журнала действий: %d", removed)
        return removed
