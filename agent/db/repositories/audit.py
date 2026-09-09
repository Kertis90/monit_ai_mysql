"""Журнал действий: запись и выборка."""
from __future__ import annotations

import logging
from typing import Optional, Sequence

from sqlalchemy import delete, func, select
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

    def _filtered(self, days: int, action: Optional[str],
                  username: Optional[str]):
        """Общие условия выборки: одни и те же для страницы и для счёта."""
        conditions = [AuditEntry.ts >= cutoff_iso(days)]
        if action:
            conditions.append(AuditEntry.action == action)
        if username:
            conditions.append(AuditEntry.username == username)
        return conditions

    async def recent(self, *, days: int = 30, limit: int = 200,
                     offset: int = 0,
                     action: Optional[str] = None,
                     username: Optional[str] = None) -> Sequence[AuditEntry]:
        stmt = (select(AuditEntry)
                .where(*self._filtered(days, action, username))
                .order_by(AuditEntry.ts.desc(), AuditEntry.id.desc())
                .limit(limit).offset(max(0, offset)))
        return (await self.session.execute(stmt)).scalars().all()

    async def count(self, *, days: int = 30, action: Optional[str] = None,
                    username: Optional[str] = None) -> int:
        """Сколько всего записей подходит под фильтр.

        Нужно для страниц: без общего числа непонятно, есть ли ещё что-то
        дальше, и «Показать ещё» приходится нажимать вслепую.
        """
        stmt = (select(func.count()).select_from(AuditEntry)
                .where(*self._filtered(days, action, username)))
        return int((await self.session.execute(stmt)).scalar() or 0)

    async def purge_old(self) -> int:
        stmt = delete(AuditEntry).where(AuditEntry.ts < cutoff_iso(RETENTION_DAYS))
        removed = int((await self.session.execute(stmt)).rowcount or 0)
        if removed:
            logger.info("Удалено записей журнала действий: %d", removed)
        return removed
