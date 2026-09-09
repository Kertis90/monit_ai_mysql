"""Заметки о кластере: что дежурный знает, а агент нет."""
from __future__ import annotations

import logging
from typing import Optional, Sequence

from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from agent.db.models import ClusterNote, to_iso

logger = logging.getLogger("agent.db.notes")


class NoteRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def list(self, cluster: str,
                   only_enabled: bool = False) -> Sequence[ClusterNote]:
        stmt = select(ClusterNote).where(ClusterNote.cluster == cluster)
        if only_enabled:
            stmt = stmt.where(ClusterNote.enabled == 1)
        return (await self.session.execute(
            stmt.order_by(ClusterNote.id))).scalars().all()

    async def add(self, cluster: str, text: str,
                  author: str = "") -> Optional[ClusterNote]:
        body = (text or "").strip()
        if not body:
            return None
        note = ClusterNote(cluster=cluster, text=body[:4000],
                           author=author, ts=to_iso(), enabled=1)
        self.session.add(note)
        await self.session.flush()
        logger.info("Заметка о кластере %s добавлена (%s)", cluster, author or "—")
        return note

    async def toggle(self, note_id: int, enabled: bool) -> bool:
        stmt = (update(ClusterNote).where(ClusterNote.id == note_id)
                .values(enabled=1 if enabled else 0))
        return bool((await self.session.execute(stmt)).rowcount)

    async def delete(self, note_id: int) -> bool:
        stmt = delete(ClusterNote).where(ClusterNote.id == note_id)
        return bool((await self.session.execute(stmt)).rowcount)
