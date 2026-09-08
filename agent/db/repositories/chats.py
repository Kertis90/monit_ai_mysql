"""
История переписки и оценки ответов.

Разделение по client_id: к агенту подключаются разные люди, и чужие вопросы
в своей ленте видеть никто не должен.
"""
from __future__ import annotations

import logging
from typing import Optional, Sequence

from sqlalchemy import delete, desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from agent.core.config import settings
from agent.db.models import ChatMessage, Feedback, cutoff_iso, to_iso

logger = logging.getLogger("agent.db.chats")


class ChatRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def add(self, *, client_id: str, role: str, content: str,
                  session_id: str = "", fingerprint: str = "") -> ChatMessage:
        row = ChatMessage(client_id=client_id, session_id=session_id,
                          ts=to_iso(), role=role, content=content,
                          fingerprint=fingerprint)
        self.session.add(row)
        await self.session.flush()
        return row

    async def history(self, client_id: str,
                      limit: Optional[int] = None) -> list[ChatMessage]:
        """Последние сообщения в хронологическом порядке.

        Выбираем свежие, а потом разворачиваем: LIMIT нужен от конца, а
        показывать надо от начала.
        """
        take = limit or settings.chat_context_messages
        stmt = (select(ChatMessage)
                .where(ChatMessage.client_id == client_id)
                .order_by(desc(ChatMessage.ts), desc(ChatMessage.id))
                .limit(take))
        rows = (await self.session.execute(stmt)).scalars().all()
        return list(reversed(rows))

    async def forget(self, client_id: str) -> int:
        stmt = delete(ChatMessage).where(ChatMessage.client_id == client_id)
        return int((await self.session.execute(stmt)).rowcount or 0)

    async def purge_old(self) -> int:
        stmt = delete(ChatMessage).where(
            ChatMessage.ts < cutoff_iso(settings.db.chats_retention_days))
        removed = int((await self.session.execute(stmt)).rowcount or 0)
        if removed:
            logger.info("Удалено старых сообщений чата: %d (хранение %d дн.)",
                        removed, settings.db.chats_retention_days)
        return removed


class FeedbackRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def add(self, *, rating: int, question: str = "", answer: str = "",
                  comment: str = "", client_id: str = "",
                  username: str = "") -> Feedback:
        row = Feedback(ts=to_iso(), client_id=client_id, username=username,
                       rating=rating, question=question, answer=answer,
                       comment=comment)
        self.session.add(row)
        await self.session.flush()
        return row

    async def recent(self, limit: int = 50) -> Sequence[Feedback]:
        stmt = (select(Feedback)
                .order_by(desc(Feedback.ts), desc(Feedback.id))
                .limit(limit))
        return (await self.session.execute(stmt)).scalars().all()

    async def stats(self, days: int = 30) -> dict:
        """Доля полезных ответов и последние отрицательные оценки.

        Отрицательные показываем целиком: сводное число говорит, что что-то
        не так, а понять что — можно только по самим вопросам.
        """
        since = cutoff_iso(days)
        rows = (await self.session.execute(
            select(Feedback).where(Feedback.ts >= since))).scalars().all()
        good = sum(1 for r in rows if r.rating > 0)
        bad  = [r for r in rows if r.rating < 0]
        bad.sort(key=lambda r: r.ts, reverse=True)
        return {
            "days": days,
            "total": len(rows),
            "positive": good,
            "negative": len(bad),
            "useful_share": round(good / len(rows), 3) if rows else None,
            "recent_negative": [
                {"ts": r.ts, "question": r.question, "comment": r.comment}
                for r in bad[:10]],
        }
