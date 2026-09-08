"""
Разговоры, сообщения и оценки ответов.

Разговоров у человека может быть несколько: разбор аварии и вопрос про
настройку — разные истории, и мешать их в одну ленту значит портить контекст
обоим. Сообщение привязано к разговору колонкой session_id, которая в таблице
уже была: заводить новую нельзя, create_all добавляет только отсутствующие
таблицы, но не колонки в существующие.

Владелец — имя вошедшего пользователя либо идентификатор браузера, когда вход
выключен. Чужие разговоры не отдаются: идентификатор угадать несложно.
"""
from __future__ import annotations

import logging
import secrets
from typing import Optional, Sequence

from sqlalchemy import delete, desc, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from agent.core.config import settings
from agent.db.models import (ChatMessage, ChatThread, Feedback, cutoff_iso,
                             to_iso)

logger = logging.getLogger("agent.db.chats")


class ChatRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    # ── разговоры ────────────────────────────────────────────────────────────

    async def threads(self, owner: str) -> list[dict]:
        """Разговоры владельца, свежие первыми, с числом сообщений."""
        await self._adopt_orphans(owner)
        stmt = (select(ChatThread.id, ChatThread.title, ChatThread.created_at,
                       ChatThread.updated_at, func.count(ChatMessage.id))
                .select_from(ChatThread)
                .outerjoin(ChatMessage, ChatMessage.session_id == ChatThread.id)
                .where(ChatThread.owner == owner)
                .group_by(ChatThread.id, ChatThread.title,
                          ChatThread.created_at, ChatThread.updated_at)
                .order_by(desc(ChatThread.updated_at)))
        return [{"id": r[0], "title": r[1], "created_at": r[2],
                 "updated_at": r[3], "messages": int(r[4] or 0)}
                for r in (await self.session.execute(stmt)).all()]

    async def create_thread(self, owner: str, title: str = "") -> ChatThread:
        now = to_iso()
        thread = ChatThread(id="t-" + secrets.token_hex(8), owner=owner,
                            title=(title or "").strip()[:200],
                            created_at=now, updated_at=now)
        self.session.add(thread)
        await self.session.flush()
        return thread

    async def get_thread(self, owner: str,
                         thread_id: str) -> Optional[ChatThread]:
        thread = await self.session.get(ChatThread, thread_id)
        return thread if thread and thread.owner == owner else None

    async def current_thread(self, owner: str) -> ChatThread:
        """Последний разговор владельца либо новый, если их нет."""
        await self._adopt_orphans(owner)
        stmt = (select(ChatThread).where(ChatThread.owner == owner)
                .order_by(desc(ChatThread.updated_at)).limit(1))
        found = (await self.session.execute(stmt)).scalars().first()
        return found or await self.create_thread(owner)

    async def rename_thread(self, owner: str, thread_id: str,
                            title: str) -> bool:
        stmt = (update(ChatThread)
                .where(ChatThread.id == thread_id, ChatThread.owner == owner)
                .values(title=(title or "").strip()[:200], updated_at=to_iso()))
        return bool((await self.session.execute(stmt)).rowcount)

    async def delete_thread(self, owner: str, thread_id: str) -> int:
        """Удалить разговор вместе с сообщениями. -1 — не найден."""
        if await self.get_thread(owner, thread_id) is None:
            return -1
        removed = int((await self.session.execute(
            delete(ChatMessage).where(ChatMessage.session_id == thread_id)
        )).rowcount or 0)
        await self.session.execute(
            delete(ChatThread).where(ChatThread.id == thread_id))
        return removed

    async def touch_thread(self, thread_id: str, first_message: str = "") -> None:
        """Отметить разговор свежим и, если названия нет, взять его из вопроса."""
        thread = await self.session.get(ChatThread, thread_id)
        if thread is None:
            return
        thread.updated_at = to_iso()
        if not thread.title and first_message:
            # Название из первого вопроса: список из «Новый чат ×5» бесполезен
            thread.title = " ".join(first_message.split())[:60]
        await self.session.flush()

    async def _adopt_orphans(self, owner: str) -> None:
        """Сообщения, оставшиеся от версии без разговоров.

        Раньше история была одна сплошная, а session_id хранил идентификатор
        соединения. Собираем такие сообщения в один разговор — иначе после
        обновления переписка выглядела бы потерянной.
        """
        known = select(ChatThread.id).where(ChatThread.owner == owner)
        stmt = (select(func.count()).select_from(ChatMessage)
                .where(ChatMessage.client_id == owner,
                       ChatMessage.session_id.not_in(known)))
        if not int((await self.session.execute(stmt)).scalar() or 0):
            return
        thread = await self.create_thread(owner, "Прежняя переписка")
        await self.session.execute(
            update(ChatMessage)
            .where(ChatMessage.client_id == owner,
                   ChatMessage.session_id.not_in(
                       select(ChatThread.id).where(ChatThread.owner == owner)))
            .values(session_id=thread.id))
        logger.info("Прежняя переписка %s собрана в разговор %s",
                    owner, thread.id)

    # ── сообщения ────────────────────────────────────────────────────────────

    async def add(self, *, client_id: str, role: str, content: str,
                  session_id: str = "", fingerprint: str = "") -> ChatMessage:
        row = ChatMessage(client_id=client_id, session_id=session_id,
                          ts=to_iso(), role=role, content=content,
                          fingerprint=fingerprint)
        self.session.add(row)
        await self.session.flush()
        return row

    async def history(self, client_id: str, limit: Optional[int] = None,
                      thread_id: Optional[str] = None) -> list[ChatMessage]:
        """Последние сообщения в хронологическом порядке.

        Выбираем свежие, а потом разворачиваем: LIMIT нужен от конца, а
        показывать надо от начала.
        """
        take = limit or settings.chat_context_messages
        stmt = select(ChatMessage).where(ChatMessage.client_id == client_id)
        if thread_id:
            stmt = stmt.where(ChatMessage.session_id == thread_id)
        stmt = (stmt.order_by(desc(ChatMessage.ts), desc(ChatMessage.id))
                    .limit(take))
        rows = (await self.session.execute(stmt)).scalars().all()
        return list(reversed(rows))

    async def forget(self, client_id: str,
                     thread_id: Optional[str] = None) -> int:
        stmt = delete(ChatMessage).where(ChatMessage.client_id == client_id)
        if thread_id:
            stmt = stmt.where(ChatMessage.session_id == thread_id)
        return int((await self.session.execute(stmt)).rowcount or 0)

    async def search(self, owner: str, text: str,
                     limit: int = 50) -> list[dict]:
        """Поиск по своей переписке с указанием, в каком чате нашлось."""
        needle = "%" + (text or "").strip().lower() + "%"
        stmt = (select(ChatMessage.ts, ChatMessage.role, ChatMessage.content,
                       ChatThread.id, ChatThread.title)
                .join(ChatThread, ChatThread.id == ChatMessage.session_id)
                .where(ChatThread.owner == owner,
                       func.lower(ChatMessage.content).like(needle))
                .order_by(desc(ChatMessage.ts))
                .limit(limit))
        return [{"ts": r[0], "role": r[1], "content": r[2],
                 "thread_id": r[3], "thread_title": r[4]}
                for r in (await self.session.execute(stmt)).all()]

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
        bad = [r for r in rows if r.rating < 0]
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
