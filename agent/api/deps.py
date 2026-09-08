"""
Зависимости роутов: сессия базы и текущий пользователь.

Проверка прав здесь, а не в каждом обработчике: пропустить её в одном роуте
проще, чем кажется, а цена ошибки — открытый наружу метод.
"""
from __future__ import annotations

from typing import Annotated, AsyncIterator, Optional

from fastapi import Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession

from agent.core.config import settings
from agent.db.base import get_session
from agent.db.repositories.alerts import AlertRepository
from agent.db.repositories.chats import ChatRepository, FeedbackRepository
from agent.db.repositories.users import UserRepository
from agent.services import access

DbSession = Annotated[AsyncSession, Depends(get_session)]


async def alert_repo(session: DbSession) -> AlertRepository:
    return AlertRepository(session)


async def user_repo(session: DbSession) -> UserRepository:
    return UserRepository(session)


async def chat_repo(session: DbSession) -> ChatRepository:
    return ChatRepository(session)


async def feedback_repo(session: DbSession) -> FeedbackRepository:
    return FeedbackRepository(session)


Alerts   = Annotated[AlertRepository, Depends(alert_repo)]
Users    = Annotated[UserRepository, Depends(user_repo)]
Chats    = Annotated[ChatRepository, Depends(chat_repo)]
Feedbacks = Annotated[FeedbackRepository, Depends(feedback_repo)]


async def optional_user(request: Request) -> Optional[dict]:
    """Пользователь, если он есть. При выключенной аутентификации — заглушка."""
    if not settings.auth.enabled:
        return {"username": "anonymous", "source": "disabled"}
    return await access.current_user(request)


async def require_user(request: Request) -> dict:
    user = await optional_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Требуется вход")
    return user


async def require_admin(request: Request) -> dict:
    user = await require_user(request)
    if user.get("source") == "disabled":
        return user
    if not await access.is_admin(user):
        raise HTTPException(status_code=403,
                            detail="Требуются права администратора")
    return user


CurrentUser = Annotated[dict, Depends(require_user)]
AdminUser   = Annotated[dict, Depends(require_admin)]
MaybeUser   = Annotated[Optional[dict], Depends(optional_user)]


def require_ingest_token(request: Request) -> None:
    """Токен для внешних систем.

    Отдельный от сессии путь: Zabbix не умеет ходить с cookie, а пускать
    события вообще без проверки нельзя — писать в ленту сможет кто угодно.
    Пустой список токенов означает «проверка выключена», и это осознанный
    выбор администратора.
    """
    if not settings.ingest_tokens:
        return
    header = (request.headers.get("X-Ingest-Token")
              or request.headers.get("Authorization", "").removeprefix("Bearer ").strip())
    if header not in settings.ingest_tokens:
        raise HTTPException(status_code=401, detail="Неверный токен приёма событий")
