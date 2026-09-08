"""
Подключение к хранилищу агента.

По умолчанию SQLite рядом с агентом: ставить нечего, переживает рестарт.
Переключение на MySQL — одной переменной DB_URL, схема та же.

Драйверы только асинхронные (aiosqlite, asyncmy): приложение целиком на
asyncio, и синхронный драйвер блокировал бы цикл событий на каждом запросе —
ровно то, от чего уходили.
"""
from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from sqlalchemy import event, text
from sqlalchemy.ext.asyncio import (AsyncEngine, AsyncSession,
                                    async_sessionmaker, create_async_engine)
from sqlalchemy.orm import DeclarativeBase

from agent.core.config import settings

logger = logging.getLogger("agent.db")


class Base(DeclarativeBase):
    """Общий предок моделей."""


def _engine_kwargs() -> dict:
    """Параметры пула: у SQLite и MySQL они разные по смыслу."""
    if settings.db.is_sqlite:
        # У файловой SQLite пул размером с MySQL смысла не имеет, а вот
        # ожидание блокировки нужно: писатель в ней один.
        return {"connect_args": {"timeout": 15}}
    return {
        "pool_size":     settings.db.pool_size,
        "max_overflow":  settings.db.pool_size,
        # MySQL закрывает простаивающие соединения (wait_timeout), и без
        # переработки пул отдаёт мёртвое — "server has gone away"
        "pool_recycle":  settings.db.pool_recycle,
        "pool_pre_ping": True,
    }


engine: AsyncEngine = create_async_engine(
    settings.db.url, echo=settings.db.echo, future=True, **_engine_kwargs())

session_factory = async_sessionmaker(
    engine, class_=AsyncSession, expire_on_commit=False)


@event.listens_for(engine.sync_engine, "connect")
def _sqlite_pragmas(dbapi_conn, _record):
    """WAL и внешние ключи для SQLite.

    WAL нужен, потому что читателей много (чат, статус, алерты), а писатель
    один: без него чтение блокирует запись и наоборот.
    """
    if not settings.db.is_sqlite:
        return
    cur = dbapi_conn.cursor()
    try:
        cur.execute("PRAGMA journal_mode=WAL")
        cur.execute("PRAGMA synchronous=NORMAL")
        cur.execute("PRAGMA foreign_keys=ON")
    finally:
        cur.close()


@asynccontextmanager
async def session_scope() -> AsyncIterator[AsyncSession]:
    """Сессия с транзакцией: коммит при успехе, откат при исключении."""
    async with session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def get_session() -> AsyncIterator[AsyncSession]:
    """Зависимость FastAPI. Отдельно от session_scope: у роутов свой стиль."""
    async with session_scope() as session:
        yield session


async def init_models() -> None:
    """Создать недостающие таблицы и рассказать, с чем работаем.

    Схема совпадает с той, что создавал прежний агент, поэтому существующие
    базы подхватываются как есть — переносить данные не нужно.
    """
    from agent.db import models  # noqa: F401  — регистрация таблиц в metadata

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with engine.connect() as conn:
        if settings.db.is_sqlite:
            row = await conn.execute(text("SELECT sqlite_version()"))
            logger.info("Хранилище: SQLite %s, %s",
                        row.scalar(), settings.db.url.split("///")[-1])
        else:
            row = await conn.execute(text("SELECT VERSION()"))
            logger.info("Хранилище: MySQL %s", row.scalar())


async def dispose() -> None:
    """Закрыть пул при остановке — иначе MySQL держит соединения до таймаута."""
    await engine.dispose()
