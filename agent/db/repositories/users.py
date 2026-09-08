"""
Список доступов: кому разрешён вход.

Проверка пароля в домене — ещё не право входа. Учётка должна быть выдана явно
администратором либо попасть сюда автоматически при первом входе по членству
в разрешённой группе или netgroup.
"""
from __future__ import annotations

import logging
from typing import Optional, Sequence

from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from agent.db.models import User, to_iso

logger = logging.getLogger("agent.db.users")


def normalize(username: str) -> str:
    """Единая форма имени: доступ выдают в одном регистре, входят в другом.

    Домен и приставку DOMAIN\\ отбрасываем — в списке лежит голое имя входа.
    """
    name = (username or "").strip()
    if "\\" in name:
        name = name.rsplit("\\", 1)[-1]
    if "@" in name:
        name = name.split("@", 1)[0]
    return name.lower()


class UserRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def get(self, username: str) -> Optional[User]:
        name = normalize(username)
        if not name:
            return None
        return await self.session.get(User, name)

    async def list(self) -> Sequence[User]:
        stmt = select(User).order_by(User.enabled.desc(), User.username)
        return (await self.session.execute(stmt)).scalars().all()

    async def allowed(self, username: str) -> bool:
        user = await self.get(username)
        return bool(user and user.enabled)

    async def is_admin(self, username: str) -> bool:
        user = await self.get(username)
        return bool(user and user.is_admin)

    async def grant(self, username: str, *, display_name: str = "",
                    email: str = "", role: str = "user",
                    granted_by: str = "") -> Optional[User]:
        """Выдать или обновить доступ.

        Двумя запросами, а не UPSERT: "INSERT ... ON CONFLICT DO UPDATE"
        появился в SQLite 3.24, а в RHEL и CentOS 7 идёт 3.7 — там это
        синтаксическая ошибка. Через ORM это ещё и переносимо на MySQL.
        """
        name = normalize(username)
        if not name:
            return None
        if role not in ("user", "admin"):
            role = "user"

        values = dict(display_name=display_name, email=email, role=role,
                      enabled=1, granted_by=granted_by, granted_at=to_iso())
        changed = (await self.session.execute(
            update(User).where(User.username == name).values(**values))).rowcount
        if not changed:
            self.session.add(User(username=name, **values))
        await self.session.flush()
        logger.info("Доступ выдан: %s (роль %s, выдал %s)",
                    name, role, granted_by or "—")
        return await self.session.get(User, name)

    async def revoke(self, username: str, by: str = "") -> bool:
        """Отозвать доступ, не удаляя запись.

        Запись остаётся намеренно: явный отзыв должен перебивать членство в
        группе, иначе человек зайдёт снова при следующем входе.
        """
        name = normalize(username)
        stmt = (update(User).where(User.username == name)
                .values(enabled=0, granted_by=by or "отозван",
                        granted_at=to_iso()))
        done = bool((await self.session.execute(stmt)).rowcount)
        if done:
            logger.info("Доступ отозван: %s (отозвал %s)", name, by or "—")
        return done

    async def delete(self, username: str) -> bool:
        stmt = delete(User).where(User.username == normalize(username))
        return bool((await self.session.execute(stmt)).rowcount)
