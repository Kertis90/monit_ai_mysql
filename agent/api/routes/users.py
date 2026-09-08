"""Список доступов и поиск людей в каталоге. Только для администраторов."""
from __future__ import annotations

import asyncio
import logging

from fastapi import APIRouter, HTTPException, Request

from agent.api.deps import AdminUser, Audit, DbSession, Users
from agent.db.repositories.audit import AuditRepository
from agent.db.repositories.users import normalize
from agent.schemas.api import (DirectorySearchOut, GrantRequest, UserOut,
                               UsersOut)
from agent.services import audit, directory

logger = logging.getLogger("agent.api.users")
router = APIRouter(tags=["Доступ"])


@router.get("/api/users", response_model=UsersOut,
            summary="Список выданных доступов")
async def list_users(admin: AdminUser, users: Users) -> UsersOut:
    why = directory.directory_search_status()
    return UsersOut(items=[UserOut.model_validate(u) for u in await users.list()],
                    ldap_search=not why, ldap_search_reason=why)


@router.post("/api/users", summary="Выдать доступ")
async def grant_access(req: GrantRequest, admin: AdminUser, users: Users,
                       journal: Audit, request: Request):
    # Схема уже проверила логин и роль, поэтому здесь остаётся только запись
    user = await users.grant(req.username, display_name=req.display_name,
                             email=req.email, role=req.role,
                             granted_by=admin.get("username", ""))
    if user is None:
        raise HTTPException(
            status_code=500,
            detail="Запись в базу доступов не удалась — подробности в журнале: "
                   "journalctl -u ai-alert-agent | grep -i доступ")
    await journal.add(action="доступ выдан", username=admin.get("username", ""),
                      target=user.username, detail="роль: %s" % user.role,
                      ip=audit.client_ip(request))
    return {"ok": True, "username": user.username, "role": user.role}


@router.delete("/api/users/{username}", summary="Отозвать доступ")
async def revoke_access(username: str, admin: AdminUser, users: Users,
                        journal: Audit, request: Request,
                        hard: bool = False):
    """По умолчанию отзыв, а не удаление.

    Запись должна остаться: явный отзыв обязан перебивать членство в группе,
    иначе человек зайдёт снова при следующем входе. hard=true — удалить
    совсем, тогда доступ по группе снова заработает.
    """
    ok = (await users.delete(username) if hard
          else await users.revoke(username, admin.get("username", "")))
    if not ok:
        raise HTTPException(status_code=404, detail="Пользователь не найден")
    await journal.add(action="доступ удалён" if hard else "доступ отозван",
                      username=admin.get("username", ""),
                      target=normalize(username), ip=audit.client_ip(request))
    return {"ok": True, "username": normalize(username), "hard": hard}


@router.get("/api/directory/search", response_model=DirectorySearchOut,
            summary="Поиск учётной записи в каталоге")
async def search_directory(admin: AdminUser, users: Users,
                           q: str = "", limit: int = 25) -> DirectorySearchOut:
    """Выдавать доступ выбором из списка, а не вводом логина вручную.

    Потолок в 500: список листается страницами, и обрезать его на сотне
    значит прятать людей, которых администратор ищет.
    """
    found, err = await asyncio.to_thread(
        directory.ldap_search_users, q, min(max(limit, 1), 500))
    found.sort(key=lambda f: (f.get("display_name") or "", f["username"]))

    granted = {u.username for u in await users.list() if u.enabled}
    for item in found:
        item["already_granted"] = item["username"] in granted
    return DirectorySearchOut(items=found, query=q, error=err)


@router.get("/api/audit", summary="Журнал действий")
async def audit_log(admin: AdminUser, session: DbSession,
                    days: int = 30, limit: int = 200, action: str = ""):
    """Кто что делал: входы, выдача и отзыв доступов, удаление событий,
    запись решений, выполненные SQL-запросы."""
    rows = await AuditRepository(session).recent(
        days=max(1, min(days, 365)), limit=max(1, min(limit, 1000)),
        action=action or None)
    return {"total": len(rows),
            "items": [{"ts": r.ts, "username": r.username, "action": r.action,
                       "target": r.target, "detail": r.detail, "ip": r.ip,
                       "ok": bool(r.ok)} for r in rows]}
