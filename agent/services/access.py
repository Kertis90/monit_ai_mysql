"""
Кого пускать в систему.

Три источника личности, в этом порядке: заголовок от доверенного прокси (SSO),
каталог (LDAP/AD), локальный администратор. Любой можно выключить.

Проверка пароля — ещё не право входа. Его даёт либо явная выдача в списке
доступов, либо членство в разрешённой группе или netgroup. Явный отзыв
перебивает группу: иначе администратор отзывает доступ, а человек заходит
снова при следующем входе, потому что из группы его никто не убирал.

Обращения к каталогу блокирующие (ldap3 синхронный), поэтому уводятся в
поток: держать на них цикл событий значит подвесить весь агент, пока
контроллер домена думает.
"""
from __future__ import annotations

import asyncio
import hmac
import logging
import os
from typing import Optional

from starlette.requests import Request

from agent.core.config import settings
from agent.core.security import read_session, verify_password
from agent.db.base import session_scope
from agent.db.repositories.users import UserRepository, normalize
from agent.services import directory

logger = logging.getLogger("agent.access")

ERR_BAD_CREDS = "Неверный логин или пароль"
ERR_NO_ACCESS = ("Учётная запись найдена, но доступ к системе не выдан. "
                 "Обратитесь к администратору.")

SSO_ENABLED = os.environ.get("SSO_ENABLED", "false").lower() == "true"
SSO_HEADER  = os.environ.get("SSO_HEADER", "X-Remote-User")
SSO_TRUSTED_PROXIES = {p.strip() for p in
                       os.environ.get("SSO_TRUSTED_PROXIES", "127.0.0.1,::1").split(",")
                       if p.strip()}


def sso_username(request: Request) -> Optional[str]:
    """Имя из заголовка, но только от доверенного адреса.

    Без проверки адреса любой клиент подставит себе чужое имя — заголовок
    подделывается тривиально.
    """
    if not SSO_ENABLED:
        return None
    peer = request.client.host if request.client else ""
    if peer not in SSO_TRUSTED_PROXIES:
        logger.warning("SSO-заголовок с недоверенного адреса %s — игнорирую", peer)
        return None
    return (request.headers.get(SSO_HEADER) or "").strip() or None


def local_authenticate(username: str, password: str) -> bool:
    """Локальный администратор — bootstrap-учётка, списка доступов не требует."""
    if not settings.auth.admin_password_hash:
        return False
    # Имя сравниваем тоже за постоянное время: иначе по задержке ответа
    # можно перебрать, какое имя существует
    user_ok = hmac.compare_digest(username or "", settings.auth.admin_user)
    pass_ok = verify_password(password or "", settings.auth.admin_password_hash)
    return user_ok and pass_ok


async def matched_groups(username: str) -> list[str]:
    """Разрешённые группы и netgroup, в которых состоит человек.

    Одно соединение с каталогом обслуживает обе проверки — открывать два
    незачем.
    """
    if not settings.ldap.enabled:
        return []
    if not (settings.ldap.allowed_groups or settings.ldap.allowed_netgroups):
        return []          # ни то, ни другое не задано — путь не используется

    def _lookup() -> list[str]:
        conn, own = directory._dir_conn(None)
        if conn is None:
            return []
        found: list[str] = []
        try:
            if settings.ldap.allowed_groups:
                found += directory.ldap_matched_groups(username, conn)
            if settings.ldap.allowed_netgroups:
                found += ["netgroup " + n for n in
                          directory.ldap_matched_netgroups(username, conn)]
        finally:
            if own:
                try:
                    conn.unbind()
                except Exception:
                    pass
        return found

    return await asyncio.to_thread(_lookup)


async def access_allowed(username: str, source: str = "") -> bool:
    """Есть ли право входа.

    Порядок важен: запись в списке доступов решает всё. Если её нет —
    смотрим группы, и вошедшего по группе сразу заводим в список, чтобы
    администратор видел, кто зашёл и почему, и мог отозвать доступ.
    """
    name = normalize(username)
    if not name:
        return False

    async with session_scope() as session:
        users = UserRepository(session)
        existing = await users.get(name)
        if existing is not None:
            return bool(existing.enabled)

    groups = await matched_groups(username)
    if not groups:
        return False

    async with session_scope() as session:
        await UserRepository(session).grant(
            name, granted_by=("группа " + ", ".join(groups))[:100])
    logger.info("Доступ по группе: %s (%s)", name, ", ".join(groups))
    return True


async def ldap_authenticate(username: str, password: str) -> bool:
    """Проверка пароля в каталоге. Синхронный ldap3 — в отдельном потоке."""
    return await asyncio.to_thread(directory.ldap_authenticate, username, password)


async def authenticate(username: str, password: str) -> tuple[Optional[str], str]:
    """(источник, ошибка). Источник None означает отказ."""
    if local_authenticate(username, password):
        return "local", ""

    if await ldap_authenticate(username, password):
        # Пароль верный — но этого мало
        if await access_allowed(username, "ldap"):
            return "ldap", ""
        logger.warning("Вход из каталога %s: доступ не выдан", username)
        return None, ERR_NO_ACCESS

    return None, ERR_BAD_CREDS


async def is_admin(user: Optional[dict]) -> bool:
    """Локальный админ — всегда админ, доменный — по роли в списке доступов."""
    if not user:
        return False
    if user.get("source") == "local":
        return True
    async with session_scope() as session:
        return await UserRepository(session).is_admin(user.get("username", ""))


async def current_user(request: Request) -> Optional[dict]:
    """Кто выполняет запрос: сначала SSO, затем сессионная cookie."""
    name = sso_username(request)
    if name:
        if not await access_allowed(name, "sso"):
            logger.warning("SSO-вход %s: доступ не выдан", name)
            return None
        return {"username": name, "source": "sso"}

    token = request.cookies.get("ai_agent_session", "")
    if not token:
        return None
    session_data = read_session(token)
    if not session_data:
        return None

    # Подписи и срока мало: доступ могли отозвать уже после выдачи cookie.
    # Проверяем только список — ходить в каталог на каждом запросе нельзя,
    # а вошедшие по группе в списке уже есть, так что отзыв действует сразу.
    if session_data.get("source") != "local":
        async with session_scope() as db:
            if not await UserRepository(db).allowed(session_data["username"]):
                logger.warning("Сессия %s: доступ отозван — вход закрыт",
                               session_data["username"])
                return None
    return session_data


async def sso_denied(request: Request) -> bool:
    """Прокси нас аутентифицировал, но доступа у человека нет."""
    name = sso_username(request)
    return bool(name) and not await access_allowed(name, "sso")


def apply_nslcd_defaults() -> list[str]:
    """Дозаполнить пустые настройки каталога из nslcd.conf.

    Настройки уже описаны в nslcd, и держать их в двух местах значит рано или
    поздно получить расхождение. Заполненные значения не трогаем: явная
    настройка всегда главнее.
    """
    path = settings.ldap.nslcd_conf
    if not (settings.ldap.enabled and path and os.path.exists(path)):
        return []
    try:
        import importlib.util
        from pathlib import Path
        # Рядом с пакетом (так его кладёт install_agent.sh) либо в scripts —
        # чтобы запуск из рабочей копии тоже работал
        here = Path(__file__).resolve().parents[1]
        for candidate in (here / "import_nslcd.py",
                          here.parent / "scripts" / "import_nslcd.py"):
            if candidate.exists():
                break
        else:
            logger.warning("Парсер import_nslcd.py не найден — %s не прочитан", path)
            return []
        spec = importlib.util.spec_from_file_location("nslcd_import", str(candidate))
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        values = module.build(module.parse_nslcd(path), "")
    except Exception as exc:
        logger.warning("Не удалось прочитать %s: %s", path, exc)
        return []

    fields = {
        "LDAP_URL": "url", "LDAP_BASE_DN": "base_dn", "LDAP_USER_BASE": "user_base",
        "LDAP_USER_FILTER": "user_filter", "LDAP_BIND_TEMPLATE": "bind_template",
        "LDAP_SEARCH_USER": "search_user", "LDAP_SEARCH_PASSWORD": "search_password",
        "LDAP_NETGROUP_BASE": "netgroup_base", "LDAP_NETGROUP_FILTER": "netgroup_filter",
    }
    taken = []
    for key, attr in fields.items():
        if getattr(settings.ldap, attr) or not values.get(key):
            continue
        setattr(settings.ldap, attr, values[key])
        setattr(directory, key, values[key])       # модуль читает свои копии
        taken.append("%s=%s" % (key, "***" if key.endswith("PASSWORD") else values[key]))
    if taken:
        logger.info("Настройки каталога дозаполнены из %s: %s", path, ", ".join(taken))
    return taken
