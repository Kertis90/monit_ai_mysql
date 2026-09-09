"""
Сборка приложения.

Здесь только состав: настройки, хранилище, middleware, роуты, статика и
жизненный цикл. Логика живёт в services и db — так видно, из чего собран
агент, не читая пять тысяч строк.

Запуск:
    python -m agent.main
"""
from __future__ import annotations

import asyncio
import logging
import sys
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles

from agent.api.responses import SafeJSONResponse
from agent.core.config import settings

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S")
logger = logging.getLogger("agent")

from agent.api.routes import (alerts, auth, chat, clusters, system,  # noqa: E402
                              users)
from agent.db.base import dispose, init_models, session_scope      # noqa: E402
from agent.db.repositories.alerts import AlertRepository           # noqa: E402
from agent.db.repositories.audit import AuditRepository            # noqa: E402
from agent.db.repositories.chats import ChatRepository             # noqa: E402
from agent.services import (access, anomaly, config_history,       # noqa: E402
                            digest, followup, growth, jobs, selfcheck, tasks)
from agent.services.mysql import refresh_db_versions               # noqa: E402

# Пути, доступные без входа. Всё остальное закрыто: забыть добавить проверку
# в новый роут проще, чем кажется, а цена ошибки — открытый наружу метод.
PUBLIC_PATHS = {
    "/login", "/api/login", "/api/logout", "/health",
    "/auth/oidc/login", "/auth/oidc/callback", "/api/alerts/ingest",
    "/docs", "/redoc", "/openapi.json", "/docs/oauth2-redirect",
}


# Страницы, а не данные: только их имеет смысл перенаправлять на форму
# входа. Всё остальное отвечает 401 — редирект на HTML в ответ на запрос
# JSON фронтенд разбирает как «сервер сломался»
PAGE_PATHS = {"/", "/report"}


def is_public(path: str) -> bool:
    return path in PUBLIC_PATHS or path.startswith("/static/")


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Агент %s: запуск", settings.version)
    access.apply_nslcd_defaults()
    await init_models()

    async with session_scope() as session:
        await AlertRepository(session).purge_old()
        await ChatRepository(session).purge_old()
        await AuditRepository(session).purge_old()
    await growth.purge_old()
    await config_history.purge_old()

    # Версии СУБД спрашиваем на старте: без них модель советует синтаксис
    # наугад — у 5.7 и 8.0 разные имена таблиц performance_schema.
    # Фоном, чтобы недоступный сервер БД не задерживал запуск агента.
    versions = asyncio.create_task(refresh_db_versions())
    # Проверки «помогло ли решение» живут в памяти процесса, и рестарт их
    # теряет — восстанавливаем на оставшееся время
    await followup.catch_up()

    # Сводка по расписанию: агент сам приходит с новостями, а не ждёт вопроса
    background = [asyncio.create_task(digest.scheduler())] if digest.ENABLED else []
    if anomaly.ENABLED:
        background.append(asyncio.create_task(anomaly.scheduler()))
    if selfcheck.ENABLED:
        background.append(asyncio.create_task(selfcheck.scheduler()))
    background.append(asyncio.create_task(growth.scheduler()))
    background.append(asyncio.create_task(config_history.scheduler()))

    yield

    for task in background:
        task.cancel()
    for task in background:
        try:
            await task
        except (asyncio.CancelledError, Exception):
            pass
    await followup.shutdown()
    # Незавершённые ответы: пережить остановку агента они всё равно
    # не могут, а висящие задачи задержали бы её
    await jobs.shutdown()
    await tasks.shutdown()

    # Задачу надо снять явно: недоступный сервер БД держит её в таймауте
    # подключения, и без отмены остановка ждёт её завершения
    versions.cancel()
    try:
        await versions
    except (asyncio.CancelledError, Exception):
        pass

    # Открытая вкладка чата держит WebSocket часами, и без принудительного
    # закрытия uvicorn ждёт клиента, растягивая рестарт на минуты
    for client in list(chat.ws_clients):
        try:
            await client.close(code=1001)
        except Exception:
            pass
    await dispose()
    logger.info("Агент остановлен")


def create_app() -> FastAPI:
    app = FastAPI(
        title="MySQL AI Monitoring Agent",
        version=settings.version,
        description=(
            "Разбор событий мониторинга MySQL и чат с агентом.\n\n"
            "Внешние системы регистрируют события через `POST /api/alerts/ingest` "
            "с токеном в заголовке `X-Ingest-Token`."),
        root_path=settings.prefix,
        lifespan=lifespan,
        # NaN и Infinity в любом поле иначе роняют весь ответ пятисоткой
        default_response_class=SafeJSONResponse,
        openapi_tags=[
            {"name": "Чат", "description": "Вопросы агенту и история переписки"},
            {"name": "События", "description": "Алерты, приём событий, память инцидентов"},
            {"name": "Кластеры", "description": "Состояние и метрики"},
            {"name": "Диагностика", "description": "SQL, ряды метрик, готовые проверки"},
            {"name": "Доступ", "description": "Вход и управление доступами"},
            {"name": "Служебные", "description": "Живость и конфигурация"},
        ])

    app.add_middleware(CORSMiddleware, allow_origins=["*"],
                       allow_methods=["*"], allow_headers=["*"])

    @app.exception_handler(Exception)
    async def any_error(request: Request, exc: Exception):
        """Необработанный сбой — тоже JSON, и с причиной.

        Пустая пятисотка в интерфейсе выглядит как «ошибка разбора JSON»:
        фронтенд ждёт объект, а получает страницу. Ответ с текстом причины
        показывается человеку и попадает в журнал.
        """
        logger.exception("Необработанная ошибка на %s", request.url.path)
        return SafeJSONResponse(
            {"error": "%s: %s" % (type(exc).__name__, exc),
             "path": request.url.path}, status_code=500)

    @app.middleware("http")
    async def guard(request: Request, call_next):
        if not settings.auth.enabled:
            return await call_next(request)

        # Путь берём сырым, как прислал прокси. Если nginx не срезает префикс
        # (proxy_pass без слэша на конце), сюда приходит /ai-agent/login —
        # в список открытых путей это не попадает, и агент отправляет на
        # /ai-agent/login снова. Поэтому префикс снимаем сами.
        prefix = (request.scope.get("root_path") or settings.prefix).rstrip("/")
        path = request.url.path
        if prefix and path.startswith(prefix):
            path = path[len(prefix):] or "/"

        if is_public(path):
            return await call_next(request)

        user = await access.current_user(request)
        if user:
            return await call_next(request)

        if path in PAGE_PATHS:
            return RedirectResponse(f"{prefix}/login", status_code=302)
        from fastapi.responses import JSONResponse
        return JSONResponse({"detail": "Требуется вход"}, status_code=401)

    for module in (auth, users, alerts, clusters, chat, system):
        app.include_router(module.router)

    static_dir = Path(settings.web_dir)
    if static_dir.exists():
        app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")
    else:
        logger.warning("Каталог интерфейса %s не найден", static_dir)
    return app


app = create_app()


def main() -> None:
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=settings.port,
                # Без ограничения uvicorn ждёт закрытия соединений
                # бесконечно, а вкладка чата держит сокет часами
                timeout_graceful_shutdown=5,
                log_level="info")


if __name__ == "__main__":
    main()
