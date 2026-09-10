"""
Одна работа на всех, кто её попросил.

Диагностика стоит дорого: профиль нагрузки — это два среза performance_schema
с паузой между ними, разбор настроек — сотни строк по SSH, самопроверка —
обход всех серверов. Раньше каждый такой запрос выполнялся сам по себе:
двое дежурных открыли страницу кластера одновременно — сервер снял профиль
дважды, нагрузив базу вдвое ради одинакового ответа.

Здесь работа привязана к ключу, а не к запросу. Первый пришедший запускает
её, остальные подключаются к той же задаче и получают тот же результат.
Свежий результат какое-то время держится в памяти: обновление страницы или
переход между вкладками не должны заново снимать те же метрики.

Второе свойство важнее первого: задача не отменяется вместе с запросом.
Закрытая вкладка больше не выбрасывает почти доделанную работу — она
дойдёт до конца, положит результат в кэш, и следующий, кто спросит,
получит его сразу.
"""
from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Callable, Optional

logger = logging.getLogger("agent.tasks")

# Сколько результат считается свежим по умолчанию. Диагностика меняется не
# ежесекундно, а вот открыть страницу дважды подряд — обычное дело.
DEFAULT_TTL = 20.0

# Когда выбрасывать остывшее из памяти
KEEP_S = 900.0

_running: dict[str, asyncio.Task] = {}
_cache: dict[str, tuple] = {}          # ключ -> (когда, результат)


def _evict(now: float) -> None:
    stale = [k for k, (when, _) in _cache.items() if now - when > KEEP_S]
    for key in stale:
        _cache.pop(key, None)


def cached(key: str, ttl: float = DEFAULT_TTL) -> Optional[Any]:
    """Готовый результат, если он ещё свежий."""
    hit = _cache.get(key)
    if hit and time.time() - hit[0] < ttl:
        return hit[1]
    return None


def running(key: str) -> bool:
    task = _running.get(key)
    return bool(task and not task.done())


async def shared(key: str, factory: Callable[[], Any],
                 ttl: float = DEFAULT_TTL) -> Any:
    """Выполнить работу один раз на всех, кто её попросил.

    ttl — сколько результат считается свежим. Ноль означает «всегда считать
    заново», но всё равно один раз на всех одновременных запросов.
    """
    now = time.time()
    _evict(now)

    hit = _cache.get(key)
    if hit and ttl > 0 and now - hit[0] < ttl:
        return hit[1]

    task = _running.get(key)
    if task is None or task.done():
        async def run() -> Any:
            try:
                result = await factory()
                _cache[key] = (time.time(), result)
                return result
            finally:
                _running.pop(key, None)

        task = asyncio.create_task(run())
        _running[key] = task
        logger.debug("Запущена общая задача %s", key)
    else:
        logger.debug("Подключились к идущей задаче %s", key)

    # shield — чтобы отменённый запрос не убивал работу: следующий, кто
    # спросит то же самое, получит готовый результат, а не начнёт заново
    return await asyncio.shield(task)


async def shared_within(key: str, factory: Callable[[], Any], budget: float,
                        ttl: float = DEFAULT_TTL) -> tuple:
    """Подождать результат не дольше budget. Возвращает (результат, успели).

    Не успели — работа НЕ отменяется: она доходит до конца и кладёт
    результат в кэш, а человек, нажав ещё раз через полминуты, получает
    его сразу. Это лучше, чем и ждать впустую, и потерять сделанное.

    Смысл в том, чтобы ответить раньше, чем истечёт терпение обратного
    прокси: nginx по умолчанию ждёт минуту и на её исходе отдаёт 504 —
    страницу с HTML вместо JSON, из-за которой в интерфейсе появлялась
    невнятная ошибка разбора.
    """
    try:
        return await asyncio.wait_for(shared(key, factory, ttl), timeout=budget), True
    except asyncio.TimeoutError:
        return None, False


def drop(key: str) -> None:
    """Забыть результат: нужно после действия, которое его меняет."""
    _cache.pop(key, None)


def stats() -> dict:
    return {"cached": len(_cache), "running": sum(
        1 for t in _running.values() if not t.done())}


async def shutdown() -> None:
    """Снять незавершённые задачи при остановке агента."""
    for task in list(_running.values()):
        if not task.done():
            task.cancel()
    for task in list(_running.values()):
        try:
            await task
        except (asyncio.CancelledError, Exception):
            pass
    _running.clear()
    _cache.clear()
