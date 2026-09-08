"""
Ограничение частоты приёма событий извне.

Смысл не в экономии на модели — она развёрнута локально. Смысл в том, что
зациклившийся скрипт на стороне Zabbix за ночь зальёт таблицу событий сотнями
тысяч записей: лента станет нечитаемой, память инцидентов — бесполезной, а
хранилище распухнет. Ограничение отсекает поток, но не мешает нормальной
работе: сотня событий в минуту от одной системы — это уже авария на её
стороне, а не мониторинг.

Счётчик в памяти процесса: агент один, а переживать его перезапуск такому
счётчику незачем.
"""
from __future__ import annotations

import logging
import os
import time
from collections import deque

logger = logging.getLogger("agent.ratelimit")

# Событий в минуту от одного отправителя. Ноль отключает проверку.
INGEST_RATE_PER_MIN = max(0, int(os.environ.get("INGEST_RATE_PER_MIN", "120")))

WINDOW_S = 60.0

_hits: dict[str, deque] = {}
# Чтобы не писать в журнал на каждое отклонённое событие: при потоке в
# тысячи запросов сам журнал станет второй проблемой
_reported: dict[str, float] = {}


def allow(key: str, limit: int = 0) -> tuple[bool, int]:
    """(пропускать ли, сколько осталось в окне)."""
    cap = limit or INGEST_RATE_PER_MIN
    if cap <= 0:
        return True, -1

    now = time.monotonic()
    hits = _hits.setdefault(key, deque())
    while hits and now - hits[0] > WINDOW_S:
        hits.popleft()

    if len(hits) >= cap:
        if now - _reported.get(key, 0) > 60:
            _reported[key] = now
            logger.warning(
                "Приём событий от %s ограничен: больше %d в минуту. "
                "Похоже на зациклившийся скрипт на стороне отправителя.",
                key, cap)
        return False, 0

    hits.append(now)
    return True, cap - len(hits)


def state(key: str) -> dict:
    """Сколько израсходовано — для диагностики, без изменения счётчика."""
    now = time.monotonic()
    hits = _hits.get(key) or deque()
    used = sum(1 for t in hits if now - t <= WINDOW_S)
    return {"used": used, "limit": INGEST_RATE_PER_MIN,
            "left": max(0, INGEST_RATE_PER_MIN - used)}


def reset() -> None:
    """Сбросить счётчики. Нужен проверкам, в работе не вызывается."""
    _hits.clear()
    _reported.clear()
