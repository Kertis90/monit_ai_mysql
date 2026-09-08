"""
Помогло ли решение.

Память инцидентов хранит, что сделали, но не знает, сработало ли это. При
следующем таком же случае агент предлагает записанное как проверенное — хотя
проверял его только тот, кто записал, и то на глаз.

Поэтому через заданное время после записи решения агент сам смотрит, не
повторилось ли событие, и дописывает вывод к решению. Дальше в разбор
попадает уже не «перезапустили mysqld», а «перезапустили mysqld — за 15 минут
не повторилось» либо «повторилось через 4 минуты».

Отметка дописывается в текст решения, а не в отдельную колонку: create_all не
меняет существующие таблицы, и новая колонка просто отсутствовала бы на всех
установленных базах.
"""
from __future__ import annotations

import asyncio
import datetime
import logging
import os

from agent.db.base import session_scope
from agent.db.models import from_iso, to_iso
from agent.db.repositories.alerts import AlertRepository

logger = logging.getLogger("agent.followup")

# Через сколько проверять. Меньше пяти минут — не успевает проявиться
# повтор, больше часа — вывод уже никому не нужен.
CHECK_MINUTES = max(5.0, min(60.0, float(os.environ.get("FOLLOWUP_MINUTES", "15"))))

MARK = "[проверено через"

# Живые проверки: нужны, чтобы снять их при остановке агента
_pending: set = set()


def already_checked(resolution: str) -> bool:
    return MARK in (resolution or "")


async def _verify(alert_id: int) -> None:
    """Повторилось ли событие после записи решения."""
    async with session_scope() as session:
        row = await AlertRepository(session).get(alert_id)
        if row is None or not row.resolution or already_checked(row.resolution):
            return
        name, cluster = row.alert, row.cluster
        resolved_at = from_iso(row.resolved_at) or from_iso(row.ts)

    async with session_scope() as session:
        repo = AlertRepository(session)
        # Берём с запасом и отбираем сами: событие могло прийти и через
        # секунду после записи решения
        recent = await repo.recent(cluster=cluster or None, name=name,
                                   hours=CHECK_MINUTES / 60 + 1, limit=50)
        repeats = [r for r in recent
                   if r.id != alert_id
                   and (from_iso(r.ts) or datetime.datetime.min) > resolved_at]

        if repeats:
            first = from_iso(repeats[-1].ts)
            minutes = max(0, int((first - resolved_at).total_seconds() // 60))
            verdict = ("%s %g мин: ПОВТОРИЛОСЬ через %d мин (записей: %d) — "
                       "решение не помогло или устранило следствие"
                       % (MARK, CHECK_MINUTES, minutes, len(repeats)))
        else:
            verdict = ("%s %g мин: не повторялось — решение выглядит рабочим"
                       % (MARK, CHECK_MINUTES))

        row = await repo.get(alert_id)
        if row is None or already_checked(row.resolution or ""):
            return
        await repo.resolve(alert_id, (row.resolution or "") + "\n" + verdict + "]",
                           row.resolved_by or "")
        logger.info("Инцидент %d (%s): %s", alert_id, name, verdict + "]")


async def _sleep_then_verify(alert_id: int, delay_s: float) -> None:
    try:
        await asyncio.sleep(delay_s)
        await _verify(alert_id)
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        logger.error("Проверка инцидента %d не выполнена: %s", alert_id, exc)


def schedule(alert_id: int, delay_s: float | None = None) -> None:
    """Поставить проверку. Вызывается сразу после записи решения."""
    task = asyncio.create_task(_sleep_then_verify(
        alert_id, CHECK_MINUTES * 60 if delay_s is None else delay_s))
    _pending.add(task)
    task.add_done_callback(_pending.discard)


async def catch_up() -> int:
    """Догнать пропущенное после перезапуска агента.

    Задачи живут в памяти процесса, и рестарт их теряет. Здесь находим
    решения, записанные недавно и ещё не проверенные, и ставим проверку на
    оставшееся время.
    """
    horizon = to_iso(datetime.datetime.now(datetime.timezone.utc)
                     - datetime.timedelta(minutes=CHECK_MINUTES * 4))
    scheduled = 0
    async with session_scope() as session:
        rows = await AlertRepository(session).recent(
            hours=CHECK_MINUTES * 4 / 60, limit=200)
    now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
    for row in rows:
        if not row.resolution or already_checked(row.resolution):
            continue
        resolved_at = from_iso(row.resolved_at)
        if resolved_at is None or to_iso(resolved_at) < horizon:
            continue
        left = CHECK_MINUTES * 60 - (now - resolved_at).total_seconds()
        schedule(row.id, max(5.0, left))
        scheduled += 1
    if scheduled:
        logger.info("Отложенных проверок инцидентов восстановлено: %d", scheduled)
    return scheduled


async def shutdown() -> None:
    """Снять незавершённые проверки, иначе остановка ждёт их таймеры."""
    for task in list(_pending):
        task.cancel()
    for task in list(_pending):
        try:
            await task
        except (asyncio.CancelledError, Exception):
            pass
