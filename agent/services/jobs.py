"""
Ответы, которые переживают закрытие вкладки.

Раньше генерация шла прямо в обработчике сокета: закрыл вкладку или нажал
обновление — и разбор, на который агент потратил минуту сбора метрик и
чтения логов, пропадал целиком. Особенно обидно на долгих вопросах, где
модель ходит инструментами.

Теперь ответ считает отдельная задача, привязанная к разговору, а не к
соединению. Сокет к ней подписывается: пропало соединение — задача идёт
дальше и в конце сохраняет ответ в историю. Клиент вернулся — подписывается
снова, получает уже накопленное и продолжает смотреть с того же места.

Реестр в памяти процесса: перезапуск агента задачи всё равно обрывает, а
переносить незавершённую генерацию через рестарт незачем — вопрос проще
задать заново.
"""
from __future__ import annotations

import asyncio
import logging
import time
from typing import Callable, Optional

logger = logging.getLogger("agent.jobs")

# Сколько держать завершённую задачу. Нужно ровно на то, чтобы вернувшийся
# клиент забрал ответ, если тот дописался, пока страница перезагружалась.
KEEP_DONE_S = 600
# Предохранитель: задача, идущая дольше, скорее всего повисла на внешнем
# вызове, и держать её вечно незачем
MAX_RUN_S = 1800


class Job:
    """Одна генерация ответа в конкретном разговоре."""

    def __init__(self, thread_id: str, question: str) -> None:
        self.thread_id = thread_id
        self.question = question
        self.started = time.time()
        self.finished: Optional[float] = None
        self.stopped = False
        # События протокола в том же виде, в каком уходят в сокет: так
        # вернувшемуся клиенту достаточно проиграть их подряд
        self.events: list[dict] = []
        self.subscribers: set[asyncio.Queue] = set()
        self.task: Optional[asyncio.Task] = None
        self.stop_event = asyncio.Event()

    @property
    def done(self) -> bool:
        return self.finished is not None

    @property
    def answer(self) -> str:
        return "".join(e.get("text", "") for e in self.events
                       if e.get("type") == "token")

    async def emit(self, event: dict) -> None:
        """Отправить событие подписчикам и запомнить для тех, кто вернётся."""
        self.events.append(event)
        for queue in list(self.subscribers):
            try:
                queue.put_nowait(event)
            except Exception:
                self.subscribers.discard(queue)

    def subscribe(self) -> asyncio.Queue:
        queue: asyncio.Queue = asyncio.Queue()
        self.subscribers.add(queue)
        return queue

    def unsubscribe(self, queue: asyncio.Queue) -> None:
        self.subscribers.discard(queue)


_jobs: dict[str, Job] = {}


def get(thread_id: str) -> Optional[Job]:
    """Задача разговора, если она есть и ещё интересна."""
    job = _jobs.get(thread_id)
    if job is None:
        return None
    if job.done and time.time() - (job.finished or 0) > KEEP_DONE_S:
        _jobs.pop(thread_id, None)
        return None
    return job


def running(thread_id: str) -> Optional[Job]:
    job = get(thread_id)
    return job if job and not job.done else None


async def start(thread_id: str, question: str,
                runner: Callable[[Job], "asyncio.Future"]) -> Job:
    """Запустить генерацию. Если для разговора уже идёт — вернуть её.

    Второй вопрос в тот же разговор, пока не ответил первый, — это почти
    всегда нетерпеливое нажатие Enter, а не осознанное желание получить два
    ответа вперемешку.
    """
    existing = running(thread_id)
    if existing is not None:
        logger.info("Разговор %s: ответ уже готовится, второй запуск пропущен",
                    thread_id)
        return existing

    job = Job(thread_id, question)
    _jobs[thread_id] = job

    async def guard() -> None:
        try:
            await asyncio.wait_for(runner(job), timeout=MAX_RUN_S)
        except asyncio.CancelledError:
            await job.emit({"type": "done", "stopped": True})
            raise
        except asyncio.TimeoutError:
            logger.error("Разговор %s: генерация не уложилась в %d с",
                         thread_id, MAX_RUN_S)
            await job.emit({"type": "error",
                            "text": "Ответ готовился слишком долго и был прерван."})
            await job.emit({"type": "done", "stopped": True})
        except Exception as exc:
            logger.error("Разговор %s: генерация не удалась: %s", thread_id, exc)
            await job.emit({"type": "error", "text": "Ошибка: %s" % exc})
            await job.emit({"type": "done", "stopped": True})
        finally:
            job.finished = time.time()
            # Будим подписчиков: без метки они ждали бы очередь вечно
            for queue in list(job.subscribers):
                try:
                    queue.put_nowait(None)
                except Exception:
                    pass

    job.task = asyncio.create_task(guard())
    return job


def stop(thread_id: str) -> bool:
    """Прервать генерацию. Сам ответ при этом сохраняется: его уже видели."""
    job = running(thread_id)
    if job is None:
        return False
    job.stopped = True
    job.stop_event.set()
    return True


def cleanup() -> int:
    """Убрать давно завершённые. Вызывается при остановке агента."""
    now = time.time()
    stale = [tid for tid, job in _jobs.items()
             if job.done and now - (job.finished or 0) > KEEP_DONE_S]
    for tid in stale:
        _jobs.pop(tid, None)
    return len(stale)


async def shutdown() -> None:
    """Снять незавершённые задачи при остановке."""
    for job in list(_jobs.values()):
        if job.task and not job.task.done():
            job.task.cancel()
    for job in list(_jobs.values()):
        if job.task:
            try:
                await job.task
            except (asyncio.CancelledError, Exception):
                pass
    _jobs.clear()
