"""
Что агент уже делал в этом разговоре.

Зачем. В историю чата уходят только вопрос человека и текст ответа. Сами
вызовы инструментов — какой запрос выполнен, что он вернул — не сохраняются
нигде. На следующем ходу модель их не видит, и на вопрос «напиши запрос,
которым ты это получил» ей ответить нечем.

Хуже, чем «не помню». Правила подсказки требуют не выдумывать и честно
говорить, когда данных нет. Не найдя в контексте ни одного запроса, модель
делает единственный доступный ей вывод: раз запроса нет, значит его не
было, а прошлый ответ — выдумка. И объявляет выдумкой настоящие данные,
полученные настоящим запросом. Отказ от верного ответа выглядит как
честность, а на деле вводит в заблуждение сильнее любой ошибки.

Поэтому агент ведёт свой журнал: имя инструмента, аргументы, чем кончилось.
Журнал прикладывается к следующему вопросу тем же блоком, что и метрики.

Журнал живёт в памяти процесса, как и кэш истории разговора. Перезапуск
агента его теряет — и это записано прямым текстом в самом блоке, чтобы
модель говорила «запрос не сохранился», а не «я его не выполнял».
"""
from __future__ import annotations

import datetime
import logging
from collections import deque
from typing import Optional

logger = logging.getLogger("agent.actions")

# Сколько действий помним на разговор. Двадцати хватает на несколько ходов
# с инструментами, а больше и не поместится в подсказку осмысленно
MAX_PER_THREAD = 20

# Сколько разговоров держим. Предел не ради памяти — записи крошечные, —
# а чтобы словарь не рос бесконечно за недели работы
MAX_THREADS = 200

# Длина запроса в журнале. Запрос нужен дословно: его будут показывать
# человеку как ответ на «напиши сам запрос»
MAX_SQL = 2000

_log: dict = {}


def record(thread_id: str, name: str, args: dict, result: str) -> None:
    """Запомнить выполненное действие."""
    key = str(thread_id or "").strip()
    if not key or not name:
        return

    if key not in _log and len(_log) >= MAX_THREADS:
        _log.pop(next(iter(_log)), None)

    entry = {
        "at": datetime.datetime.now().strftime("%H:%M"),
        "tool": str(name),
        "cluster": str((args or {}).get("cluster") or ""),
        "sql": str((args or {}).get("sql") or "")[:MAX_SQL],
        "about": _about(args or {}),
        "outcome": _outcome(result),
    }
    _log.setdefault(key, deque(maxlen=MAX_PER_THREAD)).append(entry)


def _about(args: dict) -> str:
    """Чем именно интересовались — коротко, для строки журнала."""
    parts = []
    for field in ("table", "search", "hours", "seconds", "step_seconds",
                  "filter", "kind", "connection_id"):
        value = args.get(field)
        if value not in (None, "", 0):
            parts.append("%s=%s" % (field, str(value)[:60]))
    return ", ".join(parts)


def _outcome(result) -> str:
    """Чем кончилось. Ошибку называем ошибкой, а не «нет данных»."""
    text = str(result or "")
    if not text.strip():
        return "пусто"

    # Заголовки вида «## Результат SQL» в итог не берём: они одинаковы у
    # всех ответов и только мешают увидеть суть
    body = " ".join(line for line in text.splitlines()
                    if not line.strip().startswith("#"))
    body = " ".join(body.split())
    low = body.lower()

    if "ошибка" in low[:200] or "отклонён" in low[:200] or "не найден" in low[:200]:
        return "ОШИБКА: " + body[:160]
    if "строк не найдено" in low:
        return "выполнено, строк не найдено"
    return "выполнено, ответ получен (%d символов)" % len(text)


def fmt_block(thread_id: str) -> str:
    """Журнал действий блоком для подсказки. Пусто — действий не было."""
    entries = list(_log.get(str(thread_id or "").strip()) or [])
    if not entries:
        return ""

    lines = ["## Что агент уже выполнял в этом разговоре", "",
             "  Это точный список того, что БЫЛО выполнено: инструменты, их "
             "аргументы и чем всё кончилось.",
             "  Спрашивают «каким запросом ты это получил» — бери запрос "
             "отсюда и приводи дословно.",
             "  Ничего из перечисленного выдумкой не является: это записи "
             "самого агента, а не твоя память.", ""]

    for item in entries:
        head = "  %s  %s" % (item["at"], item["tool"])
        if item["cluster"]:
            head += " (%s)" % item["cluster"]
        if item["about"]:
            head += " · " + item["about"]
        lines.append(head)
        if item["sql"]:
            for line in item["sql"].splitlines() or [item["sql"]]:
                lines.append("      " + line)
        lines.append("      -> " + item["outcome"])

    lines += ["",
              "  Журнал живёт в памяти агента и теряется при его "
              "перезапуске. Если в нём нет запроса,",
              "  о котором спрашивают, так и скажи: запрос не сохранился, "
              "могу выполнить заново — но не",
              "  объявляй прошлый ответ выдуманным на этом основании."]
    return "\n".join(lines)


def forget(thread_id: Optional[str] = None) -> int:
    """Забыть журнал разговора или все сразу. Возвращает, сколько забыто."""
    if thread_id is None:
        count = len(_log)
        _log.clear()
        return count
    return 1 if _log.pop(str(thread_id or "").strip(), None) is not None else 0
