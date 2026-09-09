"""
Разбор собранного: по одному блоку и по кластеру целиком.

Страница кластера показывает то, что агент собрал: профиль нагрузки,
репликацию, настройки, запас по ресурсам, индексы, копии. Каждый блок по
отдельности читается, но выводы из них человек до сих пор делал сам, а
самое важное обычно видно только на пересечении: медленные запросы плюс
отставание реплики плюс innodb_flush_log_at_trx_commit=1 — это одна
история, а не три.

Здесь эти куски отдаются модели: отдельно один блок («что это значит») и
все собранные вместе («что из этого следует»). Данные берутся те же, что
человек видит на экране, — разбор объясняет именно их, а не другой срез,
снятый пятью минутами позже.
"""
from __future__ import annotations

import logging

from agent.services.analysis import system_prompt
from agent.services.assistant import cluster_notes, recent_alerts
from agent.services.llm import llm_complete
from agent.services.prometheus import collect_current

logger = logging.getLogger("agent.insight")

# Разумный предел на один блок и на всё вместе. Модели развёрнуты локально,
# и дело не в цене: слишком длинный кусок вытесняет из внимания начало, где
# обычно и стоит главное.
BLOCK_LIMIT = 24000
TOTAL_LIMIT = 90000

ONE_TASK = """Объясни этот один блок диагностики.

Формат ответа:
  1. Одной фразой — всё ли здесь в порядке.
  2. Что именно бросается в глаза, с числами из блока.
  3. Что с этим делать, по шагам, и что можно менять на ходу, а что требует
     перезапуска.

Не пересказывай блок целиком и не повторяй то, что и так видно в таблице.
Если данных для вывода не хватает, скажи, какой ещё блок нужно снять."""

ALL_TASK = """Собери всё это в один разбор кластера.

Формат ответа:
  1. Состояние кластера одной фразой: работает нормально / есть чем заняться /
     требует вмешательства сейчас.
  2. Связанные наблюдения: что из разных блоков складывается в одну причину.
     Это главное — ради этого разбор и делается.
  3. Что делать, по убыванию важности, с указанием, откуда вывод.
  4. Чего не хватило, чтобы досказать.

Не перечисляй блоки по очереди и не повторяй их содержимое: человек их уже
видел. Если всё в порядке, так и скажи — придумывать проблемы не нужно."""


def _trim(text: str, limit: int) -> str:
    """Обрезать середину, а не хвост.

    В конце блока обычно итог и пояснения, в начале — самое тяжёлое из
    найденного. Резать надо середину, где идёт длинный список.
    """
    text = text or ""
    if len(text) <= limit:
        return text
    head = text[: limit // 2]
    tail = text[-limit // 2:]
    return head + "\n\n  […пропущено %d символов середины…]\n\n" % (
        len(text) - limit) + tail


def _blocks_text(blocks: list) -> str:
    parts, used = [], 0
    for block in blocks:
        title = str(block.get("title") or "Блок").strip()[:120]
        body = _trim(str(block.get("text") or "").strip(), BLOCK_LIMIT)
        if not body:
            continue
        piece = "## %s\n\n%s" % (title, body)
        if used + len(piece) > TOTAL_LIMIT:
            parts.append("(остальные блоки не поместились в разбор)")
            break
        parts.append(piece)
        used += len(piece)
    return "\n\n".join(parts)


async def cluster_context(cluster: dict) -> str:
    """Опора для разбора: кто это, как себя чувствует, что знают люди."""
    lines = ["## Кластер",
             "",
             "  %s (%s)" % (cluster["label"], cluster["name"]),
             "  Основной сервер: %s" % cluster.get("primary_ip", "?")]
    if cluster.get("replica_ip"):
        lines.append("  Реплика: %s" % cluster["replica_ip"])
    if cluster.get("app_ip"):
        lines.append("  Ядро системы: %s" % cluster["app_ip"])

    try:
        state = await collect_current(cluster)
        primary = state.get("primary") or {}
        if primary:
            lines += ["", "  Прямо сейчас: %s" % ", ".join(
                "%s=%s" % (k, v) for k, v in list(primary.items())[:10])]
    except Exception as exc:
        logger.info("Состояние для разбора не собрано: %s", exc)

    try:
        alerts = await recent_alerts(cluster["name"], hours=24, limit=10)
        if alerts:
            lines += ["", "  События за сутки:"]
            lines += ["    %s — %s" % (a.get("alert"), a.get("summary") or "")
                      for a in alerts]
    except Exception as exc:
        logger.info("События для разбора не собраны: %s", exc)

    notes = await cluster_notes(cluster["name"])
    if notes:
        lines += ["", notes]
    return "\n".join(lines)


async def analyze(cluster: dict, blocks: list, scope: str = "all",
                  question: str = "") -> str:
    """Разобрать собранное. scope=one — один блок, all — всё вместе."""
    body = _blocks_text(blocks)
    if not body.strip():
        return ("Разбирать нечего: соберите хотя бы один блок на странице "
                "кластера, тогда появится что объяснять.")

    task = ONE_TASK if scope == "one" else ALL_TASK
    if question.strip():
        task += "\n\nОтдельно ответь на вопрос: " + question.strip()[:500]

    context = await cluster_context(cluster)
    messages = [
        {"role": "system", "content": system_prompt()},
        {"role": "user",
         "content": "%s\n\n# Собранные данные\n\n%s\n\n# Задача\n\n%s"
                    % (context, body, task)},
    ]
    answer = await llm_complete(messages)
    return (answer or "").strip() or "Модель вернула пустой ответ."
