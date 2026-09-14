"""
Смысловой поиск по схеме: векторы вместо совпадения букв.

Зачем. Человек спрашивает «покажи учётные записи», а таблица называется
`vgroups` и подписана «Абоненты». Лексический поиск тут бессилен: ни одной
общей буквы у «учётных записей» и «абонентов» нет, а перечислить все
синонимы заранее нельзя — их придумывает тот, кто спрашивает.

Вектор снимает эту проблему: близость считается по смыслу, а не по
написанию. Индекс строится один раз вместе со снимком схемы и хранится у
агента; при вопросе векторизуется только сам вопрос — одно короткое
обращение к модели.

Режим опциональный, как и инструменты: не всякий OpenAI-совместимый
эндпоинт отдаёт /embeddings. При EMBED_MODE=auto делается пробный запрос, и
при отказе агент ищет по-старому, по словам. Это не деградация до
бесполезности: точное имя таблицы в вопросе лексический поиск находит
лучше и без всяких векторов.

Похожесть считаем скалярным произведением: векторы нормируются при
сохранении, и тогда скалярное произведение и есть косинус. Numpy не берём —
лишняя зависимость ради сотен векторов, которые перебираются за
миллисекунды.
"""
from __future__ import annotations

import logging
import math
from typing import Optional

import httpx

from agent.core.config import settings
from agent.services.llm import AUTH_HEADER, LLM_BASE_URL

logger = logging.getLogger("agent.embed")

EMBED_MODE = settings.llm.embed_mode
EMBED_MODEL = settings.llm.embed_model
EMBED_TIMEOUT = settings.llm.embed_timeout

# По каким кускам имени узнаётся модель векторов в списке эндпоинта.
# Скачивать её неоткуда и незачем: она либо уже развёрнута рядом с
# генеративной, либо её нет вовсе — и тогда работает запасной путь.
EMBED_HINTS = ("embed", "bge", "e5", "gte", "minilm", "labse", "sbert",
               "rubert", "sentence")

# По сколько текстов в одном запросе. Больше — быстрее, но ответ на тысячу
# документов весит десятки мегабайт и упирается в предел тела запроса
BATCH = 64

# Ниже этой близости совпадение случайно. Значение подобрано так, чтобы
# «учётные записи» находили «абонентов», а «как дела» — ничего.
MIN_SCORE = 0.30

# Умеет ли эндпоинт векторы. None — ещё не проверяли
EMBED_SUPPORTED: Optional[bool] = None


async def discover() -> str:
    """Найти модель векторов среди тех, что отдаёт эндпоинт.

    Имя модели незачем угадывать руками: эндпоинт сам перечисляет, что у
    него развёрнуто. Без интернета это единственный вменяемый путь —
    скачать модель всё равно неоткуда, а та, что уже стоит рядом с
    генеративной, называется как ей вздумается.
    """
    headers = {"Authorization": AUTH_HEADER}
    try:
        async with httpx.AsyncClient(timeout=20) as client:
            r = await client.get(f"{LLM_BASE_URL}/models", headers=headers)
            r.raise_for_status()
            data = r.json().get("data") or []
    except Exception as exc:
        logger.info("Список моделей не получен: %s", exc)
        return ""

    names = [str(item.get("id") or "") for item in data if item.get("id")]
    for name in names:
        low = name.lower()
        if any(hint in low for hint in EMBED_HINTS):
            logger.info("Модель векторов найдена сама: %s", name)
            return name
    logger.info("Среди %d моделей эндпоинта векторной не нашлось",
                len(names))
    return ""


async def probe() -> bool:
    """Готов ли смысловой поиск. Проверяем один раз за жизнь агента."""
    global EMBED_SUPPORTED, EMBED_MODEL
    if EMBED_SUPPORTED is not None:
        return EMBED_SUPPORTED
    if EMBED_MODE == "off":
        EMBED_SUPPORTED = False
        return False

    # Имя не задано — спрашиваем эндпоинт, что у него есть
    if not EMBED_MODEL:
        EMBED_MODEL = await discover()
        if not EMBED_MODEL:
            EMBED_SUPPORTED = False
            logger.info("Векторный поиск: модели векторов нет, "
                        "ищем по словам и через саму модель")
            return False

    if EMBED_MODE == "on":
        EMBED_SUPPORTED = True
        return True

    got = await encode(["проверка"])
    EMBED_SUPPORTED = bool(got)
    logger.info("Векторный поиск: %s",
                "доступен, модель %s" % EMBED_MODEL if EMBED_SUPPORTED else
                "эндпоинт не отдаёт /embeddings, ищем по словам")
    return EMBED_SUPPORTED


async def encode(texts: list) -> list:
    """Векторы для текстов. Пустой список — векторов не будет.

    Пустой ответ здесь не исключение, а обычный исход: у половины
    установок эндпоинт умеет только генерацию. Поэтому не бросаем, а
    возвращаем пусто — зовущий откатится на поиск по словам.
    """
    clean = [str(t or "")[:4000] for t in texts if str(t or "").strip()]
    if not clean:
        return []

    headers = {"Content-Type": "application/json", "Authorization": AUTH_HEADER}
    out = []
    for start in range(0, len(clean), BATCH):
        chunk = clean[start:start + BATCH]
        try:
            async with httpx.AsyncClient(timeout=EMBED_TIMEOUT) as client:
                r = await client.post(f"{LLM_BASE_URL}/embeddings",
                                      headers=headers,
                                      json={"model": EMBED_MODEL,
                                            "input": chunk})
                r.raise_for_status()
                data = r.json().get("data") or []
        except Exception as exc:
            logger.info("Векторы не получены: %s", exc)
            return []

        if len(data) != len(chunk):
            logger.warning("Эндпоинт вернул %d векторов на %d текстов",
                           len(data), len(chunk))
            return []
        for item in sorted(data, key=lambda d: d.get("index", 0)):
            out.append(normalize(item.get("embedding") or []))

    return [v for v in out if v]


def normalize(vector) -> list:
    """Вектор единичной длины, округлённый до пяти знаков.

    Нормируем при сохранении, а не при поиске: тогда близость — это
    скалярное произведение, без корней на каждом сравнении. Округление
    режет размер индекса вдвое и на близость не влияет.
    """
    try:
        values = [float(x) for x in vector]
    except (TypeError, ValueError):
        return []
    length = math.sqrt(sum(x * x for x in values))
    if not length:
        return []
    return [round(x / length, 5) for x in values]


def similarity(a, b) -> float:
    """Близость нормированных векторов: от -1 до 1."""
    if not a or not b or len(a) != len(b):
        return 0.0
    return sum(x * y for x, y in zip(a, b))


def nearest(query, index: dict, limit: int = 3,
            min_score: float = MIN_SCORE) -> list:
    """Ближайшие по смыслу ключи: [(ключ, близость), ...].

    Порог обязателен: без него на любой вопрос находится «самое похожее»,
    даже когда похожего нет, — и в подсказку уезжает случайная таблица.
    """
    if not query or not index:
        return []
    scored = []
    for key, vector in index.items():
        score = similarity(query, vector)
        if score >= min_score:
            scored.append((key, round(score, 4)))
    scored.sort(key=lambda pair: -pair[1])
    return scored[:limit]
