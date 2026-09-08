"""
Разбор намерения по тексту вопроса.

Запасной путь: основной — инструменты LLM, она сама решает, что ей нужно.
Ключевые слова остаются для эндпоинтов, которые не поддерживают tool calling,
и для случаев, когда пробный запрос показал, что модель их не умеет.
"""
from __future__ import annotations

import datetime
import logging
import re
from typing import Optional

from agent.core.config import settings

logger = logging.getLogger("agent.intents")

MAX_METRICS_HOURS = settings.prometheus.max_metrics_hours

# SQL прямо в сообщении: «выполни SELECT ...» или запрос в блоке ```sql
SQL_IN_TEXT = re.compile(
    r"```(?:sql)?\s*(.+?)```|((?:select|show|explain|describe)\s+.+)",
    re.I | re.S)

# Вопросы про историю без явного периода: «покажи динамику», «был ли рост».
# Для них берём окно по умолчанию, иначе агент отвечает, что данных нет,
# хотя Prometheus их хранит.
# Вопросы, при которых в контекст подмешивается история алертов из БД.
# Держим список узким: лишний блок только раздувает промпт.
ALERT_KEYWORDS = (
    "алерт", "alert", "инцидент", "авари", "срабатыв", "сработа",
    "тревог", "происшеств", "что случилось", "сбой", "сбои", "сбоя",
    "были проблем", "была проблем", "проблемы были", "падал", "падени",
)

HISTORY_KEYWORDS = (
    "истори", "динамик", "тренд", "за период", "график", "графики",
    "как менялось", "как менялась", "как изменил", "рост", "росла", "рос ли",
    "падал", "падени", "снижал", "было раньше", "в прошлом",
    "статистик", "средн", "пик", "максимум за", "минимум за",
)

TIME_KEYWORDS = {
    "позавчера": 54, "вчера": 30,
    "прошлый день": 30, "прошлой ночью": 16,
    "утром": 14, "ночью": 12, "вечером": 12, "днём": 12, "днем": 12,
    "сегодня": 24, "за сегодня": 24,
    "последние сутки": 26, "за сутки": 26, "сутки": 26, "за день": 26,
    "на прошлой неделе": 170, "прошлой неделе": 170,
    "за неделю": 170, "неделю": 170, "недели": 170,
    "за две недели": 340, "за месяц": 730, "месяц": 730,
    "час назад": 2, "часа назад": 4, "часов назад": 8,
}

# «за последний час» цифры не содержит, но период назван вполне однозначно.
# Раньше такие фразы проваливались в дефолт 24 ч.
WORD_PERIODS = {
    "последние полчаса": 0.5, "полчаса": 0.5, "последних полчаса": 0.5,
    "последний час": 1.5, "последнего часа": 1.5, "последнюю часу": 1.5,
    "за час": 1.5, "последний часа": 1.5,
    "пару часов": 2.5, "пары часов": 2.5, "несколько часов": 4,
    "последние два часа": 2.5, "последние три часа": 3.5,
    "последние сутки": 26, "последних суток": 26,
    "последнюю неделю": 170, "последней недели": 170,
    "последний месяц": 730, "последнего месяца": 730,
}

DEFAULT_HISTORY_HOURS = 24.0

# Явная просьба показать графики. Без неё графики не строятся: десять картинок
# под каждым ответом про метрики — это шум, а не польза.
CHART_KEYWORDS = (
    "график", "графики", "графиком", "графиках", "диаграмм", "чарт",
    "нарисуй", "визуал", "покажи картин", "в картинках",
)

# Просьба выгрузить отчёт
EXPORT_KEYWORDS = (
    "pdf", "пдф", "выгруз", "экспорт", "отчёт", "отчет", "распечат", "печат",
)

BREAKDOWN_KEYWORDS = (
    "разбивк", "детальн", "подробн", "по интервал", "по шагам", "поминутно",
    "по минутам", "по часам", "почасов", "по секундам", "таблиц",
    "по точкам", "сырые данные", "raw", "каждые",
    # Просьба «дай статистику» тоже означает подробные данные, а не агрегаты:
    # min/avg/max отвечают на вопрос «сколько», но не «когда и с чем совпало».
    "статистик", "метрик", "показател", "ресурс",
)

DIAG_KEYWORDS = (
    "диагностик", "продиагностируй", "разбер", "почему медленн", "тормоз",
    "что не так", "найди проблем", "узкое место", "боттлнек", "bottleneck",
    "оптимизир", "почему тормозит", "проверь бд", "проверь базу",
)


def detect_alert_intent(text: str) -> bool:
    t = text.lower()
    return any(kw in t for kw in ALERT_KEYWORDS)


def detect_history_intent(text: str) -> bool:
    t = text.lower()
    return any(kw in t for kw in HISTORY_KEYWORDS)


def detect_time_hours(text: str) -> float:
    """Окно в часах из фразы. 0 — период не назван."""
    t = text.lower()

    # словесные периоды проверяем ПЕРВЫМИ: они длиннее и однозначнее
    for kw, hours in sorted(WORD_PERIODS.items(), key=lambda kv: -len(kv[0])):
        if kw in t:
            return float(hours)

    # минуты — для коротких окон вида «за последние 30 минут»
    m = re.search(r'за\s+(?:послед[а-яё]+\s+)?(\d+)\s+минут', t)
    if m:
        return max(float(m.group(1)) / 60 + 0.25, 0.5)

    m = re.search(r'за\s+(?:послед[а-яё]+\s+)?(\d+)\s+час', t)
    if m:
        return float(m.group(1)) + 0.5
    m = re.search(r'(\d+)\s+час[а-яё]*\s+назад', t)
    if m:
        return float(m.group(1)) + 1

    # дни и недели: «за 3 дня», «за последние 2 недели», «5 дней назад»
    m = re.search(r'за\s+(?:послед[а-яё]+\s+)?(\d+)\s+(?:дн|сут)', t)
    if m:
        return float(m.group(1)) * 24 + 2
    m = re.search(r'(\d+)\s+(?:дн|сут)[а-яё]*\s+назад', t)
    if m:
        return float(m.group(1)) * 24 + 12
    m = re.search(r'за\s+(?:послед[а-яё]+\s+)?(\d+)\s+недел', t)
    if m:
        return float(m.group(1)) * 168 + 2
    m = re.search(r'за\s+(?:послед[а-яё]+\s+)?(\d+)\s+месяц', t)
    if m:
        return float(m.group(1)) * 730

    for kw, hours in TIME_KEYWORDS.items():
        if kw in t:
            return float(hours)

    # Период не назван, но спрашивают про историю или детализацию —
    # берём окно по умолчанию. Без этого «детально по Владивостоку» давало
    # окно 0, и таблица не строилась вовсе.
    if detect_history_intent(t) or detect_breakdown_intent(t):
        return DEFAULT_HISTORY_HOURS
    return 0.0


def parse_step_seconds(text: str) -> Optional[int]:
    """Шаг разбивки из фразы: «по 5 минут», «поминутно», «по часам»."""
    t = text.lower()
    m = re.search(r'(?:по|шаг[ом]*|интервал[ом]*|разбивк\w*\s+по)\s+(\d+)\s*'
                  r'(секунд|сек|минут|мин|час)', t)
    if m:
        n, unit = int(m.group(1)), m.group(2)
        if unit.startswith(("секунд", "сек")):
            return max(n, 15)
        if unit.startswith(("минут", "мин")):
            return n * 60
        return n * 3600
    if "поминутно" in t or "по минутам" in t:
        return 60
    if "по часам" in t or "почасов" in t:
        return 3600
    if "по секундам" in t:
        return 15
    return None


def detect_chart_intent(text: str) -> bool:
    t = text.lower()
    return any(kw in t for kw in CHART_KEYWORDS)


def detect_export_intent(text: str) -> bool:
    t = text.lower()
    return any(kw in t for kw in EXPORT_KEYWORDS)


def extract_sql(text: str) -> Optional[str]:
    """Вытащить запрос из сообщения, если пользователь его написал."""
    m = SQL_IN_TEXT.search(text)
    if not m:
        return None
    sql = (m.group(1) or m.group(2) or "").strip()
    # Отсекаем случайные совпадения вида «покажи show slave status» без смысла
    return sql if len(sql) > 10 else None


def detect_breakdown_intent(text: str) -> bool:
    t = text.lower()
    return any(kw in t for kw in BREAKDOWN_KEYWORDS) or parse_step_seconds(t) is not None


def detect_diagnose_intent(text: str) -> bool:
    t = text.lower()
    return any(kw in t for kw in DIAG_KEYWORDS)
