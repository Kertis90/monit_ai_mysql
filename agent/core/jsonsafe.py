"""
Приведение значений к тому, что переживёт JSON.

Живёт отдельно от слоя API, потому что нужно в двух местах сразу: и при
отдаче ответа наружу, и при сохранении снимка схемы в собственную базу
агента. Служба не должна тянуть за собой веб-слой ради одной функции.

Что именно приходится приводить — это типы самой MySQL. DECIMAL возвращает
всякий SUM, ROUND и AVG; DATE и DATETIME — столбцы дат; bytes — двоичные
столбцы. Стандартный кодировщик их не знает и отвечает «Object of type
Decimal is not JSON serializable», то есть теряет ответ целиком из-за
одного поля, которого никто не просил.
"""
from __future__ import annotations

import datetime
import decimal
import math
from typing import Any


def sanitize(value: Any) -> Any:
    """Заменить всё, что не переживёт JSON, на безопасные значения."""
    if isinstance(value, bool):
        return value                      # bool раньше int: он и так пройдёт
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    if isinstance(value, decimal.Decimal):
        # Целое отдаём целым: «строк 4200000» читается лучше, чем 4200000.0
        if value == value.to_integral_value():
            try:
                return int(value)
            except (ValueError, OverflowError, decimal.InvalidOperation):
                return str(value)
        try:
            number = float(value)
        except (ValueError, OverflowError, decimal.InvalidOperation):
            return str(value)
        return number if math.isfinite(number) else None
    if isinstance(value, (datetime.datetime, datetime.date, datetime.time)):
        return value.isoformat()
    if isinstance(value, datetime.timedelta):
        return value.total_seconds()
    if isinstance(value, (bytes, bytearray, memoryview)):
        # Двоичный столбец в отчёте всё равно не прочитать; показываем то,
        # что читается, а остальное честно называем
        raw = bytes(value)
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError:
            return "<двоичные данные, %d байт>" % len(raw)
    if isinstance(value, str):
        # Суррогаты появляются при декодировании битых байтов с errors=replace
        # только в одну сторону; обратно в UTF-8 они не кодируются
        return value.encode("utf-8", "replace").decode("utf-8", "replace")
    if isinstance(value, dict):
        return {sanitize(k) if not isinstance(k, str) else k: sanitize(v)
                for k, v in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [sanitize(v) for v in value]
    return value


def name_of(item: Any) -> str:
    """Подстраховка для json.dumps: тип, о котором мы не подумали.

    Лучше строка с его видом, чем потерянный ответ целиком.
    """
    return "<%s>" % type(item).__name__
