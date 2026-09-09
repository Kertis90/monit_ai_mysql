"""
JSON, который всегда получается.

Стандартный ответ FastAPI сериализует значения с `allow_nan=False`: одно
NaN или Infinity в любом углу структуры — и весь запрос падает пятисоткой,
а в интерфейсе появляется невнятная ошибка разбора JSON. Значения такие
берутся не из воздуха: деление на ноль в расчёте доли, `AVG()` по пустой
выборке, метрика Prometheus без точек за период.

Терять весь ответ из-за одного поля неправильно, поэтому нечисловые
значения превращаются в null: в интерфейсе это «—», а остальные данные
доходят целыми.

Заодно чинятся одиночные суррогаты: они приезжают из логов и вывода MySQL
с битой кодировкой и роняют кодировщик уже на уровне UTF-8.
"""
from __future__ import annotations

import json
import math
from typing import Any

from fastapi.responses import JSONResponse


def sanitize(value: Any) -> Any:
    """Заменить всё, что не переживёт JSON, на безопасные значения."""
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    if isinstance(value, str):
        # Суррогаты появляются при декодировании битых байтов с errors=replace
        # только в одну сторону; обратно в UTF-8 они не кодируются
        return value.encode("utf-8", "replace").decode("utf-8", "replace")
    if isinstance(value, dict):
        return {k: sanitize(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [sanitize(v) for v in value]
    return value


class SafeJSONResponse(JSONResponse):
    """Ответ, который не разваливается из-за одного плохого числа."""

    def render(self, content: Any) -> bytes:
        return json.dumps(
            sanitize(content), ensure_ascii=False, allow_nan=False,
            separators=(",", ":"),
        ).encode("utf-8")
