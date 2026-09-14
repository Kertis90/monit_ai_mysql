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

То же и с типами самой MySQL — DECIMAL, DATE, bytes: их стандартный
кодировщик не знает. Приведение живёт в agent.core.jsonsafe, потому что
нужно не только здесь: снимок схемы хранится строкой JSON в базе агента и
падал на том же самом.
"""
from __future__ import annotations

import json
from typing import Any

from fastapi.responses import JSONResponse

from agent.core.jsonsafe import name_of, sanitize

__all__ = ["SafeJSONResponse", "sanitize"]


class SafeJSONResponse(JSONResponse):
    """Ответ, который не разваливается из-за одного плохого значения."""

    def render(self, content: Any) -> bytes:
        return json.dumps(
            sanitize(content), ensure_ascii=False, allow_nan=False,
            separators=(",", ":"),
            # Подстраховка на случай типа, о котором мы не подумали
            default=name_of,
        ).encode("utf-8")
