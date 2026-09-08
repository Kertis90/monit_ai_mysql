"""
Помощник для журнала действий.

Сама запись идёт через репозиторий в ТОЙ ЖЕ транзакции, что и действие.
Отдельная транзакция здесь недопустима: SQLite допускает одного писателя, и
вторая запись, начатая пока не закрыта первая, упирается в «database is
locked» — журнал молча терялся бы именно на тех действиях, которые важнее
всего записать.

Общая транзакция заодно даёт правильную семантику: если действие откатилось,
запись о нём не остаётся.
"""
from __future__ import annotations

from typing import Optional

from starlette.requests import Request


def client_ip(request: Optional[Request]) -> str:
    """Адрес обратившегося.

    За nginx настоящий адрес приходит заголовком; доверяем ему только потому,
    что агент не выставлен наружу напрямую.
    """
    if request is None:
        return ""
    forwarded = (request.headers.get("X-Forwarded-For") or "").split(",")[0].strip()
    return forwarded or (request.client.host if request.client else "")
